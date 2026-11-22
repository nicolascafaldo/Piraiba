package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.capture.CaptureRepository
import com.example.capture.DnsResolutionCache
import com.example.capture.RootPromiscuousSniffer
import com.example.dissector.PacketDissector
import com.example.model.PacketDirection
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

/**
 * Local VpnService-based real-time packet sniffer and user-space TCP/UDP NAT forwarder.
 * Captures all device IPv4 packets through a local TUN interface without root, dissects
 * them via CaptureRepository, and forwards protected TCP/UDP flows so connectivity stays intact.
 */
class PacketCaptureVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.example.vpn.ACTION_START"
        const val ACTION_STOP = "com.example.vpn.ACTION_STOP"
        private const val NOTIFICATION_CHANNEL_ID = "wiretrace_capture_channel"
        private const val NOTIFICATION_ID = 1001
        private const val LOCAL_TUN_IP = "10.1.10.1"
        private const val MTU_SIZE = 1500
        private const val TCP_MSS = 1380
    }

    private val running = AtomicBoolean(false)
    private var tunInterface: ParcelFileDescriptor? = null
    private var tunOutputStream: FileOutputStream? = null
    private val tunWriteLock = Any()

    private var selector: Selector? = null
    private val selectorTasks = ConcurrentLinkedQueue<() -> Unit>()

    private val udpSessions = ConcurrentHashMap<FlowKey, UdpSession>()
    private val tcpSessions = ConcurrentHashMap<FlowKey, TcpSession>()
    private val ipIdGenerator = AtomicInteger(1)

    private var tunReaderThread: Thread? = null
    private var selectorThread: Thread? = null

    private data class FlowKey(
        val srcPort: Int,
        val dstAddress: InetAddress,
        val dstPort: Int
    )

    private class UdpSession(
        val key: FlowKey,
        val srcIpBytes: ByteArray,
        val dstIpBytes: ByteArray,
        val channel: DatagramChannel,
        @Volatile var lastActiveMs: Long = System.currentTimeMillis()
    )

    private enum class TcpState { CONNECTING, ESTABLISHED, FIN_SENT, CLOSED }

    private class TcpSession(
        val key: FlowKey,
        val srcIpBytes: ByteArray,
        val dstIpBytes: ByteArray,
        val channel: SocketChannel,
        @Volatile var state: TcpState,
        @Volatile var clientSeq: Long,
        @Volatile var serverSeq: Long,
        @Volatile var lastActiveMs: Long = System.currentTimeMillis(),
        // Server's initial sequence number (the SYN-ACK seq). Retained separately from
        // serverSeq because the latter advances with every data byte sent; SYN-ACK
        // retransmissions must always use the ISN.
        val serverIsn: Long
    ) {
        val pendingWrites = ArrayDeque<ByteBuffer>()
        var selectionKey: SelectionKey? = null
        // Selector-thread confined: set when a client half-close arrives with writes still
        // queued; cleared once they drain and shutdownOutput() is performed.
        var shutdownOutputWhenDrained = false
        // True once FIN has been sent to the client (set on the selector thread).
        @Volatile
        var finSentToClient = false
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopCapture("Capture stopped")
            return START_NOT_STICKY
        }

        startForegroundNotification()
        if (running.compareAndSet(false, true)) {
            startTunnelAndLoops()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stopCapture("VPN permission revoked by system")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopCapture(null)
        super.onDestroy()
    }

    private fun startForegroundNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                getString(R.string.vpn_notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.vpn_notification_channel_desc)
            }
            manager.createNotificationChannel(channel)
        }

        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, PacketCaptureVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification: Notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .setContentIntent(openAppIntent)
            .addAction(0, getString(R.string.action_stop_capture), stopIntent)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startTunnelAndLoops() {
        try {
            val configureIntent = PendingIntent.getActivity(
                this,
                2,
                Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                },
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val pfd = Builder()
                .setSession("Piraíba Capture")
                .setConfigureIntent(configureIntent)
                .setMtu(MTU_SIZE)
                .addAddress(LOCAL_TUN_IP, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .establish()

            if (pfd == null) {
                running.set(false)
                CaptureRepository.onCaptureStopped(
                    reason = "Android could not create the local VPN interface. Another VPN or Always-on VPN may currently be active in device settings.",
                    isError = true
                )
                stopSelf()
                return
            }

            tunInterface = pfd
            tunOutputStream = FileOutputStream(pfd.fileDescriptor)
            selector = Selector.open()
            DnsResolutionCache.setSocketProtector { socket -> protect(socket) }
            CaptureRepository.setVpnSocketProtector(this) { socket -> protect(socket) }
            CaptureRepository.onCaptureStarted()

            selectorThread = Thread(::runSelectorLoop, "WireTrace-Selector").apply { start() }
            tunReaderThread = Thread(::runTunReaderLoop, "WireTrace-TunReader").apply { start() }
        } catch (e: Exception) {
            running.set(false)
            CaptureRepository.onCaptureStopped(
                reason = "Capture start failed: ${e.message ?: "unexpected error"}",
                isError = true
            )
            stopSelf()
        }
    }

    private fun stopCapture(reason: String?) {
        // Master stop: the root tcpdump sniffer and LAN multicast listener are separate
        // capture backends that outlive this service. The notification's "Stop capture"
        // action (and revoke/destroy) must silence them too — otherwise packets keep
        // being captured with no foreground notification after capture "stopped".
        runCatching { RootPromiscuousSniffer.stopCapture() }
        if (CaptureRepository.lanMulticastEnabled.value) {
            runCatching {
                CaptureRepository.setLanMulticastEnabled(applicationContext, false)
            }
        }

        running.set(false)
        selectorTasks.clear()
        runCatching { selector?.wakeup() }
        runCatching { tunInterface?.close() }
        tunInterface = null
        tunOutputStream = null

        udpSessions.values.forEach { runCatching { it.channel.close() } }
        udpSessions.clear()
        tcpSessions.values.forEach { runCatching { it.channel.close() } }
        tcpSessions.clear()
        runCatching { selector?.close() }
        selector = null

        tunReaderThread?.interrupt()
        selectorThread?.interrupt()
        tunReaderThread = null
        selectorThread = null

        DnsResolutionCache.setSocketProtector(null)
        CaptureRepository.setVpnSocketProtector(this, null)
        CaptureRepository.onCaptureStopped(reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun runTunReaderLoop() {
        val pfd = tunInterface ?: return
        val input = FileInputStream(pfd.fileDescriptor)
        val packetBuf = ByteArray(MTU_SIZE + 64)

        while (running.get()) {
            try {
                val len = input.read(packetBuf)
                if (len <= 0) {
                    if (len < 0) break
                    continue
                }
                val rawPacket = packetBuf.copyOf(len)
                CaptureRepository.recordRawPacket(rawPacket, PacketDirection.OUTBOUND)
                dispatchOutboundPacket(rawPacket)
            } catch (_: InterruptedException) {
                break
            } catch (_: Exception) {
                if (!running.get()) break
            }
        }
    }

    private fun dispatchOutboundPacket(raw: ByteArray) {
        if (raw.size < 20) return
        val version = (raw[0].toInt() ushr 4) and 0x0F
        if (version != 4) return // IPv4 TUN forwarding

        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > raw.size) return
        // Fragmented datagrams cannot be forwarded safely: non-first fragments carry no
        // transport header (ports would be read out of payload bytes, corrupting sessions)
        // and this forwarder does no reassembly. Drop fragments — the packet is still
        // recorded for display by the caller before dispatch.
        val flagsAndFrag = ((raw[6].toInt() and 0xFF) shl 8) or (raw[7].toInt() and 0xFF)
        if ((flagsAndFrag and 0x1FFF) != 0 || (flagsAndFrag and 0x2000) != 0) return
        val totalLen = (((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)).coerceAtMost(raw.size)
        val proto = raw[9].toInt() and 0xFF
        val srcIpBytes = raw.copyOfRange(12, 16)
        val dstIpBytes = raw.copyOfRange(16, 20)
        val dstAddr = InetAddress.getByAddress(dstIpBytes)

        when (proto) {
            17 -> handleOutboundUdp(raw, ihl, totalLen, srcIpBytes, dstIpBytes, dstAddr)
            6 -> handleOutboundTcp(raw, ihl, totalLen, srcIpBytes, dstIpBytes, dstAddr)
        }
    }

    private fun handleOutboundUdp(
        raw: ByteArray,
        ihl: Int,
        totalLen: Int,
        srcIpBytes: ByteArray,
        dstIpBytes: ByteArray,
        dstAddr: InetAddress
    ) {
        if (ihl + 8 > totalLen) return
        val srcPort = ((raw[ihl].toInt() and 0xFF) shl 8) or (raw[ihl + 1].toInt() and 0xFF)
        val dstPort = ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
        val payloadOffset = ihl + 8
        if (payloadOffset > totalLen) return
        val payload = raw.copyOfRange(payloadOffset, totalLen)

        val key = FlowKey(srcPort, dstAddr, dstPort)
        val existing = udpSessions[key]
        if (existing != null && existing.channel.isOpen) {
            existing.lastActiveMs = System.currentTimeMillis()
            enqueueSelectorTask {
                runCatching {
                    existing.channel.write(ByteBuffer.wrap(payload))
                }
            }
            return
        }

        runCatching {
            val channel = DatagramChannel.open()
            channel.configureBlocking(false)
            if (!protect(channel.socket())) {
                channel.close()
                return
            }
            channel.connect(InetSocketAddress(dstAddr, dstPort))
            val session = UdpSession(key, srcIpBytes, dstIpBytes, channel)
            udpSessions[key] = session
            enqueueSelectorTask {
                val sel = selector ?: return@enqueueSelectorTask
                if (channel.isOpen) {
                    runCatching {
                        channel.register(sel, SelectionKey.OP_READ, session)
                        channel.write(ByteBuffer.wrap(payload))
                    }.onFailure {
                        udpSessions.remove(key)
                        runCatching { channel.close() }
                    }
                }
            }
        }
    }

    private fun handleOutboundTcp(
        raw: ByteArray,
        ihl: Int,
        totalLen: Int,
        srcIpBytes: ByteArray,
        dstIpBytes: ByteArray,
        dstAddr: InetAddress
    ) {
        if (ihl + 20 > totalLen) return
        val srcPort = ((raw[ihl].toInt() and 0xFF) shl 8) or (raw[ihl + 1].toInt() and 0xFF)
        val dstPort = ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
        val seq = ((raw[ihl + 4].toLong() and 0xFF) shl 24) or
            ((raw[ihl + 5].toLong() and 0xFF) shl 16) or
            ((raw[ihl + 6].toLong() and 0xFF) shl 8) or
            (raw[ihl + 7].toLong() and 0xFF)
        val dataOffset = (((raw[ihl + 12].toInt() and 0xF0) ushr 4) * 4).coerceAtLeast(20)
        val flags = raw[ihl + 13].toInt() and 0xFF
        val payloadOffset = (ihl + dataOffset).coerceAtMost(totalLen)
        val payloadLen = (totalLen - payloadOffset).coerceAtLeast(0)
        val payload = if (payloadLen > 0) raw.copyOfRange(payloadOffset, totalLen) else ByteArray(0)

        val key = FlowKey(srcPort, dstAddr, dstPort)
        val isSyn = (flags and PacketDissector.TCP_FLAG_SYN) != 0
        val isAck = (flags and PacketDissector.TCP_FLAG_ACK) != 0
        val isFin = (flags and PacketDissector.TCP_FLAG_FIN) != 0
        val isRst = (flags and PacketDissector.TCP_FLAG_RST) != 0

        if (isRst) {
            tcpSessions.remove(key)?.let { s ->
                s.state = TcpState.CLOSED
                enqueueSelectorTask { runCatching { s.channel.close() } }
            }
            return
        }

        if (isSyn && !isAck) {
            val existing = tcpSessions[key]
            if (existing != null) {
                when (existing.state) {
                    // Handshake still in flight: this is a SYN retransmit (common on lossy
                    // mobile networks). Keep the current attempt instead of killing the
                    // channel mid-connect and redialing.
                    TcpState.CONNECTING -> return
                    // Our SYN-ACK was likely lost — resend it (original ISN = serverSeq - 1)
                    // rather than tearing down an established session and churning the server.
                    TcpState.ESTABLISHED -> {
                        sendTcpControlPacket(
                            session = existing,
                            flags = PacketDissector.TCP_FLAG_SYN or PacketDissector.TCP_FLAG_ACK,
                            seq = existing.serverIsn,
                            ack = (seq + 1L) and 0xFFFFFFFFL
                        )
                        return
                    }
                    else -> { /* stale session (FIN_SENT/CLOSED): replace it below */ }
                }
            }
            tcpSessions.remove(key)?.let { old ->
                old.state = TcpState.CLOSED
                enqueueSelectorTask { runCatching { old.channel.close() } }
            }
            runCatching {
                val channel = SocketChannel.open()
                channel.configureBlocking(false)
                if (!protect(channel.socket())) {
                    channel.close()
                    return
                }
                val initialServerSeq = (Random.nextInt() and 0x7FFFFFFF).toLong()
                val session = TcpSession(
                    key = key,
                    srcIpBytes = srcIpBytes,
                    dstIpBytes = dstIpBytes,
                    channel = channel,
                    state = TcpState.CONNECTING,
                    clientSeq = (seq + 1L) and 0xFFFFFFFFL,
                    serverSeq = initialServerSeq,
                    serverIsn = initialServerSeq
                )
                tcpSessions[key] = session
                val connectedImmediately = channel.connect(InetSocketAddress(dstAddr, dstPort))
                enqueueSelectorTask {
                    val sel = selector ?: return@enqueueSelectorTask
                    if (!channel.isOpen) return@enqueueSelectorTask
                    runCatching {
                        if (connectedImmediately) {
                            if (session.state == TcpState.CONNECTING) {
                                // Don't clobber FIN_SENT (client may have half-closed while
                                // this task waited in the queue).
                                session.state = TcpState.ESTABLISHED
                            }
                            sendTcpControlPacket(
                                session = session,
                                flags = PacketDissector.TCP_FLAG_SYN or PacketDissector.TCP_FLAG_ACK
                            )
                            session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
                            if (session.shutdownOutputWhenDrained && session.pendingWrites.isEmpty()) {
                                session.shutdownOutputWhenDrained = false
                                runCatching { session.channel.shutdownOutput() }
                            }
                            session.selectionKey = channel.register(sel, SelectionKey.OP_READ, session)
                        } else {
                            session.selectionKey = channel.register(sel, SelectionKey.OP_CONNECT, session)
                        }
                    }.onFailure {
                        closeTcpWithReset(session)
                    }
                }
            }
            return
        }

        val session = tcpSessions[key] ?: return
        session.lastActiveMs = System.currentTimeMillis()

        if (payload.isNotEmpty() && session.state == TcpState.ESTABLISHED) {
            if (seq == session.clientSeq) {
                session.clientSeq = (session.clientSeq + payload.size.toLong()) and 0xFFFFFFFFL
                enqueueSelectorTask {
                    if (!session.channel.isOpen) return@enqueueSelectorTask
                    session.pendingWrites.addLast(ByteBuffer.wrap(payload))
                    val sk = session.selectionKey
                    if (sk != null && sk.isValid) {
                        sk.interestOps(sk.interestOps() or SelectionKey.OP_WRITE)
                    }
                }
            }
            // Send ACK immediately for window progression
            sendTcpControlPacket(session, PacketDissector.TCP_FLAG_ACK)
        }

        if (isFin) {
            session.clientSeq = (session.clientSeq + 1L) and 0xFFFFFFFFL
            if (session.state == TcpState.ESTABLISHED || session.state == TcpState.CONNECTING) {
                session.state = TcpState.FIN_SENT
                // ACK the client's FIN immediately, but KEEP the upstream connection open:
                // forward the half-close (after draining queued writes) so the server can
                // still deliver its remaining data. The old code removed the session and
                // closed the channel right here, discarding every in-flight response.
                sendTcpControlPacket(session, PacketDissector.TCP_FLAG_ACK)
                enqueueSelectorTask {
                    // Selector-thread confined; serialized with finishConnect()/isWritable
                    // on the same thread, so isConnected is stable here.
                    if (session.pendingWrites.isEmpty()) {
                        if (session.channel.isConnected) {
                            runCatching { session.channel.shutdownOutput() }
                        } else {
                            // Handshake still in flight: shutdownOutput() would throw
                            // NotYetConnectedException here. finishConnect() performs it.
                            session.shutdownOutputWhenDrained = true
                        }
                    } else {
                        // Drain remaining writes first; shutdownOutput runs from the
                        // selector's isWritable handler once pendingWrites is empty.
                        session.shutdownOutputWhenDrained = true
                        val sk = session.selectionKey
                        if (sk != null && sk.isValid) {
                            sk.interestOps(sk.interestOps() or SelectionKey.OP_WRITE)
                        }
                    }
                }
            } else {
                // Retransmitted FIN (or session already closing): re-ACK only.
                sendTcpControlPacket(session, PacketDissector.TCP_FLAG_ACK)
            }
        }
    }

    private fun enqueueSelectorTask(task: () -> Unit) {
        selectorTasks.add(task)
        selector?.wakeup()
    }

    private fun runSelectorLoop() {
        val sel = selector ?: return
        val readBuffer = ByteBuffer.allocate(TCP_MSS)
        val udpReadBuffer = ByteBuffer.allocate(4096)
        var lastCleanupMs = System.currentTimeMillis()

        while (running.get() && sel.isOpen) {
            try {
                while (true) {
                    val task = selectorTasks.poll() ?: break
                    runCatching { task() }
                }

                sel.select(250L)

                val keys = sel.selectedKeys().iterator()
                while (keys.hasNext()) {
                    val key = keys.next()
                    keys.remove()
                    if (!key.isValid) continue

                    when (val att = key.attachment()) {
                        is UdpSession -> handleUdpSelection(key, att, udpReadBuffer)
                        is TcpSession -> handleTcpSelection(key, att, readBuffer)
                    }
                }

                val now = System.currentTimeMillis()
                if (now - lastCleanupMs > 5000L) {
                    lastCleanupMs = now
                    cleanupIdleSessions(now)
                }
            } catch (_: InterruptedException) {
                break
            } catch (_: Exception) {
                if (!running.get()) break
            }
        }
    }

    private fun handleUdpSelection(key: SelectionKey, session: UdpSession, buf: ByteBuffer) {
        if (!key.isReadable) return
        buf.clear()
        val read = runCatching { session.channel.read(buf) }.getOrElse { -1 }
        if (read > 0) {
            session.lastActiveMs = System.currentTimeMillis()
            val payload = ByteArray(read)
            buf.flip()
            buf.get(payload)
            val ipPacket = buildIpv4UdpPacket(
                srcIp = session.dstIpBytes,
                dstIp = session.srcIpBytes,
                srcPort = session.key.dstPort,
                dstPort = session.key.srcPort,
                payload = payload
            )
            emitInboundToTun(ipPacket)
        } else if (read < 0) {
            udpSessions.remove(session.key)
            runCatching { session.channel.close() }
        }
    }

    private fun handleTcpSelection(key: SelectionKey, session: TcpSession, buf: ByteBuffer) {
        if (key.isConnectable) {
            val finished = runCatching { session.channel.finishConnect() }.getOrElse { false }
            if (finished) {
                if (session.state == TcpState.CONNECTING) {
                    // Don't clobber FIN_SENT: the client may have half-closed while the
                    // handshake was in flight (the flag check below then performs it).
                    session.state = TcpState.ESTABLISHED
                }
                session.lastActiveMs = System.currentTimeMillis()
                sendTcpControlPacket(
                    session = session,
                    flags = PacketDissector.TCP_FLAG_SYN or PacketDissector.TCP_FLAG_ACK
                )
                session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
                if (session.shutdownOutputWhenDrained && session.pendingWrites.isEmpty()) {
                    // Client FINed while the handshake was still in flight; the earlier
                    // shutdownOutput() attempt failed on the unconnected socket. Do it now.
                    session.shutdownOutputWhenDrained = false
                    runCatching { session.channel.shutdownOutput() }
                }
                val ops = SelectionKey.OP_READ or
                    if (session.pendingWrites.isNotEmpty()) SelectionKey.OP_WRITE else 0
                key.interestOps(ops)
            } else {
                closeTcpWithReset(session)
            }
            return
        }

        if (key.isValid && key.isWritable) {
            while (session.pendingWrites.isNotEmpty()) {
                val front = session.pendingWrites.first()
                val written = runCatching { session.channel.write(front) }.getOrElse { -1 }
                if (written < 0) {
                    closeTcpWithReset(session)
                    return
                }
                if (front.hasRemaining()) break
                session.pendingWrites.removeFirst()
            }
            if (session.pendingWrites.isEmpty() && key.isValid) {
                key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
                if (session.shutdownOutputWhenDrained) {
                    // Client half-closed while writes were still queued; now that everything
                    // is forwarded, propagate the FIN upstream.
                    session.shutdownOutputWhenDrained = false
                    runCatching { session.channel.shutdownOutput() }
                }
            }
        }

        if (key.isValid && key.isReadable) {
            buf.clear()
            val read = runCatching { session.channel.read(buf) }.getOrElse { -1 }
            if (read > 0) {
                session.lastActiveMs = System.currentTimeMillis()
                val payload = ByteArray(read)
                buf.flip()
                buf.get(payload)
                val ipPacket = buildIpv4TcpPacket(
                    srcIp = session.dstIpBytes,
                    dstIp = session.srcIpBytes,
                    srcPort = session.key.dstPort,
                    dstPort = session.key.srcPort,
                    seq = session.serverSeq,
                    ack = session.clientSeq,
                    flags = PacketDissector.TCP_FLAG_PSH or PacketDissector.TCP_FLAG_ACK,
                    payload = payload
                )
                session.serverSeq = (session.serverSeq + read.toLong()) and 0xFFFFFFFFL
                emitInboundToTun(ipPacket)
            } else if (read < 0) {
                // Server side finished. Notify the client with FIN unless we already did —
                // including the half-closed case (client sent FIN first), which the old
                // `state == ESTABLISHED` check silently skipped, leaving the client hanging.
                if (!session.finSentToClient &&
                    (session.state == TcpState.ESTABLISHED || session.state == TcpState.FIN_SENT)
                ) {
                    session.finSentToClient = true
                    session.state = TcpState.FIN_SENT
                    sendTcpControlPacket(
                        session = session,
                        flags = PacketDissector.TCP_FLAG_FIN or PacketDissector.TCP_FLAG_ACK
                    )
                    session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
                }
                tcpSessions.remove(session.key)
                session.state = TcpState.CLOSED
                runCatching { session.channel.close() }
            }
        }
    }

    private fun closeTcpWithReset(session: TcpSession) {
        if (session.state != TcpState.CLOSED) {
            sendTcpControlPacket(session, PacketDissector.TCP_FLAG_RST or PacketDissector.TCP_FLAG_ACK)
        }
        tcpSessions.remove(session.key)
        session.state = TcpState.CLOSED
        runCatching { session.channel.close() }
    }

    private fun cleanupIdleSessions(nowMs: Long) {
        val udpIter = udpSessions.entries.iterator()
        while (udpIter.hasNext()) {
            val entry = udpIter.next()
            if (nowMs - entry.value.lastActiveMs > 30_000L) {
                runCatching { entry.value.channel.close() }
                udpIter.remove()
            }
        }
        val tcpIter = tcpSessions.entries.iterator()
        while (tcpIter.hasNext()) {
            val entry = tcpIter.next()
            if (nowMs - entry.value.lastActiveMs > 90_000L) {
                runCatching { entry.value.channel.close() }
                tcpIter.remove()
            }
        }
    }

    private fun sendTcpControlPacket(
        session: TcpSession,
        flags: Int,
        seq: Long = session.serverSeq,
        ack: Long = session.clientSeq
    ) {
        val pkt = buildIpv4TcpPacket(
            srcIp = session.dstIpBytes,
            dstIp = session.srcIpBytes,
            srcPort = session.key.dstPort,
            dstPort = session.key.srcPort,
            seq = seq,
            ack = ack,
            flags = flags,
            payload = ByteArray(0)
        )
        emitInboundToTun(pkt)
    }

    private fun emitInboundToTun(ipPacket: ByteArray) {
        CaptureRepository.recordRawPacket(ipPacket, PacketDirection.INBOUND)
        val out = tunOutputStream ?: return
        synchronized(tunWriteLock) {
            runCatching {
                out.write(ipPacket)
            }
        }
    }

    private fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        writeIpv4Header(pkt, totalLen, protocol = 17, srcIp = srcIp, dstIp = dstIp)

        // UDP header at offset 20
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(payload, 0, pkt, 28, payload.size)

        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 17, udpLen)
        return pkt
    }

    private fun buildIpv4TcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray
    ): ByteArray {
        val isSyn = (flags and PacketDissector.TCP_FLAG_SYN) != 0
        val tcpHeaderLen = if (isSyn) 24 else 20
        val tcpLen = tcpHeaderLen + payload.size
        val totalLen = 20 + tcpLen
        val pkt = ByteArray(totalLen)

        writeIpv4Header(pkt, totalLen, protocol = 6, srcIp = srcIp, dstIp = dstIp)

        // TCP header at offset 20
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()

        pkt[24] = ((seq ushr 24) and 0xFF).toByte()
        pkt[25] = ((seq ushr 16) and 0xFF).toByte()
        pkt[26] = ((seq ushr 8) and 0xFF).toByte()
        pkt[27] = (seq and 0xFF).toByte()

        pkt[28] = ((ack ushr 24) and 0xFF).toByte()
        pkt[29] = ((ack ushr 16) and 0xFF).toByte()
        pkt[30] = ((ack ushr 8) and 0xFF).toByte()
        pkt[31] = (ack and 0xFF).toByte()

        pkt[32] = (((tcpHeaderLen / 4) shl 4) and 0xF0).toByte()
        pkt[33] = (flags and 0xFF).toByte()
        // Window = 65535
        pkt[34] = 0xFF.toByte()
        pkt[35] = 0xFF.toByte()

        if (isSyn) {
            // MSS option = 1380
            pkt[40] = 2
            pkt[41] = 4
            pkt[42] = ((TCP_MSS ushr 8) and 0xFF).toByte()
            pkt[43] = (TCP_MSS and 0xFF).toByte()
        }

        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, 20 + tcpHeaderLen, payload.size)
        }

        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 6, tcpLen)
        return pkt
    }

    private fun writeIpv4Header(
        pkt: ByteArray,
        totalLen: Int,
        protocol: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        val id = ipIdGenerator.getAndIncrement() and 0xFFFF
        pkt[0] = 0x45.toByte()
        pkt[1] = 0x00
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[4] = ((id ushr 8) and 0xFF).toByte()
        pkt[5] = (id and 0xFF).toByte()
        pkt[6] = 0x40.toByte() // DF
        pkt[7] = 0x00
        pkt[8] = 64.toByte() // TTL
        pkt[9] = protocol.toByte()
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
    }
}
