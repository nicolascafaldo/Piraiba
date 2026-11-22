package com.example.capture

import android.os.Build
import com.example.dissector.PcapCodec
import com.example.model.CaptureSource
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import com.example.model.RootSandboxState
import com.example.model.RootSandboxStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.EOFException
import java.io.InputStream
import java.io.InputStreamReader
import java.net.Inet4Address
import java.net.NetworkInterface
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Genuine Root Promiscuous Sandbox using system `su` + existing `tcpdump` binaries when
 * running on a rooted Android device (Magisk / KernelSU / SuperSU / userdebug).
 *
 * On stock unrooted Android devices, an unprivileged app sandbox cannot elevate itself to UID 0
 * or open AF_PACKET / CAP_NET_RAW sockets; this manager probes cleanly, reports exact kernel
 * sandbox constraints, and never fabricates root access or fake LAN traffic.
 */
object RootPromiscuousSniffer {

    private const val MAX_LOG_LINES = 80
    private const val FRAME_PUBLISH_INTERVAL_MS = 500L
    private val ifaceRegex = Regex("^[a-zA-Z0-9._:-]{1,32}$")
    private val bpfSafeRegex = Regex("^[a-zA-Z0-9 .:_/()=!<>&|-]{0,160}$")

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val capturing = AtomicBoolean(false)

    // Frame counter lives here (not in the StateFlow): publishing _state per captured frame
    // recomposed the whole top-level UI at packet rate under a busy root capture.
    private val frameCount = java.util.concurrent.atomic.AtomicLong(0L)
    private val lastFramePublishMs = java.util.concurrent.atomic.AtomicLong(0L)

    private val _state = MutableStateFlow(RootSandboxState())
    val state: StateFlow<RootSandboxState> = _state.asStateFlow()

    @Volatile
    private var activeProcess: Process? = null
    private var captureJob: Job? = null
    private var stderrJob: Job? = null

    fun setSelectedInterface(iface: String) {
        val clean = iface.trim()
        if (ifaceRegex.matches(clean)) {
            _state.update { it.copy(selectedInterface = clean) }
        }
    }

    fun setBpfFilter(filter: String) {
        _state.update { it.copy(bpfFilter = filter) }
    }

    fun setPromiscuousMode(enabled: Boolean) {
        _state.update { it.copy(promiscuousMode = enabled) }
    }

    fun probeSandbox() {
        if (capturing.get()) {
            appendLog("Root capture is already active on ${_state.value.selectedInterface}.")
            return
        }
        scope.launch {
            _state.update {
                it.copy(
                    status = RootSandboxStatus.CHECKING,
                    statusDetail = "Checking local environment for su root elevation and tcpdump..."
                )
            }
            appendLog("Checking su & system tcpdump...")

            val probeCmd = listOf(
                "su", "-c",
                "id; echo '---TCPDUMP---'; which tcpdump 2>/dev/null || ls /system/bin/tcpdump /system/xbin/tcpdump /vendor/bin/tcpdump /data/adb/modules/*/system/bin/tcpdump 2>/dev/null | head -n 1; echo '---IFACES---'; ip -o link show 2>/dev/null | cut -d: -f2 | tr -d ' '"
            )

            val probeResult = runCatching {
                val proc = ProcessBuilder(probeCmd).redirectErrorStream(true).start()
                val finished = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    proc.waitFor(4, TimeUnit.SECONDS)
                } else {
                    waitForLegacyProcess(proc, 4_000L)
                }
                if (!finished) {
                    forceDestroy(proc)
                    error("su check timed out waiting for root prompt")
                }
                val output = BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }
                proc.exitValue() to output
            }

            if (probeResult.isFailure) {
                val msg = probeResult.exceptionOrNull()?.message ?: "su binary unavailable"
                val localIfaces = discoverNonRootInterfaces()
                appendLog("su unavailable: $msg")
                appendLog("Non-root fallback: WifiManager.MulticastLock (mDNS/SSDP/LLMNR) & tun0 VPN.")
                _state.update {
                    it.copy(
                        status = RootSandboxStatus.NO_ROOT_OR_DENIED,
                        suAvailable = false,
                        tcpdumpPath = null,
                        availableInterfaces = localIfaces,
                        selectedInterface = localIfaces.firstOrNull() ?: "wlan0",
                        statusDetail = "Device is not rooted or su was denied ($msg). Android's kernel blocks UID/CAP_NET_RAW elevation from an unprivileged app sandbox."
                    )
                }
                return@launch
            }

            val (exitCode, rawOut) = probeResult.getOrThrow()
            val uidRoot = rawOut.contains("uid=0")
            if (!uidRoot) {
                val localIfaces = discoverNonRootInterfaces()
                appendLog("su returned exit=$exitCode without uid=0 root shell.")
                _state.update {
                    it.copy(
                        status = RootSandboxStatus.NO_ROOT_OR_DENIED,
                        suAvailable = false,
                        tcpdumpPath = null,
                        availableInterfaces = localIfaces,
                        selectedInterface = localIfaces.firstOrNull() ?: "wlan0",
                        statusDetail = "Root elevation denied (su exited $exitCode without uid=0). Grant superuser permission in Magisk/KernelSU or use LAN Multicast Listen."
                    )
                }
                return@launch
            }

            val tcpdumpPath = parseSection(rawOut, "---TCPDUMP---", "---IFACES---")
                .lineSequence()
                .map { it.trim() }
                .firstOrNull { it.startsWith("/") }

            val detectedIfaces = parseSection(rawOut, "---IFACES---", null)
                .lineSequence()
                .map { it.substringBefore('@').trim() }
                .filter { it.isNotBlank() && it != "lo" && !it.startsWith("dummy") && ifaceRegex.matches(it) }
                .distinct()
                .sortedByDescending { it.startsWith("wlan") || it.startsWith("eth") }
                .toMutableList()
            if (!detectedIfaces.contains("any")) {
                detectedIfaces.add("any")
            }

            appendLog("Root shell verified (uid=0).")
            if (tcpdumpPath != null) {
                appendLog("Found tcpdump at $tcpdumpPath")
                appendLog("Interfaces: ${detectedIfaces.joinToString(", ")}")
                val preferredIface = detectedIfaces.firstOrNull { it == _state.value.selectedInterface }
                    ?: detectedIfaces.firstOrNull()
                    ?: "wlan0"
                _state.update {
                    it.copy(
                        status = RootSandboxStatus.ROOT_READY,
                        suAvailable = true,
                        tcpdumpPath = tcpdumpPath,
                        availableInterfaces = detectedIfaces,
                        selectedInterface = preferredIface,
                        statusDetail = "Root sandbox ready ($tcpdumpPath). Start capture to stream raw 802.3/wlan0 frames."
                    )
                }
            } else {
                appendLog("tcpdump binary not found on system/vendor/Magisk paths.")
                _state.update {
                    it.copy(
                        status = RootSandboxStatus.NO_TCPDUMP,
                        suAvailable = true,
                        tcpdumpPath = null,
                        availableInterfaces = detectedIfaces,
                        selectedInterface = detectedIfaces.firstOrNull() ?: "wlan0",
                        statusDetail = "Root access confirmed (uid=0), but no system tcpdump binary was found in /system/bin, /system/xbin, or /vendor/bin."
                    )
                }
            }
        }
    }

    fun startCapture() {
        val snapshot = _state.value
        val tcpdump = snapshot.tcpdumpPath
        if (!snapshot.suAvailable || tcpdump == null) {
            appendLog("Cannot start root capture: root su + tcpdump must be ready first.")
            probeSandbox()
            return
        }
        val iface = snapshot.selectedInterface.trim()
        if (!ifaceRegex.matches(iface)) {
            appendLog("Rejected invalid interface name: $iface")
            return
        }
        val bpf = snapshot.bpfFilter.trim()
        if (!bpfSafeRegex.matches(bpf) || bpf.contains('\'')) {
            appendLog("Invalid characters in BPF filter. Allowed: letters, digits, spaces, .:_/()=!<>&|-")
            _state.update { it.copy(status = RootSandboxStatus.ERROR, statusDetail = "Unsafe characters in BPF filter expression.") }
            return
        }

        if (!capturing.compareAndSet(false, true)) {
            return
        }

        val promiscFlag = if (snapshot.promiscuousMode) "" else " -p"
        val bpfArg = if (bpf.isNotEmpty()) " '$bpf'" else ""
        val shellCmd = "exec '$tcpdump' -i '$iface'$promiscFlag -U -s 0 -w -$bpfArg"

        _state.update {
            it.copy(
                status = RootSandboxStatus.ROOT_RUNNING,
                capturedFrames = 0L,
                statusDetail = "Streaming raw libpcap frames on $iface (${if (snapshot.promiscuousMode) "IFF_PROMISC" else "non-promiscuous"})..."
            )
        }
        frameCount.set(0L)
        lastFramePublishMs.set(0L)
        appendLog("Starting: su -c \"$shellCmd\"")

        captureJob = scope.launch {
            val localIps = collectLocalIpv4Strings()
            var proc: Process? = null
            try {
                proc = ProcessBuilder("su", "-c", shellCmd).start()
                activeProcess = proc

                stderrJob = launch {
                    runCatching {
                        BufferedReader(InputStreamReader(proc.errorStream)).use { err ->
                            var line: String? = null
                            while (capturing.get() && err.readLine().also { line = it } != null) {
                                line?.takeIf { it.isNotBlank() }?.let { appendLog("tcpdump: $it") }
                            }
                        }
                    }
                }

                parseLibpcapStream(proc.inputStream) { frameBytes, linkLayerType ->
                    val dir = inferDirectionFromFrame(frameBytes, linkLayerType, localIps)
                    val count = frameCount.incrementAndGet()
                    maybePublishFrameCount(count)
                    CaptureRepository.recordRawPacket(
                        rawBytes = frameBytes,
                        direction = dir,
                        captureSource = CaptureSource.LAN_PROMISCUOUS,
                        linkLayerType = linkLayerType
                    )
                }

                val code = runCatching { proc.waitFor() }.getOrDefault(-1)
                if (capturing.getAndSet(false)) {
                    appendLog("tcpdump exited cleanly (code=$code)")
                    _state.update {
                        it.copy(
                            status = RootSandboxStatus.ROOT_READY,
                            capturedFrames = frameCount.get(),
                            statusDetail = "Root capture stopped (exit=$code, ${frameCount.get()} frames captured)."
                        )
                    }
                }
            } catch (e: Exception) {
                val wasRunning = capturing.getAndSet(false)
                if (wasRunning) {
                    appendLog("Root capture error: ${e.message}")
                    _state.update {
                        it.copy(
                            status = RootSandboxStatus.ERROR,
                            capturedFrames = frameCount.get(),
                            statusDetail = "Root stream ended: ${e.message ?: "stream error"}"
                        )
                    }
                }
            } finally {
                runCatching { stderrJob?.cancel() }
                stderrJob = null
                runCatching { proc?.destroy() }
                if (activeProcess === proc) {
                    activeProcess = null
                }
            }
        }
    }

    fun stopCapture() {
        val wasRunning = capturing.getAndSet(false)
        runCatching { activeProcess?.destroy() }
        runCatching { activeProcess?.let(::forceDestroy) }
        activeProcess = null
        runCatching { captureJob?.cancel() }
        captureJob = null
        runCatching { stderrJob?.cancel() }
        stderrJob = null
        if (wasRunning) {
            appendLog("Root promiscuous capture stopped by user (${_state.value.capturedFrames} frames).")
            val readyStatus = if (_state.value.suAvailable && _state.value.tcpdumpPath != null) {
                RootSandboxStatus.ROOT_READY
            } else {
                RootSandboxStatus.NO_ROOT_OR_DENIED
            }
            _state.update {
                it.copy(
                    status = readyStatus,
                    capturedFrames = frameCount.get(),
                    statusDetail = "Stopped (${frameCount.get()} root frames captured)."
                )
            }
        }
    }

    /**
     * Publishes the frame counter to the UI state at most every
     * [FRAME_PUBLISH_INTERVAL_MS] so a busy capture cannot recompose the top-level UI
     * once per frame; exit paths publish the exact final count.
     */
    private fun maybePublishFrameCount(count: Long) {
        val nowMs = System.currentTimeMillis()
        val last = lastFramePublishMs.get()
        if (nowMs - last >= FRAME_PUBLISH_INTERVAL_MS && lastFramePublishMs.compareAndSet(last, nowMs)) {
            _state.update { it.copy(capturedFrames = count) }
        }
    }

    /**
     * Streams binary libpcap packets from a live `tcpdump -U -w -` stdout pipe without waiting
     * for EOF. Exposed as `internal` for deterministic JVM unit testing.
     */
    internal fun parseLibpcapStream(
        input: InputStream,
        onFrame: (ByteArray, LinkLayerType) -> Unit
    ) {
        val buffered = BufferedInputStream(input, 16 * 1024)
        val gh = ByteArray(24)
        if (!readFullyOrFalse(buffered, gh)) {
            error("No pcap global header received from tcpdump")
        }

        val magic = ((gh[0].toInt() and 0xFF) shl 24) or
            ((gh[1].toInt() and 0xFF) shl 16) or
            ((gh[2].toInt() and 0xFF) shl 8) or
            (gh[3].toInt() and 0xFF)

        val littleEndian = when (magic) {
            0xD4C3B2A1.toInt(), 0x4D3CB2A1 -> true
            0xA1B2C3D4.toInt(), 0xA1B23C4D.toInt() -> false
            else -> error("Unrecognized pcap stream magic: 0x${magic.toUInt().toString(16)}")
        }

        val linkType = readInt(gh, 20, littleEndian)
        val linkLayer = PcapCodec.linkLayerForPcapType(linkType)

        val rh = ByteArray(16)
        while (readFullyOrFalse(buffered, rh)) {
            val inclLen = readInt(rh, 8, littleEndian)
            if (inclLen < 0 || inclLen > 1024 * 1024) {
                break
            }
            if (inclLen == 0) {
                continue
            }
            val frame = ByteArray(inclLen)
            if (!readFullyOrFalse(buffered, frame)) {
                break
            }
            onFrame(frame, linkLayer)
        }
    }

    private fun inferDirectionFromFrame(
        frameBytes: ByteArray,
        linkLayerType: LinkLayerType,
        localIps: Set<String>
    ): PacketDirection {
        val l3Offset = PcapCodec.ipHeaderOffset(linkLayerType)
        if (frameBytes.size >= l3Offset + 20) {
            val version = (frameBytes[l3Offset].toInt() ushr 4) and 0x0F
            if (version == 4) {
                val srcIp = "${frameBytes[l3Offset + 12].toInt() and 0xFF}." +
                    "${frameBytes[l3Offset + 13].toInt() and 0xFF}." +
                    "${frameBytes[l3Offset + 14].toInt() and 0xFF}." +
                    "${frameBytes[l3Offset + 15].toInt() and 0xFF}"
                if (srcIp in localIps) return PacketDirection.OUTBOUND
            }
        }
        return PacketDirection.INBOUND
    }

    private fun collectLocalIpv4Strings(): Set<String> {
        val ips = mutableSetOf<String>()
        val ifaces = runCatching { NetworkInterface.getNetworkInterfaces() }.getOrNull() ?: return ips
        while (ifaces.hasMoreElements()) {
            val ni = ifaces.nextElement()
            if (ni.isLoopback || ni.name.startsWith("tun")) continue
            val addrs = ni.inetAddresses
            while (addrs.hasMoreElements()) {
                val addr = addrs.nextElement()
                if (addr is Inet4Address) {
                    addr.hostAddress?.let { ips.add(it) }
                }
            }
        }
        return ips
    }

    private fun discoverNonRootInterfaces(): List<String> {
        val list = mutableListOf<String>()
        val ifaces = runCatching { NetworkInterface.getNetworkInterfaces() }.getOrNull()
        if (ifaces != null) {
            while (ifaces.hasMoreElements()) {
                val ni = ifaces.nextElement()
                val name = ni.name
                if (!ni.isLoopback && !name.startsWith("tun") && !name.startsWith("dummy")) {
                    list.add(name)
                }
            }
        }
        val sorted = list.distinct()
            .sortedByDescending { it.startsWith("wlan") || it.startsWith("eth") }
            .toMutableList()
        if (!sorted.contains("wlan0")) sorted.add(0, "wlan0")
        if (!sorted.contains("any")) sorted.add("any")
        return sorted
    }

    private fun parseSection(text: String, startMarker: String, endMarker: String?): String {
        val startIdx = text.indexOf(startMarker)
        if (startIdx < 0) return ""
        val afterStart = text.substring(startIdx + startMarker.length)
        return if (endMarker != null) {
            val endIdx = afterStart.indexOf(endMarker)
            if (endIdx >= 0) afterStart.substring(0, endIdx) else afterStart
        } else {
            afterStart
        }
    }

    private fun appendLog(line: String) {
        val ts = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val entry = "[$ts] $line"
        _state.update { prev ->
            prev.copy(consoleLogs = (prev.consoleLogs + entry).takeLast(MAX_LOG_LINES))
        }
    }

    private fun readFullyOrFalse(input: InputStream, dest: ByteArray): Boolean {
        var offset = 0
        while (offset < dest.size) {
            val read = input.read(dest, offset, dest.size - offset)
            if (read < 0) {
                return if (offset == 0) false else throw EOFException("Truncated pcap stream")
            }
            offset += read
        }
        return true
    }

    private fun readInt(buf: ByteArray, offset: Int, littleEndian: Boolean): Int {
        val b0 = buf[offset].toInt() and 0xFF
        val b1 = buf[offset + 1].toInt() and 0xFF
        val b2 = buf[offset + 2].toInt() and 0xFF
        val b3 = buf[offset + 3].toInt() and 0xFF
        return if (littleEndian) {
            b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
        } else {
            (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
        }
    }

    private fun forceDestroy(proc: Process) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            proc.destroyForcibly()
        } else {
            proc.destroy()
        }
    }

    private fun waitForLegacyProcess(proc: Process, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (runCatching { proc.exitValue() }.isSuccess) {
                return true
            }
            try {
                Thread.sleep(50L)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
        return runCatching { proc.exitValue() }.isSuccess
    }
}
