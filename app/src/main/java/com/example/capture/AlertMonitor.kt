package com.example.capture

import com.example.dissector.PacketDissector
import com.example.model.AlertCategory
import com.example.model.AlertSeverity
import com.example.model.AlertThresholdConfig
import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.NetworkAlertEvent
import com.example.model.PacketDirection
import com.example.model.PortMonitorMode
import com.example.model.ProtocolType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Real-time network event evaluator triggered on every captured packet and throughput tick.
 * Detects:
 *  - High latency via TCP SYN->SYN/ACK, DNS query->response, and HTTP request->response RTT
 *  - Unauthorized port activity (Blocklist / Watched ports OR Strict Allowlist mode)
 *  - Unexpected data spikes (per-second throughput KB/s or packets/sec burst)
 */
object AlertMonitor {

    private const val MAX_ALERT_HISTORY = 200
    private const val PORT_ALERT_COOLDOWN_MS = 15_000L
    private const val SPIKE_ALERT_COOLDOWN_MS = 5_000L

    private val lock = Any()
    private val nextAlertId = AtomicLong(0L)

    // Latency tracking maps (key -> outbound timestampMs)
    private val pendingTcpSyn = ConcurrentHashMap<String, Long>()
    private val pendingDnsQuery = ConcurrentHashMap<String, Long>()
    private val pendingHttpReq = ConcurrentHashMap<String, Long>()

    // Alert deduplication cooldowns
    private val portCooldownUntil = ConcurrentHashMap<String, Long>()
    private var lastSpikeAlertMs = 0L

    // Rolling 1-second throughput counters
    private var currentSecond = -1L
    private var packetsInCurrentSecond = 0
    private var bytesInCurrentSecond = 0L

    private val _config = MutableStateFlow(AlertThresholdConfig())
    val config: StateFlow<AlertThresholdConfig> = _config.asStateFlow()

    private val _alerts = MutableStateFlow<List<NetworkAlertEvent>>(emptyList())
    val alerts: StateFlow<List<NetworkAlertEvent>> = _alerts.asStateFlow()

    private val _unreadCount = MutableStateFlow(0)
    val unreadCount: StateFlow<Int> = _unreadCount.asStateFlow()

    private val _latestAlert = MutableStateFlow<NetworkAlertEvent?>(null)
    val latestAlert: StateFlow<NetworkAlertEvent?> = _latestAlert.asStateFlow()

    fun updateConfig(newConfig: AlertThresholdConfig) {
        _config.value = newConfig
    }

    fun markAllRead() {
        _unreadCount.value = 0
    }

    fun consumeLatestAlert() {
        _latestAlert.value = null
    }

    fun clearAlerts() {
        synchronized(lock) {
            _alerts.value = emptyList()
            _unreadCount.value = 0
            _latestAlert.value = null
            portCooldownUntil.clear()
            pendingTcpSyn.clear()
            pendingDnsQuery.clear()
            pendingHttpReq.clear()
            lastSpikeAlertMs = 0L
        }
    }

    fun resetTrackingState() {
        synchronized(lock) {
            pendingTcpSyn.clear()
            pendingDnsQuery.clear()
            pendingHttpReq.clear()
            portCooldownUntil.clear()
            currentSecond = -1L
            packetsInCurrentSecond = 0
            bytesInCurrentSecond = 0L
        }
    }

    fun evaluatePacket(packet: CapturedPacket) {
        val cfg = _config.value
        if (!cfg.alertsEnabled) return

        val nowMs = packet.timestampMs
        val remoteIp = if (packet.direction == PacketDirection.OUTBOUND) packet.dstIp else packet.srcIp
        val remotePort = if (packet.direction == PacketDirection.OUTBOUND) packet.dstPort else packet.srcPort

        if (cfg.highLatencyEnabled) {
            evaluateLatency(packet, cfg, remoteIp)
        }

        if (cfg.unauthorizedPortEnabled && remotePort > 0) {
            evaluatePortActivity(packet, cfg, remoteIp, remotePort, nowMs)
        }

        if (cfg.dataSpikeEnabled) {
            evaluateThroughputSpike(packet, cfg, nowMs)
        }
    }

    private fun evaluateLatency(
        packet: CapturedPacket,
        cfg: AlertThresholdConfig,
        remoteIp: String
    ) {
        // 1. TCP SYN -> SYN/ACK RTT
        if (packet.transportProtocol == "TCP") {
            val isSyn = (packet.tcpFlags and PacketDissector.TCP_FLAG_SYN) != 0
            val isAck = (packet.tcpFlags and PacketDissector.TCP_FLAG_ACK) != 0
            if (packet.direction == PacketDirection.OUTBOUND && isSyn && !isAck) {
                pendingTcpSyn[packet.streamKey] = packet.timestampMs
                trimMapIfNeeded(pendingTcpSyn)
            } else if (packet.direction == PacketDirection.INBOUND && isSyn && isAck) {
                val startMs = pendingTcpSyn.remove(packet.streamKey)
                if (startMs != null) {
                    val rttMs = (packet.timestampMs - startMs).coerceAtLeast(0L)
                    if (rttMs > cfg.maxLatencyMs) {
                        val sev = if (rttMs >= cfg.maxLatencyMs * 2L) AlertSeverity.CRITICAL else AlertSeverity.WARNING
                        emitAlert(
                            category = AlertCategory.HIGH_LATENCY,
                            severity = sev,
                            title = "High TCP Handshake Latency (${rttMs} ms)",
                            detail = "SYN→SYN/ACK RTT to $remoteIp:${packet.srcPort} exceeded ${cfg.maxLatencyMs} ms threshold",
                            packetId = packet.id,
                            filterExpr = "ip.addr == $remoteIp && tcp.port == ${packet.srcPort}",
                            timestampMs = packet.timestampMs,
                            captureSource = packet.captureSource
                        )
                    }
                }
            }
        }

        // 2. DNS Query -> Response RTT
        if (packet.protocol == ProtocolType.DNS) {
            if (packet.direction == PacketDirection.OUTBOUND) {
                pendingDnsQuery[packet.streamKey] = packet.timestampMs
                trimMapIfNeeded(pendingDnsQuery)
            } else {
                val startMs = pendingDnsQuery.remove(packet.streamKey)
                if (startMs != null) {
                    val rttMs = (packet.timestampMs - startMs).coerceAtLeast(0L)
                    if (rttMs > cfg.maxLatencyMs) {
                        val sev = if (rttMs >= cfg.maxLatencyMs * 2L) AlertSeverity.CRITICAL else AlertSeverity.WARNING
                        val targetLabel = packet.hostOrSni ?: remoteIp
                        emitAlert(
                            category = AlertCategory.HIGH_LATENCY,
                            severity = sev,
                            title = "Slow DNS Resolution (${rttMs} ms)",
                            detail = "DNS response for $targetLabel from $remoteIp exceeded ${cfg.maxLatencyMs} ms threshold",
                            packetId = packet.id,
                            filterExpr = "dns && ip.addr == $remoteIp",
                            timestampMs = packet.timestampMs,
                            captureSource = packet.captureSource
                        )
                    }
                }
            }
        }

        // 3. HTTP Request -> Response TTFB
        if (packet.protocol == ProtocolType.HTTP) {
            if (packet.direction == PacketDirection.OUTBOUND) {
                pendingHttpReq.putIfAbsent(packet.streamKey, packet.timestampMs)
                trimMapIfNeeded(pendingHttpReq)
            } else {
                val startMs = pendingHttpReq.remove(packet.streamKey)
                if (startMs != null) {
                    val rttMs = (packet.timestampMs - startMs).coerceAtLeast(0L)
                    if (rttMs > cfg.maxLatencyMs) {
                        val sev = if (rttMs >= cfg.maxLatencyMs * 2L) AlertSeverity.CRITICAL else AlertSeverity.WARNING
                        val hostText = packet.hostOrSni ?: remoteIp
                        emitAlert(
                            category = AlertCategory.HIGH_LATENCY,
                            severity = sev,
                            title = "High HTTP Response Latency (${rttMs} ms)",
                            detail = "HTTP TTFB from $hostText exceeded ${cfg.maxLatencyMs} ms threshold",
                            packetId = packet.id,
                            filterExpr = "http && ip.addr == $remoteIp",
                            timestampMs = packet.timestampMs,
                            captureSource = packet.captureSource
                        )
                    }
                }
            }
        }
    }

    private fun evaluatePortActivity(
        packet: CapturedPacket,
        cfg: AlertThresholdConfig,
        remoteIp: String,
        remotePort: Int,
        nowMs: Long
    ) {
        val violation = when (cfg.portMonitorMode) {
            PortMonitorMode.WATCHED_PORTS -> remotePort in cfg.flaggedPorts
            PortMonitorMode.ALLOWLIST_ONLY -> remotePort !in cfg.allowedPorts
        }
        if (!violation) return

        val cooldownKey = "${cfg.portMonitorMode.name}|$remoteIp|$remotePort"
        val cooldownUntil = portCooldownUntil[cooldownKey]
        if (cooldownUntil != null && nowMs < cooldownUntil) return
        portCooldownUntil[cooldownKey] = nowMs + PORT_ALERT_COOLDOWN_MS

        val modeDesc = if (cfg.portMonitorMode == PortMonitorMode.WATCHED_PORTS) {
            "matched watched port $remotePort"
        } else {
            "port $remotePort is not in allowlist"
        }

        emitAlert(
            category = AlertCategory.UNAUTHORIZED_PORT,
            severity = AlertSeverity.CRITICAL,
            title = "Unauthorized Port Activity (:$remotePort)",
            detail = "${packet.transportProtocol} ${packet.direction.shortLabel} with $remoteIp:$remotePort — $modeDesc",
            packetId = packet.id,
            filterExpr = "ip.addr == $remoteIp && port == $remotePort",
            timestampMs = nowMs,
            captureSource = packet.captureSource
        )
    }

    private fun evaluateThroughputSpike(
        packet: CapturedPacket,
        cfg: AlertThresholdConfig,
        nowMs: Long
    ) {
        val sec = nowMs / 1000L
        val byteLimit = cfg.maxBytesPerSecKB * 1024L
        var shouldFireBandwidth = false
        var shouldFirePps = false
        var snapshotBytes = 0L
        var snapshotPackets = 0

        synchronized(lock) {
            if (sec != currentSecond) {
                currentSecond = sec
                packetsInCurrentSecond = 0
                bytesInCurrentSecond = 0L
            }
            packetsInCurrentSecond += 1
            bytesInCurrentSecond += packet.length.toLong()
            snapshotBytes = bytesInCurrentSecond
            snapshotPackets = packetsInCurrentSecond

            if (nowMs - lastSpikeAlertMs >= SPIKE_ALERT_COOLDOWN_MS) {
                if (snapshotBytes > byteLimit) {
                    shouldFireBandwidth = true
                    lastSpikeAlertMs = nowMs
                } else if (snapshotPackets > cfg.maxPacketsPerSec) {
                    shouldFirePps = true
                    lastSpikeAlertMs = nowMs
                }
            }
        }

        if (shouldFireBandwidth) {
            val kbPerSec = snapshotBytes / 1024L
            emitAlert(
                category = AlertCategory.DATA_SPIKE,
                severity = if (kbPerSec >= cfg.maxBytesPerSecKB * 2L) AlertSeverity.CRITICAL else AlertSeverity.WARNING,
                title = "Data Spike Detected ($kbPerSec KB/s)",
                detail = "1s traffic rate ($kbPerSec KB/s) exceeded ${cfg.maxBytesPerSecKB} KB/s limit",
                packetId = packet.id,
                filterExpr = null,
                timestampMs = nowMs,
                captureSource = packet.captureSource
            )
        } else if (shouldFirePps) {
            emitAlert(
                category = AlertCategory.DATA_SPIKE,
                severity = AlertSeverity.WARNING,
                title = "Packet Burst Detected ($snapshotPackets pkt/s)",
                detail = "1s frame rate ($snapshotPackets pkt/s) exceeded ${cfg.maxPacketsPerSec} pkt/s limit",
                packetId = packet.id,
                filterExpr = null,
                timestampMs = nowMs,
                captureSource = packet.captureSource
            )
        }
    }

    private fun emitAlert(
        category: AlertCategory,
        severity: AlertSeverity,
        title: String,
        detail: String,
        packetId: Long?,
        filterExpr: String?,
        timestampMs: Long,
        captureSource: CaptureSource = CaptureSource.DEVICE_VPN
    ) {
        val event = NetworkAlertEvent(
            id = nextAlertId.incrementAndGet(),
            timestampMs = timestampMs,
            category = category,
            severity = severity,
            title = title,
            detail = detail,
            packetId = packetId,
            filterExpr = filterExpr,
            captureSource = captureSource
        )
        synchronized(lock) {
            val updated = listOf(event) + _alerts.value.take(MAX_ALERT_HISTORY - 1)
            _alerts.value = updated
            _unreadCount.value = (_unreadCount.value + 1).coerceAtMost(99)
            _latestAlert.value = event
        }
    }

    private fun trimMapIfNeeded(map: ConcurrentHashMap<String, Long>) {
        if (map.size > 500) {
            val cutoff = System.currentTimeMillis() - 60_000L
            val iter = map.entries.iterator()
            while (iter.hasNext()) {
                if (iter.next().value < cutoff) iter.remove()
            }
        }
    }
}
