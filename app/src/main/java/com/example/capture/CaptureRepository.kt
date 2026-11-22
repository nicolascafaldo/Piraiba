package com.example.capture

import android.content.Context
import com.example.dissector.PacketDissector
import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import com.example.model.ThroughputPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.DatagramSocket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class CaptureStatusEvent(
    val id: Long,
    val message: String,
    val isError: Boolean = false
)

/**
 * Thread-safe singleton repository holding live captured packets, throughput telemetry,
 * and VPN capture state shared between PacketCaptureVpnService and the Compose UI.
 */
object CaptureRepository {

    private const val MAX_BUFFERED_PACKETS = 4000
    private const val THROUGHPUT_WINDOW_SEC = 60

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val bufferLock = Any()
    private val packetBuffer = ArrayDeque<CapturedPacket>(MAX_BUFFERED_PACKETS)
    // Identity counter: strictly monotonic, NEVER reset — ids are allocated from it by every
    // capture backend and by pcap import (remapped), so buffer keys can never collide even if
    // a packet is in flight across a clear/import.
    private val nextPacketId = AtomicLong(0L)
    // Session-scoped display counters (reset by clearCapture / import); kept separate from
    // nextPacketId so clearing does not break packet identity.
    private val sessionPacketCount = AtomicLong(0L)
    private val sessionByteCount = AtomicLong(0L)
    private val dirty = AtomicBoolean(false)

    private val throughputLock = Any()
    private val secondBuckets = LinkedHashMap<Long, MutableThroughputBucket>()

    private data class MutableThroughputBucket(
        var packets: Int = 0,
        var bytesOut: Long = 0L,
        var bytesIn: Long = 0L
    )

    private val _isCapturing = MutableStateFlow(false)
    val isCapturing: StateFlow<Boolean> = _isCapturing.asStateFlow()

    private val _captureStartTimeMs = MutableStateFlow<Long?>(null)
    val captureStartTimeMs: StateFlow<Long?> = _captureStartTimeMs.asStateFlow()

    private val _packets = MutableStateFlow<List<CapturedPacket>>(emptyList())
    val packets: StateFlow<List<CapturedPacket>> = _packets.asStateFlow()

    private val _totalPacketCount = MutableStateFlow(0L)
    val totalPacketCount: StateFlow<Long> = _totalPacketCount.asStateFlow()

    private val _totalBytes = MutableStateFlow(0L)
    val totalBytes: StateFlow<Long> = _totalBytes.asStateFlow()

    private val _throughputHistory = MutableStateFlow<List<ThroughputPoint>>(emptyList())
    val throughputHistory: StateFlow<List<ThroughputPoint>> = _throughputHistory.asStateFlow()

    private val statusSeq = AtomicLong(0L)
    private val _statusMessage = MutableStateFlow<CaptureStatusEvent?>(null)
    val statusMessage: StateFlow<CaptureStatusEvent?> = _statusMessage.asStateFlow()

    private val _lanMulticastEnabled = MutableStateFlow(false)
    val lanMulticastEnabled: StateFlow<Boolean> = _lanMulticastEnabled.asStateFlow()

    @Volatile
    private var vpnSocketProtector: ((DatagramSocket) -> Boolean)? = null

    init {
        scope.launch {
            while (isActive) {
                if (dirty.compareAndSet(true, false)) {
                    flushToStateFlows()
                } else if (_isCapturing.value) {
                    updateThroughputOnly()
                }
                delay(120L)
            }
        }
    }

    fun setVpnSocketProtector(context: Context, protector: ((DatagramSocket) -> Boolean)?) {
        vpnSocketProtector = protector
        if (_lanMulticastEnabled.value) {
            LanMulticastSniffer.restartIfRunning(context, protector)
            if (protector != null && !LanMulticastSniffer.isListening.value) {
                LanMulticastSniffer.start(context, protector)
            }
        }
    }

    fun setLanMulticastEnabled(context: Context, enabled: Boolean) {
        _lanMulticastEnabled.value = enabled
        if (enabled) {
            LanMulticastSniffer.start(context, vpnSocketProtector)
        } else {
            LanMulticastSniffer.stop(resetCount = false)
        }
    }

    fun onCaptureStarted() {
        val now = System.currentTimeMillis()
        if (_captureStartTimeMs.value == null) {
            _captureStartTimeMs.value = now
        }
        _isCapturing.value = true
        _statusMessage.value = CaptureStatusEvent(
            id = statusSeq.incrementAndGet(),
            message = "Local VPN tunnel active on tun0 (10.1.10.1)",
            isError = false
        )
    }

    fun onCaptureStopped(reason: String? = null, isError: Boolean = false) {
        _isCapturing.value = false
        if (dirty.compareAndSet(true, false)) {
            flushToStateFlows()
        }
        if (reason != null) {
            _statusMessage.value = CaptureStatusEvent(
                id = statusSeq.incrementAndGet(),
                message = reason,
                isError = isError
            )
        }
    }

    /**
     * Posts a status event WITHOUT touching the capturing flag — used when a stop *request* itself failed and the real capture state is unknown. Claiming
     * "stopped" there would hide a still-running capture.
     */
    fun postStatus(message: String, isError: Boolean = false) {
        _statusMessage.value = CaptureStatusEvent(
            id = statusSeq.incrementAndGet(),
            message = message,
            isError = isError
        )
    }

    fun clearStatusMessage() {
        _statusMessage.value = null
    }

    fun recordRawPacket(
        rawBytes: ByteArray,
        direction: PacketDirection,
        captureSource: CaptureSource = CaptureSource.DEVICE_VPN,
        linkLayerType: LinkLayerType = LinkLayerType.RAW_TUN
    ) {
        if (rawBytes.isEmpty()) return
        val now = System.currentTimeMillis()
        val start = _captureStartTimeMs.value ?: now.also { _captureStartTimeMs.value = it }
        val relMs = (now - start).coerceAtLeast(0L)
        val id = nextPacketId.incrementAndGet()

        val dissected = PacketDissector.dissect(
            id = id,
            rawBytes = rawBytes,
            timestampMs = now,
            relativeTimeMs = relMs,
            direction = direction,
            linkLayerType = linkLayerType,
            captureSource = captureSource
        )

        synchronized(bufferLock) {
            if (packetBuffer.size >= MAX_BUFFERED_PACKETS) {
                packetBuffer.removeFirst()
            }
            packetBuffer.addLast(dissected)
        }
        DnsResolutionCache.ingestPacket(dissected)
        AlertMonitor.evaluatePacket(dissected)

        sessionPacketCount.incrementAndGet()
        sessionByteCount.addAndGet(rawBytes.size.toLong())
        // NOTE: _totalPacketCount/_totalBytes are NOT set here. Per-packet StateFlow writes
        // made the 15-flow uiState combine re-emit (and recompose the top-level UI) for
        // EVERY packet at line rate; they are published by the 120 ms flush loop instead.

        val sec = now / 1000L
        synchronized(throughputLock) {
            val bucket = secondBuckets.getOrPut(sec) { MutableThroughputBucket() }
            bucket.packets += 1
            if (direction == PacketDirection.OUTBOUND) {
                bucket.bytesOut += rawBytes.size.toLong()
            } else {
                bucket.bytesIn += rawBytes.size.toLong()
            }
            val cutoff = sec - THROUGHPUT_WINDOW_SEC - 5
            val iter = secondBuckets.keys.iterator()
            while (iter.hasNext()) {
                if (iter.next() < cutoff) iter.remove()
            }
        }

        dirty.set(true)
    }

    /**
     * Replaces the buffer with an imported capture. Imported packets are REMAPPED to fresh ids
     * from [nextPacketId] while holding [bufferLock], so they can never collide with a live
     * packet that was allocated an id before this call and inserts itself afterwards.
     * Returns the packets actually retained (at most [MAX_BUFFERED_PACKETS]).
     */
    fun replaceWithImportedPackets(imported: List<CapturedPacket>): List<CapturedPacket> {
        val retained = synchronized(bufferLock) {
            packetBuffer.clear()
            val remapped = imported.takeLast(MAX_BUFFERED_PACKETS).map { pkt ->
                pkt.copy(id = nextPacketId.incrementAndGet())
            }
            remapped.forEach { packetBuffer.addLast(it) }
            // The header stats ("All captured packets (N pkts • B)", "• N total") must
            // describe what is actually held: after an import the buffer contains ONLY the
            // imported packets (cap-truncated), and the byte counter previously summed the
            // full `imported` list — overstating bytes whenever the cap evicted packets.
            // Import redefines the capture set, exactly like clearCapture does.
            val bytes = remapped.sumOf { it.rawBytes.size.toLong() }
            sessionPacketCount.set(remapped.size.toLong())
            _totalPacketCount.value = remapped.size.toLong()
            sessionByteCount.set(bytes)
            _totalBytes.value = bytes
            remapped
        }
        _captureStartTimeMs.value = imported.firstOrNull()?.timestampMs
        synchronized(throughputLock) {
            secondBuckets.clear()
        }
        _packets.value = retained
        _throughputHistory.value = emptyList()
        DnsResolutionCache.clear()
        DnsResolutionCache.ingestPackets(retained)
        AlertMonitor.resetTrackingState()
        retained.forEach { AlertMonitor.evaluatePacket(it) }
        return retained
    }

    fun clearCapture() {
        synchronized(bufferLock) {
            packetBuffer.clear()
            // NOTE: nextPacketId is deliberately NOT reset — see field comment. Resetting it is what
            // previously allowed duplicate packet ids (and a LazyColumn key crash) when a writer
            // was in flight across a clear.
            // Counter resets live inside the same lock as flushToStateFlows' publication so a
            // concurrent flush can't resurrect pre-clear totals after this returns.
            sessionPacketCount.set(0L)
            _totalPacketCount.value = 0L
            sessionByteCount.set(0L)
            _totalBytes.value = 0L
        }
        synchronized(throughputLock) {
            secondBuckets.clear()
        }
        _captureStartTimeMs.value = if (_isCapturing.value) System.currentTimeMillis() else null
        _packets.value = emptyList()
        _throughputHistory.value = emptyList()
        dirty.set(false)
        DnsResolutionCache.clear()
        AlertMonitor.clearAlerts()
        LanMulticastSniffer.resetCounter()
    }

    fun snapshotAllPackets(): List<CapturedPacket> = synchronized(bufferLock) {
        packetBuffer.toList()
    }

    private fun flushToStateFlows() {
        // Snapshot AND counter publication happen inside bufferLock so clearCapture/
        // replaceWithImportedPackets (which reset counters under the same lock) can never
        // interleave with a preempted flush that would re-publish stale pre-clear totals.
        synchronized(bufferLock) {
            _packets.value = packetBuffer.toList()
            _totalPacketCount.value = sessionPacketCount.get()
            _totalBytes.value = sessionByteCount.get()
        }
        updateThroughputOnly()
    }

    private fun updateThroughputOnly() {
        val nowSec = System.currentTimeMillis() / 1000L
        val points = synchronized(throughputLock) {
            ((nowSec - 29)..nowSec).map { sec ->
                val b = secondBuckets[sec]
                ThroughputPoint(
                    bucketSecond = sec,
                    packetsPerSec = b?.packets ?: 0,
                    bytesOut = b?.bytesOut ?: 0L,
                    bytesIn = b?.bytesIn ?: 0L
                )
            }
        }
        _throughputHistory.value = points
    }
}
