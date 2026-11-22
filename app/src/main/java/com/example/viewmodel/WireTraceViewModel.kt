package com.example.viewmodel

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.capture.AlertConfigStore
import com.example.capture.AlertMonitor
import com.example.capture.CaptureRepository
import com.example.capture.DnsResolutionCache
import com.example.capture.LanMulticastSniffer
import com.example.capture.RootPromiscuousSniffer
import com.example.dissector.DisplayFilterParser
import com.example.dissector.ParsedDisplayFilter
import com.example.dissector.PcapCodec
import com.example.model.AlertThresholdConfig
import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.ConversationStream
import com.example.model.NetworkAlertEvent
import com.example.model.PacketDirection
import com.example.model.PortMonitorMode
import com.example.model.ProtocolStat
import com.example.model.ProtocolType
import com.example.model.QuickFilter
import com.example.model.ResolvedHost
import com.example.model.RootSandboxState
import com.example.model.ThroughputPoint
import com.example.model.TrafficScopeFilter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

data class CaptureUiState(
    val isCapturing: Boolean = false,
    val captureStartTimeMs: Long? = null,
    val totalPacketCount: Long = 0L,
    val totalBytes: Long = 0L,
    val packets: List<CapturedPacket> = emptyList(),
    val filterQuery: String = "",
    val quickFilter: QuickFilter = QuickFilter.ALL,
    val filterValidation: ParsedDisplayFilter = ParsedDisplayFilter(isValid = true) { true },
    val selectedPacketId: Long? = null,
    val autoScroll: Boolean = true,
    val throughputHistory: List<ThroughputPoint> = emptyList(),
    val darkTheme: Boolean = true,
    val resolveHostnames: Boolean = true,
    val resolvedDomains: Map<String, ResolvedHost> = emptyMap(),
    val lanMulticastEnabled: Boolean = false,
    val lanMulticastActive: Boolean = false,
    val lanPacketCount: Long = 0L,
    val trafficScopeFilter: TrafficScopeFilter = TrafficScopeFilter.ALL,
    val phonePacketCount: Int = 0,
    val lanBufferedPacketCount: Int = 0
)

data class SandboxUiState(
    val rootSandboxState: RootSandboxState = RootSandboxState(),
    val lanMulticastEnabled: Boolean = false,
    val lanMulticastActive: Boolean = false,
    val lanPacketCount: Long = 0L,
    val totalBufferedLanPackets: Int = 0,
    val packets: List<CapturedPacket> = emptyList(),
    val filterQuery: String = "",
    val quickFilter: QuickFilter = QuickFilter.ALL,
    val filterValidation: ParsedDisplayFilter = ParsedDisplayFilter(isValid = true) { true },
    val selectedPacketId: Long? = null,
    val autoScroll: Boolean = true,
    val resolveHostnames: Boolean = true,
    val resolvedDomains: Map<String, ResolvedHost> = emptyMap()
)

class WireTraceViewModel : ViewModel() {

    private val _filterQuery = MutableStateFlow("")
    private val _quickFilter = MutableStateFlow(QuickFilter.ALL)
    private val _trafficScopeFilter = MutableStateFlow(TrafficScopeFilter.PHONE_ONLY)
    private val _sandboxFilterQuery = MutableStateFlow("")
    private val _sandboxQuickFilter = MutableStateFlow(QuickFilter.ALL)
    private val _sandboxAutoScroll = MutableStateFlow(true)
    private val _selectedPacketId = MutableStateFlow<Long?>(null)
    private val _autoScroll = MutableStateFlow(true)
    private val _darkTheme = MutableStateFlow(true)
    private val _resolveHostnames = MutableStateFlow(true)
    private val _toastEvent = MutableStateFlow<String?>(null)
    private val _vpnDisclosureAccepted = MutableStateFlow(false)
    private var appContext: Context? = null
    private var alertStoreBound = false

    val toastEvent: StateFlow<String?> = _toastEvent.asStateFlow()
    val vpnDisclosureAccepted: StateFlow<Boolean> = _vpnDisclosureAccepted.asStateFlow()
    val alertConfig: StateFlow<AlertThresholdConfig> = AlertMonitor.config
    val alertEvents: StateFlow<List<NetworkAlertEvent>> = AlertMonitor.alerts
    val unreadAlertCount: StateFlow<Int> = AlertMonitor.unreadCount
    val latestAlertEvent: StateFlow<NetworkAlertEvent?> = AlertMonitor.latestAlert
    val rootSandboxState: StateFlow<RootSandboxState> = RootPromiscuousSniffer.state

    fun bindAlertStore(context: Context) {
        if (alertStoreBound) return
        alertStoreBound = true
        val appCtx = context.applicationContext
        appContext = appCtx
        viewModelScope.launch {
            AlertConfigStore.observeConfig(appCtx)
                .catch { e ->
                    // A corrupted DataStore file throws on read; without this catch the
                    // exception escapes viewModelScope and kills the process. Keep defaults.
                    _toastEvent.value =
                        "Alert settings could not be read (${e.message ?: "corrupt file"}); using defaults"
                }
                .collect { loaded ->
                    AlertMonitor.updateConfig(loaded)
                }
        }
        viewModelScope.launch {
            AlertConfigStore.observeVpnDisclosureAccepted(appCtx)
                .catch { _vpnDisclosureAccepted.value = false }
                .collect { accepted ->
                    _vpnDisclosureAccepted.value = accepted
                }
        }
    }

    fun acceptVpnDisclosure() {
        _vpnDisclosureAccepted.value = true
        val ctx = appContext ?: return
        viewModelScope.launch {
            runCatching { AlertConfigStore.setVpnDisclosureAccepted(ctx, true) }
        }
    }

    fun updateAlertConfig(newConfig: AlertThresholdConfig) {
        AlertMonitor.updateConfig(newConfig)
        val ctx = appContext ?: return
        viewModelScope.launch {
            runCatching { AlertConfigStore.saveConfig(ctx, newConfig) }
        }
    }

    fun addMonitoredPort(port: Int) {
        if (port !in 1..65535) {
            _toastEvent.value = "Port must be between 1 and 65535"
            return
        }
        val current = alertConfig.value
        val updated = if (current.portMonitorMode == PortMonitorMode.WATCHED_PORTS) {
            current.copy(flaggedPorts = current.flaggedPorts + port)
        } else {
            current.copy(allowedPorts = current.allowedPorts + port)
        }
        updateAlertConfig(updated)
    }

    fun removeMonitoredPort(port: Int) {
        val current = alertConfig.value
        val updated = if (current.portMonitorMode == PortMonitorMode.WATCHED_PORTS) {
            current.copy(flaggedPorts = current.flaggedPorts - port)
        } else {
            current.copy(allowedPorts = current.allowedPorts - port)
        }
        updateAlertConfig(updated)
    }

    fun resetAlertDefaults() {
        updateAlertConfig(AlertThresholdConfig())
        _toastEvent.value = "Alert thresholds reset to defaults"
    }

    fun clearAlerts() {
        AlertMonitor.clearAlerts()
        _toastEvent.value = "Alert log cleared"
    }

    fun markAlertsRead() {
        AlertMonitor.markAllRead()
    }

    fun consumeLatestAlert() {
        AlertMonitor.consumeLatestAlert()
    }

    private val parsedFilterFlow: StateFlow<ParsedDisplayFilter> = combine(
        _filterQuery,
        _quickFilter,
        DnsResolutionCache.resolvedHosts,
        _resolveHostnames
    ) { query, quick, resolvedMap, resolveEnabled ->
        DisplayFilterParser.parse(
            query = query,
            quickFilter = quick,
            resolvedDomains = if (resolveEnabled) resolvedMap else emptyMap()
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ParsedDisplayFilter(isValid = true) { true }
    )

    val filteredPackets: StateFlow<List<CapturedPacket>> = combine(
        CaptureRepository.packets,
        _trafficScopeFilter,
        parsedFilterFlow
    ) { packets, scopeFilter, parsed ->
        packets.filter { pkt ->
            val scopeMatch = when (scopeFilter) {
                TrafficScopeFilter.ALL -> true
                TrafficScopeFilter.PHONE_ONLY -> pkt.captureSource == CaptureSource.DEVICE_VPN
                TrafficScopeFilter.LAN_ONLY -> pkt.captureSource == CaptureSource.LAN_PROMISCUOUS
            }
            scopeMatch && parsed.matches(pkt)
        }
    }.flowOn(Dispatchers.Default)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    private data class LanSummaryState(
        val enabled: Boolean,
        val active: Boolean,
        val lanTotalCount: Long,
        val scopeFilter: TrafficScopeFilter,
        val phoneCount: Int,
        val lanBufferedCount: Int
    )

    private val lanSummaryFlow = combine(
        CaptureRepository.lanMulticastEnabled,
        LanMulticastSniffer.isListening,
        LanMulticastSniffer.lanPacketCount,
        _trafficScopeFilter,
        CaptureRepository.packets
    ) { enabled, listening, count, scopeFilter, allPackets ->
        val lanBuffered = allPackets.count { it.captureSource == CaptureSource.LAN_PROMISCUOUS }
        val phoneBuffered = allPackets.size - lanBuffered
        LanSummaryState(enabled, listening, count, scopeFilter, phoneBuffered, lanBuffered)
    }.flowOn(Dispatchers.Default) // O(n) packet classification off the main thread (runs per flush)

    val uiState: StateFlow<CaptureUiState> = combine(
        CaptureRepository.isCapturing,
        CaptureRepository.captureStartTimeMs,
        CaptureRepository.totalPacketCount,
        CaptureRepository.totalBytes,
        filteredPackets,
        _filterQuery,
        _quickFilter,
        parsedFilterFlow,
        _selectedPacketId,
        _autoScroll,
        CaptureRepository.throughputHistory,
        _darkTheme,
        _resolveHostnames,
        DnsResolutionCache.resolvedHosts,
        lanSummaryFlow
    ) { values ->
        @Suppress("UNCHECKED_CAST")
        val packets = values[4] as List<CapturedPacket>
        @Suppress("UNCHECKED_CAST")
        val throughputHistory = values[10] as List<ThroughputPoint>
        @Suppress("UNCHECKED_CAST")
        val resolvedDomains = values[13] as Map<String, ResolvedHost>
        @Suppress("UNCHECKED_CAST")
        val lanState = values[14] as LanSummaryState
        CaptureUiState(
            isCapturing = values[0] as Boolean,
            captureStartTimeMs = values[1] as Long?,
            totalPacketCount = values[2] as Long,
            totalBytes = values[3] as Long,
            packets = packets,
            filterQuery = values[5] as String,
            quickFilter = values[6] as QuickFilter,
            filterValidation = values[7] as ParsedDisplayFilter,
            selectedPacketId = values[8] as Long?,
            autoScroll = values[9] as Boolean,
            throughputHistory = throughputHistory,
            darkTheme = values[11] as Boolean,
            resolveHostnames = values[12] as Boolean,
            resolvedDomains = resolvedDomains,
            lanMulticastEnabled = lanState.enabled,
            lanMulticastActive = lanState.active,
            lanPacketCount = lanState.lanTotalCount,
            trafficScopeFilter = lanState.scopeFilter,
            phonePacketCount = lanState.phoneCount,
            lanBufferedPacketCount = lanState.lanBufferedCount
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = CaptureUiState()
    )

    private val parsedSandboxFilterFlow: StateFlow<ParsedDisplayFilter> = combine(
        _sandboxFilterQuery,
        _sandboxQuickFilter,
        DnsResolutionCache.resolvedHosts,
        _resolveHostnames
    ) { query, quick, resolvedMap, resolveEnabled ->
        DisplayFilterParser.parse(
            query = query,
            quickFilter = quick,
            resolvedDomains = if (resolveEnabled) resolvedMap else emptyMap()
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ParsedDisplayFilter(isValid = true) { true }
    )

    private val sandboxPacketsAndCount: StateFlow<Pair<List<CapturedPacket>, Int>> = combine(
        CaptureRepository.packets,
        parsedSandboxFilterFlow
    ) { allPackets, parsed ->
        val lanOnly = allPackets.filter { it.captureSource == CaptureSource.LAN_PROMISCUOUS }
        lanOnly.filter { parsed.matches(it) } to lanOnly.size
    }.flowOn(Dispatchers.Default)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList<CapturedPacket>() to 0
        )

    val sandboxUiState: StateFlow<SandboxUiState> = combine(
        rootSandboxState,
        lanSummaryFlow,
        sandboxPacketsAndCount,
        _sandboxFilterQuery,
        _sandboxQuickFilter,
        parsedSandboxFilterFlow,
        _selectedPacketId,
        _sandboxAutoScroll,
        _resolveHostnames,
        DnsResolutionCache.resolvedHosts
    ) { values ->
        @Suppress("UNCHECKED_CAST")
        val lanState = values[1] as LanSummaryState
        @Suppress("UNCHECKED_CAST")
        val packetsPair = values[2] as Pair<List<CapturedPacket>, Int>
        @Suppress("UNCHECKED_CAST")
        val resolvedDomains = values[9] as Map<String, ResolvedHost>
        SandboxUiState(
            rootSandboxState = values[0] as RootSandboxState,
            lanMulticastEnabled = lanState.enabled,
            lanMulticastActive = lanState.active,
            lanPacketCount = lanState.lanTotalCount,
            totalBufferedLanPackets = packetsPair.second,
            packets = packetsPair.first,
            filterQuery = values[3] as String,
            quickFilter = values[4] as QuickFilter,
            filterValidation = values[5] as ParsedDisplayFilter,
            selectedPacketId = values[6] as Long?,
            autoScroll = values[7] as Boolean,
            resolveHostnames = values[8] as Boolean,
            resolvedDomains = resolvedDomains
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = SandboxUiState()
    )

    val selectedPacket: StateFlow<CapturedPacket?> = combine(
        CaptureRepository.packets,
        _selectedPacketId
    ) { packets, selectedId ->
        selectedId?.let { id -> packets.find { it.id == id } }
    }.flowOn(Dispatchers.Default) // O(n) lookup must not run on the main thread at flush rate
        .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = null
    )

    val conversations: StateFlow<List<ConversationStream>> = combine(
        CaptureRepository.packets,
        DnsResolutionCache.resolvedHosts,
        _resolveHostnames
    ) { packets, resolvedMap, resolveEnabled ->
        buildConversations(packets, if (resolveEnabled) resolvedMap else emptyMap())
    }.flowOn(Dispatchers.Default)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    val protocolStats: StateFlow<List<ProtocolStat>> = CaptureRepository.packets
        .map { packets -> buildProtocolStats(packets) }
        .flowOn(Dispatchers.Default)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    val topHosts: StateFlow<List<Pair<String, Int>>> = CaptureRepository.packets
        .map { packets ->
            packets.mapNotNull { it.hostOrSni?.takeIf { h -> h.isNotBlank() } }
                .groupingBy { it }
                .eachCount()
                .entries
                .sortedByDescending { it.value }
                .take(10)
                .map { it.key to it.value }
        }.flowOn(Dispatchers.Default)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    fun setFilterQuery(query: String) {
        _filterQuery.value = query
    }

    fun setQuickFilter(filter: QuickFilter) {
        _quickFilter.value = filter
    }

    fun setTrafficScopeFilter(scopeFilter: TrafficScopeFilter) {
        _trafficScopeFilter.value = scopeFilter
    }

    fun selectPacket(packetId: Long?) {
        _selectedPacketId.value = packetId
    }

    fun toggleAutoScroll() {
        _autoScroll.value = !_autoScroll.value
    }

    fun toggleTheme() {
        _darkTheme.value = !_darkTheme.value
    }

    fun toggleResolveHostnames() {
        val next = !_resolveHostnames.value
        _resolveHostnames.value = next
        _toastEvent.value = if (next) {
            "Passive DNS/SNI hostname resolution enabled"
        } else {
            "Showing raw IP addresses"
        }
    }

    fun toggleLanMulticast(context: Context) {
        val next = !CaptureRepository.lanMulticastEnabled.value
        CaptureRepository.setLanMulticastEnabled(context.applicationContext, next)
        _toastEvent.value = if (next) {
            "LAN Multicast Listen active (mDNS, SSDP, LLMNR, WS-Discovery)"
        } else {
            "LAN Multicast Listen turned off"
        }
    }

    fun probeRootSandbox() {
        RootPromiscuousSniffer.probeSandbox()
    }

    fun setRootSandboxInterface(iface: String) {
        RootPromiscuousSniffer.setSelectedInterface(iface)
    }

    fun setRootSandboxBpfFilter(filter: String) {
        RootPromiscuousSniffer.setBpfFilter(filter)
    }

    fun setRootSandboxPromiscuous(enabled: Boolean) {
        RootPromiscuousSniffer.setPromiscuousMode(enabled)
    }

    fun setSandboxFilterQuery(query: String) {
        _sandboxFilterQuery.value = query
    }

    fun setSandboxQuickFilter(filter: QuickFilter) {
        _sandboxQuickFilter.value = filter
    }

    fun toggleSandboxAutoScroll() {
        _sandboxAutoScroll.value = !_sandboxAutoScroll.value
    }

    fun startRootSandboxCapture() {
        RootPromiscuousSniffer.startCapture()
    }

    fun stopRootSandboxCapture() {
        RootPromiscuousSniffer.stopCapture()
    }

    fun filterToStream(stream: ConversationStream) {
        val portPart = if (stream.remotePort > 0) " && port == ${stream.remotePort}" else ""
        val expr = "ip.addr == ${stream.remoteIp}$portPart"
        if (stream.captureSource == CaptureSource.LAN_PROMISCUOUS) {
            _sandboxQuickFilter.value = QuickFilter.ALL
            _sandboxFilterQuery.value = expr
        } else {
            _quickFilter.value = QuickFilter.ALL
            _trafficScopeFilter.value = TrafficScopeFilter.PHONE_ONLY
            _filterQuery.value = expr
        }
    }

    fun applyAlertInspection(event: NetworkAlertEvent): Boolean {
        val isLan = event.captureSource == CaptureSource.LAN_PROMISCUOUS ||
            (event.packetId != null && CaptureRepository.snapshotAllPackets()
                .find { it.id == event.packetId }?.captureSource == CaptureSource.LAN_PROMISCUOUS)
        if (isLan) {
            _sandboxQuickFilter.value = QuickFilter.ALL
            _sandboxFilterQuery.value = event.filterExpr.orEmpty()
        } else {
            _quickFilter.value = QuickFilter.ALL
            _trafficScopeFilter.value = TrafficScopeFilter.PHONE_ONLY
            _filterQuery.value = event.filterExpr.orEmpty()
        }
        _selectedPacketId.value = event.packetId
        return isLan
    }

    fun clearCapture() {
        _selectedPacketId.value = null
        CaptureRepository.clearCapture()
        _toastEvent.value = "Capture buffer cleared"
    }

    fun consumeToast() {
        _toastEvent.value = null
    }

    fun packetsForStream(streamKey: String): List<CapturedPacket> =
        CaptureRepository.snapshotAllPackets().filter { it.streamKey == streamKey }

    fun exportPcap(
        contentResolver: ContentResolver,
        uri: Uri,
        filteredOnly: Boolean = false,
        fromSandbox: Boolean = false
    ) {
        viewModelScope.launch {
            val packets = if (filteredOnly) {
                if (fromSandbox) sandboxUiState.value.packets else filteredPackets.value
            } else {
                CaptureRepository.snapshotAllPackets()
            }
            if (packets.isEmpty()) {
                _toastEvent.value = "No packets to export"
                return@launch
            }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    contentResolver.openOutputStream(uri)?.use { out ->
                        PcapCodec.writePcap(packets, out)
                    } ?: error("Unable to open destination file")
                }
            }
            _toastEvent.value = result.fold(
                onSuccess = { "Saved ${packets.size} packets to .pcap" },
                onFailure = { "Export failed: ${it.message}" }
            )
        }
    }

    fun exportPcapForSharing(
        context: Context,
        fileName: String,
        filteredOnly: Boolean,
        fromSandbox: Boolean = false,
        onReadyToShare: (Uri, Int) -> Unit
    ) {
        viewModelScope.launch {
            val packets = if (filteredOnly) {
                if (fromSandbox) sandboxUiState.value.packets else filteredPackets.value
            } else {
                CaptureRepository.snapshotAllPackets()
            }
            if (packets.isEmpty()) {
                _toastEvent.value = "No packets to share"
                return@launch
            }
            val safeName = fileName.trim()
                .ifEmpty { "piraiba_capture.pcap" }
                .let { if (it.endsWith(".pcap", ignoreCase = true)) it else "$it.pcap" }
                .replace(Regex("[^a-zA-Z0-9._-]"), "_")

            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val dir = File(context.cacheDir, "captures").apply { mkdirs() }
                    val file = File(dir, safeName)
                    FileOutputStream(file).use { out ->
                        PcapCodec.writePcap(packets, out)
                    }
                    FileProvider.getUriForFile(
                        context,
                        "${context.packageName}.fileprovider",
                        file
                    )
                }
            }
            result.fold(
                onSuccess = { uri -> onReadyToShare(uri, packets.size) },
                onFailure = { _toastEvent.value = "Share export failed: ${it.message}" }
            )
        }
    }

    fun importPcap(contentResolver: ContentResolver, uri: Uri) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    contentResolver.openInputStream(uri)?.use { input ->
                        PcapCodec.readPcap(input)
                    } ?: error("Unable to open .pcap file")
                }
            }
            result.fold(
                onSuccess = { imported ->
                    if (imported.isEmpty()) {
                        _toastEvent.value = "No valid IP packets found in file"
                    } else {
                        val retained = CaptureRepository.replaceWithImportedPackets(imported)
                        // Select from what was actually retained (ids are remapped, and packets
                        // beyond the 4000-packet buffer cap are evicted).
                        _selectedPacketId.value = retained.firstOrNull()?.id
                        // Report what the user can actually see: the ring buffer may have
                        // evicted older packets from a large file.
                        _toastEvent.value = if (retained.size == imported.size) {
                            "Loaded ${imported.size} packets from .pcap"
                        } else {
                            "Loaded ${imported.size} packets from .pcap — showing the newest ${retained.size} (buffer cap)"
                        }
                    }
                },
                onFailure = {
                    _toastEvent.value = "Import failed: ${it.message}"
                }
            )
        }
    }

    private fun buildConversations(
        packets: List<CapturedPacket>,
        resolvedDomains: Map<String, ResolvedHost>
    ): List<ConversationStream> {
        if (packets.isEmpty()) return emptyList()
        val grouped = LinkedHashMap<String, MutableList<CapturedPacket>>()
        for (pkt in packets) {
            grouped.getOrPut(pkt.streamKey) { mutableListOf() }.add(pkt)
        }
        return grouped.entries.map { (key, list) ->
            val first = list.first()
            val last = list.last()
            val isFirstOut = first.direction == PacketDirection.OUTBOUND
            val localEp = if (isFirstOut) "${first.srcIp}:${first.srcPort}" else "${first.dstIp}:${first.dstPort}"
            val remoteIp = if (isFirstOut) first.dstIp else first.srcIp
            val remotePort = if (isFirstOut) first.dstPort else first.srcPort
            val remoteEp = "$remoteIp:$remotePort"

            val highestProto = list.firstOrNull {
                it.protocol in setOf(ProtocolType.TLS, ProtocolType.HTTP, ProtocolType.DNS, ProtocolType.QUIC)
            }?.protocol ?: first.protocol

            val host = list.firstNotNullOfOrNull { it.hostOrSni } ?: resolvedDomains[remoteIp]?.domain
            var outBytes = 0L
            var inBytes = 0L
            for (p in list) {
                if (p.direction == PacketDirection.OUTBOUND) outBytes += p.length else inBytes += p.length
            }

            ConversationStream(
                key = key,
                localEndpoint = localEp,
                remoteEndpoint = remoteEp,
                remoteIp = remoteIp,
                remotePort = remotePort,
                protocol = highestProto,
                transportProtocol = first.transportProtocol,
                hostLabel = host,
                packetCount = list.size,
                bytesOut = outBytes,
                bytesIn = inBytes,
                firstSeenMs = first.timestampMs,
                lastSeenMs = last.timestampMs,
                captureSource = first.captureSource
            )
        }.sortedByDescending { it.lastSeenMs }
    }

    private fun buildProtocolStats(packets: List<CapturedPacket>): List<ProtocolStat> {
        if (packets.isEmpty()) return emptyList()
        val total = packets.size.toFloat()
        return packets.groupBy { it.protocol }
            .entries
            .map { (proto, list) ->
                ProtocolStat(
                    protocol = proto,
                    packetCount = list.size,
                    totalBytes = list.sumOf { it.length.toLong() },
                    fraction = list.size / total
                )
            }
            .sortedByDescending { it.packetCount }
    }
}
