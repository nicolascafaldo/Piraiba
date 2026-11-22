package com.example.model

enum class ProtocolType(val label: String) {
    TCP("TCP"),
    TLS("TLS"),
    HTTP("HTTP"),
    DNS("DNS"),
    UDP("UDP"),
    QUIC("QUIC"),
    ICMP("ICMP"),
    OTHER("IP")
}

enum class PacketDirection(val shortLabel: String) {
    OUTBOUND("OUT"),
    INBOUND("IN")
}

enum class LinkLayerType {
    RAW_TUN,
    ETHERNET,
    LINUX_SLL,
    LINUX_SLL2
}

enum class CaptureSource(val label: String, val shortLabel: String) {
    DEVICE_VPN("Phone (tun0)", "PHONE"),
    LAN_PROMISCUOUS("LAN Promiscuous", "LAN")
}

enum class TrafficScopeFilter(val label: String) {
    ALL("All"),
    PHONE_ONLY("Phone"),
    LAN_ONLY("LAN")
}

data class ProtocolField(
    val label: String,
    val value: String,
    val byteStart: Int,
    val byteEnd: Int
)

data class ProtocolLayer(
    val name: String,
    val byteStart: Int,
    val byteEnd: Int,
    val fields: List<ProtocolField>
)

data class DnsMapping(
    val ip: String,
    val domain: String
)

enum class ResolutionSource(val shortLabel: String, val priority: Int) {
    WELL_KNOWN("MCAST", 0),
    REVERSE_PTR("PTR", 1),
    SSDP_INFO("SSDP", 2),
    MDNS_LAN("mDNS", 3),
    HTTP_HOST("HTTP", 4),
    TLS_SNI("SNI", 5),
    DNS_ANSWER("DNS", 6)
}

data class ResolvedHost(
    val ip: String,
    val domain: String,
    val source: ResolutionSource,
    val updatedAtMs: Long
)

data class CapturedPacket(
    val id: Long,
    val timestampMs: Long,
    val relativeTimeMs: Long,
    val direction: PacketDirection,
    val ipVersion: Int,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val transportProtocol: String,
    val protocol: ProtocolType,
    val length: Int,
    val hostOrSni: String?,
    val infoSummary: String,
    val tcpFlags: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val rawBytes: ByteArray,
    val layers: List<ProtocolLayer>,
    val linkLayerType: LinkLayerType = LinkLayerType.RAW_TUN,
    val dnsMappings: List<DnsMapping> = emptyList(),
    val captureSource: CaptureSource = CaptureSource.DEVICE_VPN
) {
    val streamKey: String
        get() {
            val a = "$srcIp:$srcPort"
            val b = "$dstIp:$dstPort"
            val prefix = captureSource.shortLabel
            return if (a <= b) "$prefix|$transportProtocol|$a|$b" else "$prefix|$transportProtocol|$b|$a"
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CapturedPacket) return false
        return id == other.id && timestampMs == other.timestampMs && length == other.length
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + timestampMs.hashCode()
        result = 31 * result + length
        return result
    }
}

data class ConversationStream(
    val key: String,
    val localEndpoint: String,
    val remoteEndpoint: String,
    val remoteIp: String,
    val remotePort: Int,
    val protocol: ProtocolType,
    val transportProtocol: String,
    val hostLabel: String?,
    val packetCount: Int,
    val bytesOut: Long,
    val bytesIn: Long,
    val firstSeenMs: Long,
    val lastSeenMs: Long,
    val captureSource: CaptureSource = CaptureSource.DEVICE_VPN
) {
    val totalBytes: Long get() = bytesOut + bytesIn
}

data class ThroughputPoint(
    val bucketSecond: Long,
    val packetsPerSec: Int,
    val bytesOut: Long,
    val bytesIn: Long
)

data class ProtocolStat(
    val protocol: ProtocolType,
    val packetCount: Int,
    val totalBytes: Long,
    val fraction: Float
)

enum class QuickFilter(val label: String) {
    ALL("All"),
    TCP("TCP"),
    TLS("TLS"),
    DNS("DNS"),
    HTTP("HTTP"),
    UDP("UDP"),
    ICMP("ICMP")
}

enum class RootSandboxStatus(val label: String) {
    UNCHECKED("Not Checked"),
    CHECKING("Checking Root..."),
    ROOT_READY("Root Ready"),
    ROOT_RUNNING("Root Capture Active"),
    NO_ROOT_OR_DENIED("No Root Access"),
    NO_TCPDUMP("tcpdump Missing"),
    ERROR("Sandbox Error")
}

data class RootSandboxState(
    val status: RootSandboxStatus = RootSandboxStatus.UNCHECKED,
    val suAvailable: Boolean = false,
    val tcpdumpPath: String? = null,
    val availableInterfaces: List<String> = listOf("wlan0", "any"),
    val selectedInterface: String = "wlan0",
    val bpfFilter: String = "",
    val promiscuousMode: Boolean = true,
    val capturedFrames: Long = 0L,
    val statusDetail: String = "Tap Check Root to inspect local su + tcpdump availability on this device.",
    val consoleLogs: List<String> = emptyList()
)
