package com.example.model

enum class AlertCategory(val label: String) {
    HIGH_LATENCY("High Latency"),
    UNAUTHORIZED_PORT("Unauthorized Port"),
    DATA_SPIKE("Data Spike")
}

enum class AlertSeverity(val label: String) {
    WARNING("Warning"),
    CRITICAL("Critical")
}

enum class PortMonitorMode(val label: String, val description: String) {
    WATCHED_PORTS(
        label = "Watched Ports",
        description = "Flag traffic touching known risky or unexpected ports"
    ),
    ALLOWLIST_ONLY(
        label = "Strict Allowlist",
        description = "Flag any remote port outside your approved allowlist"
    )
}

data class AlertThresholdConfig(
    val alertsEnabled: Boolean = true,
    val highLatencyEnabled: Boolean = true,
    val maxLatencyMs: Int = 250,
    val unauthorizedPortEnabled: Boolean = true,
    val portMonitorMode: PortMonitorMode = PortMonitorMode.WATCHED_PORTS,
    val flaggedPorts: Set<Int> = DEFAULT_FLAGGED_PORTS,
    val allowedPorts: Set<Int> = DEFAULT_ALLOWED_PORTS,
    val dataSpikeEnabled: Boolean = true,
    val maxBytesPerSecKB: Int = 512,
    val maxPacketsPerSec: Int = 150,
    val notifySystemBar: Boolean = false
) {
    companion object {
        val DEFAULT_FLAGGED_PORTS = setOf(21, 22, 23, 25, 445, 1433, 3389, 4444, 5900)
        val DEFAULT_ALLOWED_PORTS = setOf(53, 80, 123, 443, 5353)
    }
}

data class NetworkAlertEvent(
    val id: Long,
    val timestampMs: Long,
    val category: AlertCategory,
    val severity: AlertSeverity,
    val title: String,
    val detail: String,
    val packetId: Long? = null,
    val filterExpr: String? = null,
    val captureSource: CaptureSource = CaptureSource.DEVICE_VPN
)
