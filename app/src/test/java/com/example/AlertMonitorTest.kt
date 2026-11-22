package com.example

import com.example.capture.AlertConfigStore
import com.example.capture.AlertMonitor
import com.example.dissector.PacketDissector
import com.example.model.AlertCategory
import com.example.model.AlertThresholdConfig
import com.example.model.CaptureSource
import com.example.model.PacketDirection
import com.example.model.PortMonitorMode
import com.example.vpn.PacketChecksumUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AlertMonitorTest {

    @Before
    fun setUp() {
        AlertMonitor.clearAlerts()
        AlertMonitor.resetTrackingState()
        AlertMonitor.updateConfig(AlertThresholdConfig())
    }

    @Test
    fun triggersHighLatencyAlertOnSlowTcpHandshake() {
        AlertMonitor.updateConfig(
            AlertThresholdConfig(
                alertsEnabled = true,
                highLatencyEnabled = true,
                maxLatencyMs = 100,
                unauthorizedPortEnabled = false,
                dataSpikeEnabled = false
            )
        )

        val synBytes = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(93, 184.toByte(), 215.toByte(), 14),
            srcPort = 54000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_SYN
        )
        val synAckBytes = buildIpv4Tcp(
            srcIp = byteArrayOf(93, 184.toByte(), 215.toByte(), 14),
            dstIp = byteArrayOf(10, 1, 10, 1),
            srcPort = 443,
            dstPort = 54000,
            flags = PacketDissector.TCP_FLAG_SYN or PacketDissector.TCP_FLAG_ACK
        )

        val synPkt = PacketDissector.dissect(1L, synBytes, 1_000_000L, 0L, PacketDirection.OUTBOUND)
        val synAckPkt = PacketDissector.dissect(2L, synAckBytes, 1_000_320L, 320L, PacketDirection.INBOUND)

        AlertMonitor.evaluatePacket(synPkt)
        assertTrue(AlertMonitor.alerts.value.isEmpty())

        AlertMonitor.evaluatePacket(synAckPkt)
        val alerts = AlertMonitor.alerts.value
        assertEquals(1, alerts.size)
        assertEquals(AlertCategory.HIGH_LATENCY, alerts.first().category)
        assertTrue(alerts.first().title.contains("320 ms"))
    }

    @Test
    fun triggersUnauthorizedPortInWatchedAndAllowlistModes() {
        AlertMonitor.updateConfig(
            AlertThresholdConfig(
                alertsEnabled = true,
                highLatencyEnabled = false,
                unauthorizedPortEnabled = true,
                portMonitorMode = PortMonitorMode.WATCHED_PORTS,
                flaggedPorts = setOf(22, 3389),
                dataSpikeEnabled = false
            )
        )

        val sshBytes = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(1, 2, 3, 4),
            srcPort = 55000,
            dstPort = 22,
            flags = PacketDissector.TCP_FLAG_SYN
        )
        AlertMonitor.evaluatePacket(
            PacketDissector.dissect(3L, sshBytes, 2_000_000L, 10L, PacketDirection.OUTBOUND)
        )
        assertEquals(1, AlertMonitor.alerts.value.size)
        assertEquals(AlertCategory.UNAUTHORIZED_PORT, AlertMonitor.alerts.value.first().category)

        // Switch to strict allowlist mode where 8443 is not allowed
        AlertMonitor.clearAlerts()
        AlertMonitor.updateConfig(
            AlertThresholdConfig(
                alertsEnabled = true,
                highLatencyEnabled = false,
                unauthorizedPortEnabled = true,
                portMonitorMode = PortMonitorMode.ALLOWLIST_ONLY,
                allowedPorts = setOf(53, 80, 443),
                dataSpikeEnabled = false
            )
        )
        val customPortBytes = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(5, 6, 7, 8),
            srcPort = 55001,
            dstPort = 8443,
            flags = PacketDissector.TCP_FLAG_SYN
        )
        AlertMonitor.evaluatePacket(
            PacketDissector.dissect(4L, customPortBytes, 2_000_500L, 20L, PacketDirection.OUTBOUND)
        )
        assertEquals(1, AlertMonitor.alerts.value.size)
        assertTrue(AlertMonitor.alerts.value.first().title.contains(":8443"))
    }

    @Test
    fun triggersDataSpikeWhenBytesPerSecondExceedsLimit() {
        AlertMonitor.updateConfig(
            AlertThresholdConfig(
                alertsEnabled = true,
                highLatencyEnabled = false,
                unauthorizedPortEnabled = false,
                dataSpikeEnabled = true,
                maxBytesPerSecKB = 2, // 2048 bytes/s threshold
                maxPacketsPerSec = 500
            )
        )

        val bigPayload = ByteArray(1200) { 0x41 }
        val pktBytes = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(9, 9, 9, 9),
            srcPort = 56000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_PSH or PacketDissector.TCP_FLAG_ACK,
            payload = bigPayload
        )
        // Two 1240-byte packets in the same second = 2480 bytes > 2048 B limit
        AlertMonitor.evaluatePacket(PacketDissector.dissect(5L, pktBytes, 3_000_100L, 10L, PacketDirection.OUTBOUND))
        assertTrue(AlertMonitor.alerts.value.isEmpty())

        AlertMonitor.evaluatePacket(PacketDissector.dissect(6L, pktBytes, 3_000_250L, 20L, PacketDirection.OUTBOUND))
        assertEquals(1, AlertMonitor.alerts.value.size)
        assertEquals(AlertCategory.DATA_SPIKE, AlertMonitor.alerts.value.first().category)
    }

    @Test
    fun portSetSerializationRoundTripsCleanly() {
        val encoded = AlertConfigStore.encodePorts(setOf(443, 22, 80, 8080))
        assertEquals("22,80,443,8080", encoded)
        assertEquals(setOf(22, 80, 443, 8080), AlertConfigStore.decodePorts(encoded))
        assertEquals(emptySet<Int>(), AlertConfigStore.decodePorts(""))
    }

    @Test
    fun preservesLanPromiscuousCaptureSourceOnAlertEvents() {
        AlertMonitor.updateConfig(
            AlertThresholdConfig(
                alertsEnabled = true,
                highLatencyEnabled = false,
                unauthorizedPortEnabled = true,
                portMonitorMode = PortMonitorMode.WATCHED_PORTS,
                flaggedPorts = setOf(23),
                dataSpikeEnabled = false
            )
        )
        val telnetLanBytes = buildIpv4Tcp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 99),
            dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
            srcPort = 23,
            dstPort = 51000,
            flags = PacketDissector.TCP_FLAG_SYN
        )
        AlertMonitor.evaluatePacket(
            PacketDissector.dissect(
                id = 77L,
                rawBytes = telnetLanBytes,
                timestampMs = 4_000_000L,
                relativeTimeMs = 0L,
                direction = PacketDirection.INBOUND,
                captureSource = CaptureSource.LAN_PROMISCUOUS
            )
        )

        val alert = AlertMonitor.alerts.value.single()
        assertEquals(CaptureSource.LAN_PROMISCUOUS, alert.captureSource)
        assertEquals(77L, alert.packetId)
    }

    private fun buildIpv4Tcp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        flags: Int,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val totalLen = 40 + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64
        pkt[9] = 6
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[32] = 0x50
        pkt[33] = flags.toByte()
        pkt[34] = 0xFF.toByte()
        pkt[35] = 0xFF.toByte()
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, 40, payload.size)
        }
        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 6, 20 + payload.size)
        return pkt
    }
}
