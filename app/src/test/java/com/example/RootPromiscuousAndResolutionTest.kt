package com.example

import com.example.capture.DnsResolutionCache
import com.example.capture.LanMulticastSniffer
import com.example.capture.RootPromiscuousSniffer
import com.example.dissector.PacketDissector
import com.example.dissector.PcapCodec
import com.example.model.CaptureSource
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import com.example.model.ProtocolType
import com.example.model.ResolutionSource
import com.example.vpn.PacketChecksumUtils
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.charset.StandardCharsets

class RootPromiscuousAndResolutionTest {

    @Before
    fun setup() {
        DnsResolutionCache.setAutoPtrEnabled(false)
        DnsResolutionCache.clear()
    }

    @After
    fun teardown() {
        DnsResolutionCache.clear()
        DnsResolutionCache.setAutoPtrEnabled(false)
    }

    @Test
    fun mdnsAdditionalRecordResolvesLanIpInResolutionCache() {
        val mdnsPayload = buildMdnsResponseWithAdditionalA(
            servicePtrName = "_http._tcp.local",
            hostName = "office-printer.local",
            hostIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 77)
        )
        val frame = LanMulticastSniffer.buildLanUdpFrame(
            srcIp = InetAddress.getByName("192.168.1.77").address,
            dstIp = InetAddress.getByName(LanMulticastSniffer.MDNS_GROUP).address,
            srcPort = 5353,
            dstPort = 5353,
            payload = mdnsPayload
        )
        val pkt = PacketDissector.dissect(
            id = 100L,
            rawBytes = frame,
            timestampMs = 1_700_000_010_000L,
            relativeTimeMs = 10L,
            direction = PacketDirection.INBOUND,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        assertEquals(ProtocolType.DNS, pkt.protocol)
        assertTrue(pkt.dnsMappings.any { it.ip == "192.168.1.77" && it.domain == "office-printer.local" })

        DnsResolutionCache.ingestPacket(pkt)
        val resolved = DnsResolutionCache.resolvedHosts.value
        assertEquals("office-printer.local", resolved["192.168.1.77"]?.domain)
        assertEquals(ResolutionSource.MDNS_LAN, resolved["192.168.1.77"]?.source)
        assertEquals("mdns.mcast.net", resolved["224.0.0.251"]?.domain)
    }

    @Test
    fun ssdpNotifyExtractsLanDeviceLabelAndSeedsResolutionCache() {
        val ssdpText = (
            "NOTIFY * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "SERVER: Linux/5.15 UPnP/1.0 LivingRoom-NAS/2.1\r\n" +
                "NT: upnp:rootdevice\r\n" +
                "LOCATION: http://192.168.1.88:5000/desc.xml\r\n\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)

        val frame = LanMulticastSniffer.buildLanUdpFrame(
            srcIp = InetAddress.getByName("192.168.1.88").address,
            dstIp = InetAddress.getByName(LanMulticastSniffer.SSDP_GROUP).address,
            srcPort = 49152,
            dstPort = 1900,
            payload = ssdpText
        )
        val pkt = PacketDissector.dissect(
            id = 101L,
            rawBytes = frame,
            timestampMs = 1_700_000_011_000L,
            relativeTimeMs = 20L,
            direction = PacketDirection.INBOUND,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )

        assertTrue(pkt.layers.any { it.name.contains("SSDP") || it.name.contains("Discovery") })
        assertFalse(pkt.hostOrSni.isNullOrBlank())

        DnsResolutionCache.ingestPacket(pkt)
        val resolved = DnsResolutionCache.resolvedHosts.value
        assertTrue(resolved.containsKey("192.168.1.88"))
        assertEquals(ResolutionSource.SSDP_INFO, resolved["192.168.1.88"]?.source)
        assertEquals("ssdp.upnp.mcast.net", resolved["239.255.255.250"]?.domain)
    }

    @Test
    fun dissectsLinuxSll2AndArpFramesFromRootCapture() {
        // SLL2 (20 bytes) + IPv4 TCP
        val ip = buildIpv4Udp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 20),
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 51000,
            dstPort = 53,
            payload = ByteArray(12)
        )
        val sll2Header = ByteArray(20).apply {
            this[0] = 0x08; this[1] = 0x00 // EtherType IPv4
        }
        val sll2Pkt = PacketDissector.dissect(
            id = 200L,
            rawBytes = sll2Header + ip,
            timestampMs = 1_700_000_020_000L,
            relativeTimeMs = 5L,
            direction = PacketDirection.OUTBOUND,
            linkLayerType = LinkLayerType.LINUX_SLL2,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        assertEquals("192.168.1.20", sll2Pkt.srcIp)
        assertEquals("8.8.8.8", sll2Pkt.dstIp)
        assertTrue(sll2Pkt.layers.any { it.name.contains("SLL2") })

        // Ethernet + ARP Who-Has 192.168.1.1
        val ethArpHeader = ByteArray(14).apply {
            this[12] = 0x08; this[13] = 0x06 // EtherType ARP
        }
        val arpPayload = byteArrayOf(
            0x00, 0x01, // HTYPE Ethernet
            0x08, 0x00, // PTYPE IPv4
            0x06, 0x04, // HLEN=6, PLEN=4
            0x00, 0x01, // Opcode 1 (Request)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Sender MAC
            192.toByte(), 168.toByte(), 1, 25, // Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
            192.toByte(), 168.toByte(), 1, 1 // Target IP
        )
        val arpPkt = PacketDissector.dissect(
            id = 201L,
            rawBytes = ethArpHeader + arpPayload,
            timestampMs = 1_700_000_021_000L,
            relativeTimeMs = 15L,
            direction = PacketDirection.INBOUND,
            linkLayerType = LinkLayerType.ETHERNET,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        assertEquals("ARP", arpPkt.transportProtocol)
        assertEquals("192.168.1.25", arpPkt.srcIp)
        assertEquals("192.168.1.1", arpPkt.dstIp)
        assertTrue(arpPkt.infoSummary.contains("Who has 192.168.1.1"))
    }

    @Test
    fun parseLibpcapStreamStreamsEthernetAndLinuxSllFrames() {
        val out = ByteArrayOutputStream()
        // Little-endian libpcap global header (LINKTYPE_LINUX_SLL = 113)
        out.write(byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte()))
        writeShortLe(out, 2); writeShortLe(out, 4)
        writeIntLe(out, 0); writeIntLe(out, 0)
        writeIntLe(out, 65535)
        writeIntLe(out, PcapCodec.LINKTYPE_LINUX_SLL)

        val sllHeader = ByteArray(16).apply { this[14] = 0x08; this[15] = 0x00 }
        val udpIp = buildIpv4Udp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 90),
            dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
            srcPort = 44444,
            dstPort = 53,
            payload = ByteArray(8)
        )
        val frame = sllHeader + udpIp
        writeIntLe(out, 1_700_000_000)
        writeIntLe(out, 123_000)
        writeIntLe(out, frame.size)
        writeIntLe(out, frame.size)
        out.write(frame)

        val collected = mutableListOf<Pair<ByteArray, LinkLayerType>>()
        RootPromiscuousSniffer.parseLibpcapStream(ByteArrayInputStream(out.toByteArray())) { bytes, ll ->
            collected.add(bytes to ll)
        }

        assertEquals(1, collected.size)
        assertEquals(LinkLayerType.LINUX_SLL, collected.first().second)
        val pkt = PacketDissector.dissect(
            id = 300L,
            rawBytes = collected.first().first,
            timestampMs = 1_700_000_000_123L,
            relativeTimeMs = 0L,
            direction = PacketDirection.INBOUND,
            linkLayerType = collected.first().second,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        assertEquals("192.168.1.90", pkt.srcIp)
        assertEquals("192.168.1.1", pkt.dstIp)
    }

    @Test
    fun parseLibpcapStreamSkipsZeroLengthAndStopsAtOversizedBound() {
        val out = ByteArrayOutputStream()
        // Little-endian libpcap global header (LINKTYPE_ETHERNET = 1)
        out.write(byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte()))
        writeShortLe(out, 2); writeShortLe(out, 4)
        writeIntLe(out, 0); writeIntLe(out, 0)
        writeIntLe(out, 65535)
        writeIntLe(out, PcapCodec.LINKTYPE_ETHERNET)

        // Record 1: inclLen == 0 must be skipped without ending the stream
        writeIntLe(out, 1_700_000_000); writeIntLe(out, 0)
        writeIntLe(out, 0); writeIntLe(out, 0)

        // Record 2: valid Ethernet + IPv4 UDP frame must still be delivered
        val ethHeader = ByteArray(14).apply { this[12] = 0x08; this[13] = 0x00 }
        val validFrame = ethHeader + buildIpv4Udp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 10),
            dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
            srcPort = 50000,
            dstPort = 53,
            payload = ByteArray(8)
        )
        writeIntLe(out, 1_700_000_001); writeIntLe(out, 0)
        writeIntLe(out, validFrame.size); writeIntLe(out, validFrame.size)
        out.write(validFrame)

        // Record 3: inclLen > 1024 * 1024 must stop parsing immediately before allocating
        writeIntLe(out, 1_700_000_002); writeIntLe(out, 0)
        writeIntLe(out, (1024 * 1024) + 1); writeIntLe(out, (1024 * 1024) + 1)

        // Record 4: trailing valid frame after the oversized header must not be reached
        writeIntLe(out, 1_700_000_003); writeIntLe(out, 0)
        writeIntLe(out, validFrame.size); writeIntLe(out, validFrame.size)
        out.write(validFrame)

        val collected = mutableListOf<Pair<ByteArray, LinkLayerType>>()
        RootPromiscuousSniffer.parseLibpcapStream(ByteArrayInputStream(out.toByteArray())) { bytes, ll ->
            collected.add(bytes to ll)
        }

        assertEquals(1, collected.size)
        assertEquals(LinkLayerType.ETHERNET, collected.single().second)
        assertEquals(validFrame.size, collected.single().first.size)
    }

    private fun buildMdnsResponseWithAdditionalA(
        servicePtrName: String,
        hostName: String,
        hostIp: ByteArray
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x00); out.write(0x00) // txId
        out.write(0x84); out.write(0x00) // response
        out.write(0x00); out.write(0x00) // QD=0
        out.write(0x00); out.write(0x01) // AN=1 (PTR)
        out.write(0x00); out.write(0x00) // NS=0
        out.write(0x00); out.write(0x01) // AR=1 (A record in Additional!)

        // Answer: PTR _http._tcp.local -> hostName
        val ptrRdata = ByteArrayOutputStream().apply { writeDnsName(this, hostName) }.toByteArray()
        writeDnsName(out, servicePtrName)
        out.write(0x00); out.write(0x0C) // PTR
        out.write(0x00); out.write(0x01) // IN
        out.write(0x00); out.write(0x00); out.write(0x00); out.write(0x78)
        out.write((ptrRdata.size ushr 8) and 0xFF); out.write(ptrRdata.size and 0xFF)
        out.write(ptrRdata)

        // Additional: A hostName -> hostIp
        writeDnsName(out, hostName)
        out.write(0x00); out.write(0x01) // A
        out.write(0x00); out.write(0x01) // IN
        out.write(0x00); out.write(0x00); out.write(0x00); out.write(0x78)
        out.write(0x00); out.write(0x04)
        out.write(hostIp)
        return out.toByteArray()
    }

    private fun buildIpv4Udp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64
        pkt[9] = 17
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
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

    private fun writeDnsName(out: ByteArrayOutputStream, name: String) {
        for (label in name.split('.')) {
            val bytes = label.toByteArray(StandardCharsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)
    }

    private fun writeShortLe(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xFF)
        out.write((v ushr 8) and 0xFF)
    }

    private fun writeIntLe(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 24) and 0xFF)
    }
}
