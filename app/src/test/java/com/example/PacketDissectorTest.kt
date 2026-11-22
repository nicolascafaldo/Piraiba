package com.example

import com.example.capture.DnsResolutionCache
import com.example.dissector.DisplayFilterParser
import com.example.dissector.PacketDissector
import com.example.dissector.PcapCodec
import com.example.model.CaptureSource
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import com.example.model.ProtocolType
import com.example.model.QuickFilter
import com.example.model.ResolutionSource
import com.example.model.ResolvedHost
import com.example.vpn.PacketChecksumUtils
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class PacketDissectorTest {

    @Before
    fun setUp() {
        DnsResolutionCache.setAutoPtrEnabled(false)
        DnsResolutionCache.clear()
    }

    @After
    fun tearDown() {
        DnsResolutionCache.clear()
        DnsResolutionCache.setAutoPtrEnabled(false)
    }

    @Test
    fun dissectsIpv4TcpHttpPacketAndMatchesPayloadFilter() {
        val httpPayload = "GET /api/status HTTP/1.1\r\nHost: api.example.org\r\nUser-Agent: Test\r\n\r\n"
            .toByteArray(StandardCharsets.US_ASCII)
        val raw = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(93, 184.toByte(), 215.toByte(), 14),
            srcPort = 51234,
            dstPort = 80,
            flags = PacketDissector.TCP_FLAG_PSH or PacketDissector.TCP_FLAG_ACK,
            payload = httpPayload
        )

        val pkt = PacketDissector.dissect(1L, raw, 1_700_000_000_000L, 12L, PacketDirection.OUTBOUND)
        assertEquals(ProtocolType.HTTP, pkt.protocol)
        assertEquals("10.1.10.1", pkt.srcIp)
        assertEquals("93.184.215.14", pkt.dstIp)
        assertEquals(51234, pkt.srcPort)
        assertEquals(80, pkt.dstPort)
        assertEquals("api.example.org", pkt.hostOrSni)
        assertTrue(pkt.layers.any { it.name.contains("Hypertext Transfer Protocol") })

        assertTrue(DisplayFilterParser.parse("http && port == 80", QuickFilter.ALL).matches(pkt))
        assertTrue(DisplayFilterParser.parse("payload contains \"/api/status\"", QuickFilter.ALL).matches(pkt))
        assertTrue(DisplayFilterParser.parse("ip.src == 10.1.10.1", QuickFilter.ALL).matches(pkt))
        assertFalse(DisplayFilterParser.parse("dns", QuickFilter.ALL).matches(pkt))
    }

    @Test
    fun dissectsEthernetHeaderWhenLinkLayerIsEthernet() {
        val ip = buildIpv4Tcp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 10),
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 44000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_SYN,
            payload = ByteArray(0)
        )
        val ethHeader = byteArrayOf(
            0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(), 0xdd.toByte(), 0xee.toByte(), 0xff.toByte(),
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x08, 0x00
        )
        val frame = ethHeader + ip
        val pkt = PacketDissector.dissect(
            id = 2L,
            rawBytes = frame,
            timestampMs = 1_700_000_000_100L,
            relativeTimeMs = 100L,
            direction = PacketDirection.OUTBOUND,
            linkLayerType = LinkLayerType.ETHERNET
        )
        assertTrue(pkt.layers.any { it.name.startsWith("Ethernet II") })
        assertEquals("192.168.1.10", pkt.srcIp)
        assertEquals(443, pkt.dstPort)
    }

    @Test
    fun pcapRoundTripPreservesPackets() {
        val raw = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 50000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_SYN,
            payload = ByteArray(0)
        )
        val pkt = PacketDissector.dissect(1L, raw, 1_700_000_000_000L, 0L, PacketDirection.OUTBOUND)

        val out = ByteArrayOutputStream()
        PcapCodec.writePcap(listOf(pkt), out)

        val imported = PcapCodec.readPcap(ByteArrayInputStream(out.toByteArray()))
        assertEquals(1, imported.size)
        assertEquals("10.1.10.1", imported.first().srcIp)
        assertEquals("1.1.1.1", imported.first().dstIp)
        assertEquals(443, imported.first().dstPort)
        assertEquals(LinkLayerType.RAW_TUN, imported.first().linkLayerType)
    }

    @Test
    fun ethernetPcapExportWritesLinkTypeEthernetAndPreservesFrames() {
        val ip = buildIpv4Tcp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 50),
            dstIp = byteArrayOf(8, 8, 4, 4),
            srcPort = 52000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_SYN,
            payload = ByteArray(0)
        )
        val ethHeader = byteArrayOf(
            0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(), 0xdd.toByte(), 0xee.toByte(), 0xff.toByte(),
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x08, 0x00
        )
        val pkt = PacketDissector.dissect(
            id = 1L,
            rawBytes = ethHeader + ip,
            timestampMs = 1_700_000_000_250L,
            relativeTimeMs = 0L,
            direction = PacketDirection.OUTBOUND,
            linkLayerType = LinkLayerType.ETHERNET
        )

        val out = ByteArrayOutputStream()
        PcapCodec.writePcap(listOf(pkt), out)
        val bytes = out.toByteArray()

        // Verify libpcap little-endian magic (d4 c3 b2 a1) and LINKTYPE_ETHERNET (1) at offset 20
        assertEquals(0xd4.toByte(), bytes[0])
        assertEquals(0xc3.toByte(), bytes[1])
        assertEquals(0xb2.toByte(), bytes[2])
        assertEquals(0xa1.toByte(), bytes[3])
        assertEquals(1, bytes[20].toInt() and 0xFF)

        val reimported = PcapCodec.readPcap(ByteArrayInputStream(bytes))
        assertEquals(1, reimported.size)
        assertEquals(LinkLayerType.ETHERNET, reimported.first().linkLayerType)
        assertEquals("192.168.1.50", reimported.first().srcIp)
    }

    @Test
    fun dissectsDnsResponseAndPopulatesResolutionCacheWithPriority() {
        DnsResolutionCache.clear()

        val dnsPayload = buildDnsAResponse(
            txId = 0x1A2B,
            domain = "api.example.org",
            resolvedIp = byteArrayOf(93, 184.toByte(), 215.toByte(), 14)
        )
        val raw = buildIpv4Udp(
            srcIp = byteArrayOf(8, 8, 8, 8),
            dstIp = byteArrayOf(10, 1, 10, 1),
            srcPort = 53,
            dstPort = 53123,
            payload = dnsPayload
        )
        val pkt = PacketDissector.dissect(10L, raw, 1_700_000_001_000L, 50L, PacketDirection.INBOUND)
        assertEquals(ProtocolType.DNS, pkt.protocol)
        assertEquals(1, pkt.dnsMappings.size)
        assertEquals("93.184.215.14", pkt.dnsMappings.first().ip)
        assertEquals("api.example.org", pkt.dnsMappings.first().domain)

        // Lower-priority PTR must not overwrite DNS_ANSWER, and private TUN IP is ignored
        DnsResolutionCache.putMapping("93.184.215.14", "edge.generic-cdn.net", ResolutionSource.REVERSE_PTR)
        DnsResolutionCache.ingestPacket(pkt)
        DnsResolutionCache.putMapping("93.184.215.14", "fallback.ptr.net", ResolutionSource.REVERSE_PTR)
        DnsResolutionCache.putMapping("10.1.10.1", "should-ignore.local", ResolutionSource.DNS_ANSWER)

        val map = DnsResolutionCache.resolvedHosts.value
        assertEquals("api.example.org", map["93.184.215.14"]?.domain)
        assertEquals(ResolutionSource.DNS_ANSWER, map["93.184.215.14"]?.source)
        assertFalse(map.containsKey("10.1.10.1"))
        DnsResolutionCache.clear()
    }

    @Test
    fun passiveIpClassificationIgnoresLocalTunAndAcceptsLanAndPublicIps() {
        assertFalse(DnsResolutionCache.isResolvablePublicIp("10.1.10.1"))
        assertFalse(DnsResolutionCache.isResolvablePublicIp("192.168.1.1"))
        assertTrue(DnsResolutionCache.isResolvablePublicIp("8.8.8.8"))
        assertFalse(DnsResolutionCache.isResolvableAnyIp("10.1.10.1"))
        assertTrue(DnsResolutionCache.isResolvableAnyIp("192.168.1.1"))
        assertTrue(DnsResolutionCache.isResolvableAnyIp("8.8.8.8"))
    }

    @Test
    fun displayFilterMatchesPacketsByResolvedDomainName() {
        val raw = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(140.toByte(), 82, 121, 4),
            srcPort = 51000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_SYN,
            payload = ByteArray(0)
        )
        val pkt = PacketDissector.dissect(20L, raw, 1_700_000_002_000L, 80L, PacketDirection.OUTBOUND)
        val resolved = mapOf(
            "140.82.121.4" to ResolvedHost(
                ip = "140.82.121.4",
                domain = "github.com",
                source = ResolutionSource.TLS_SNI,
                updatedAtMs = 1_700_000_002_000L
            )
        )

        assertTrue(DisplayFilterParser.parse("dns.resolved contains github", QuickFilter.ALL, resolved).matches(pkt))
        assertTrue(DisplayFilterParser.parse("github", QuickFilter.ALL, resolved).matches(pkt))
        assertFalse(DisplayFilterParser.parse("github", QuickFilter.ALL, emptyMap()).matches(pkt))
    }

    @Test
    fun doesNotDissectTransportHeadersOutOfNonFirstFragments() {
        val raw = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 50000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_SYN,
            payload = ByteArray(0)
        )
        // Mark as a non-first fragment (fragOffset = 185 -> 1480 bytes in). There is no
        // transport header at l4Offset for such a packet, so ports/flags read from there
        // would be payload bytes: phantom TCP sessions, bogus AlertMonitor SYNs, and
        // (for UDP fragments) poisoned DnsResolutionCache entries.
        raw[6] = 0x00
        raw[7] = 185.toByte()

        val pkt = PacketDissector.dissect(9L, raw, 1_700_000_000_000L, 0L, PacketDirection.OUTBOUND)
        assertEquals(ProtocolType.OTHER, pkt.protocol)
        assertEquals(0, pkt.srcPort)
        assertEquals(0, pkt.dstPort)
        assertTrue(pkt.infoSummary.contains("fragment"))
        assertFalse(DisplayFilterParser.parse("tcp", QuickFilter.ALL).matches(pkt))

        // First fragment (offset 0, MF set) DOES carry the transport header — still dissected.
        val firstFrag = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 50000,
            dstPort = 443,
            flags = PacketDissector.TCP_FLAG_SYN,
            payload = ByteArray(0)
        )
        firstFrag[6] = 0x20 // MF set, offset 0
        firstFrag[7] = 0x00
        val firstPkt = PacketDissector.dissect(10L, firstFrag, 1_700_000_000_000L, 0L, PacketDirection.OUTBOUND)
        assertEquals(ProtocolType.TCP, firstPkt.protocol)
        assertEquals(443, firstPkt.dstPort)
    }

    @Test
    fun oversizedFilterIsRejectedInsteadOfStackOverflowing() {
        // Length guard fires before any recursion (512 chars max).
        val tooLong = DisplayFilterParser.parse(
            query = "(!".repeat(500),
            quickFilter = QuickFilter.ALL
        )
        assertFalse(tooLong.isValid)
        assertTrue(tooLong.errorHint?.contains("512") == true)

        // Within the cap, deep recursion must complete normally — an uncaught
        // StackOverflowError would crash the app (the parser runs on the main thread).
        // Deep '!' chain bottoms out in a missing-expression error, not a crash.
        val deepNot = DisplayFilterParser.parse("!".repeat(200), QuickFilter.ALL)
        assertFalse(deepNot.isValid)

        // Deep balanced parens must parse successfully end to end.
        val deepParens = DisplayFilterParser.parse(
            "(".repeat(100) + "tcp" + ")".repeat(100),
            QuickFilter.ALL
        )
        assertTrue(deepParens.isValid)
    }

    @Test
    fun displayFilterMatchesArpMdnsAndSsdpProtocolAtomsWithoutMetadataCrossMatch() {
        val mdnsPkt = PacketDissector.dissect(
            id = 30L,
            rawBytes = buildIpv4Udp(
                srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 20),
                dstIp = byteArrayOf(224.toByte(), 0, 0, 251.toByte()),
                srcPort = 5353,
                dstPort = 5353,
                payload = ByteArray(12)
            ),
            timestampMs = 1_700_000_003_000L,
            relativeTimeMs = 0L,
            direction = PacketDirection.INBOUND,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        val ssdpPkt = PacketDissector.dissect(
            id = 31L,
            rawBytes = buildIpv4Udp(
                srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 30),
                dstIp = byteArrayOf(239.toByte(), 255.toByte(), 255.toByte(), 250.toByte()),
                srcPort = 49000,
                dstPort = 1900,
                payload = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
            ),
            timestampMs = 1_700_000_003_010L,
            relativeTimeMs = 10L,
            direction = PacketDirection.INBOUND,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        val arpRaw = ByteArray(14).apply { this[12] = 0x08; this[13] = 0x06 } + byteArrayOf(
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            192.toByte(), 168.toByte(), 1, 25,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            192.toByte(), 168.toByte(), 1, 1
        )
        val arpPkt = PacketDissector.dissect(
            id = 32L,
            rawBytes = arpRaw,
            timestampMs = 1_700_000_003_020L,
            relativeTimeMs = 20L,
            direction = PacketDirection.INBOUND,
            linkLayerType = LinkLayerType.ETHERNET,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        val tcpWithArpWord = PacketDissector.dissect(
            id = 33L,
            rawBytes = buildIpv4Tcp(
                srcIp = byteArrayOf(10, 1, 10, 1),
                dstIp = byteArrayOf(93, 184.toByte(), 215.toByte(), 14),
                srcPort = 52000,
                dstPort = 80,
                flags = PacketDissector.TCP_FLAG_PSH or PacketDissector.TCP_FLAG_ACK,
                payload = "GET /carpet HTTP/1.1\r\nHost: example.arpa\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
            ),
            timestampMs = 1_700_000_003_030L,
            relativeTimeMs = 30L,
            direction = PacketDirection.OUTBOUND
        )

        val mdnsFilter = DisplayFilterParser.parse("mdns", QuickFilter.ALL)
        val ssdpFilter = DisplayFilterParser.parse("ssdp", QuickFilter.ALL)
        val arpFilter = DisplayFilterParser.parse("arp", QuickFilter.ALL)
        val compoundFilter = DisplayFilterParser.parse("(mdns || ssdp) && !arp", QuickFilter.ALL)

        assertTrue(mdnsFilter.matches(mdnsPkt))
        assertFalse(mdnsFilter.matches(ssdpPkt))
        assertTrue(ssdpFilter.matches(ssdpPkt))
        assertFalse(ssdpFilter.matches(mdnsPkt))
        assertTrue(arpFilter.matches(arpPkt))
        assertFalse(arpFilter.matches(tcpWithArpWord))
        assertTrue(compoundFilter.matches(mdnsPkt))
        assertTrue(compoundFilter.matches(ssdpPkt))
        assertFalse(compoundFilter.matches(arpPkt))
    }

    private fun buildIpv4Tcp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        flags: Int,
        payload: ByteArray
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
        System.arraycopy(payload, 0, pkt, 40, payload.size)

        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 6, 20 + payload.size)
        return pkt
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

    private fun buildDnsAResponse(txId: Int, domain: String, resolvedIp: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((txId ushr 8) and 0xFF); out.write(txId and 0xFF)
        out.write(0x81); out.write(0x80) // standard response, no error
        out.write(0x00); out.write(0x01) // QD=1
        out.write(0x00); out.write(0x01) // AN=1
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        writeDnsName(out, domain)
        out.write(0x00); out.write(0x01) // QTYPE A
        out.write(0x00); out.write(0x01) // QCLASS IN
        // Answer pointing to offset 12 (0xC00C)
        out.write(0xC0); out.write(0x0C)
        out.write(0x00); out.write(0x01) // TYPE A
        out.write(0x00); out.write(0x01) // CLASS IN
        out.write(0x00); out.write(0x00); out.write(0x01); out.write(0x2C) // TTL 300s
        out.write(0x00); out.write(0x04) // RDLEN 4
        out.write(resolvedIp)
        return out.toByteArray()
    }

    private fun writeDnsName(out: ByteArrayOutputStream, name: String) {
        for (label in name.split('.')) {
            val bytes = label.toByteArray(StandardCharsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)
    }
}
