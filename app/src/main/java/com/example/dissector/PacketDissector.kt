package com.example.dissector

import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.DnsMapping
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import com.example.model.ProtocolField
import com.example.model.ProtocolLayer
import com.example.model.ProtocolType
import com.example.vpn.PacketChecksumUtils
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Pure Kotlin multi-layer network packet dissector (Ethernet II, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS/SNI, HTTP, QUIC).
 * Every field carries exact byte bounds [byteStart, byteEnd) for interactive Hex Dump highlighting.
 */
object PacketDissector {

    const val TCP_FLAG_FIN = 0x01
    const val TCP_FLAG_SYN = 0x02
    const val TCP_FLAG_RST = 0x04
    const val TCP_FLAG_PSH = 0x08
    const val TCP_FLAG_ACK = 0x10
    const val TCP_FLAG_URG = 0x20
    const val TCP_FLAG_ECE = 0x40
    const val TCP_FLAG_CWR = 0x80

    fun dissect(
        id: Long,
        rawBytes: ByteArray,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        linkLayerType: LinkLayerType = LinkLayerType.RAW_TUN,
        captureSource: CaptureSource = CaptureSource.DEVICE_VPN
    ): CapturedPacket {
        val len = rawBytes.size
        val layers = mutableListOf<ProtocolLayer>()

        val interfaceLabel = when {
            captureSource == CaptureSource.LAN_PROMISCUOUS && linkLayerType == LinkLayerType.ETHERNET -> "wlan0 (Promiscuous Root)"
            captureSource == CaptureSource.LAN_PROMISCUOUS && (linkLayerType == LinkLayerType.LINUX_SLL || linkLayerType == LinkLayerType.LINUX_SLL2) -> "any (Promiscuous Root)"
            captureSource == CaptureSource.LAN_PROMISCUOUS -> "wlan0 (Promiscuous LAN Multicast)"
            linkLayerType == LinkLayerType.ETHERNET -> "eth0 (Ethernet II)"
            linkLayerType == LinkLayerType.LINUX_SLL || linkLayerType == LinkLayerType.LINUX_SLL2 -> "any (Linux Cooked)"
            else -> "tun0 (Raw IP)"
        }
        layers.add(
            ProtocolLayer(
                name = "Frame #$id: $len bytes on $interfaceLabel (${direction.shortLabel})",
                byteStart = 0,
                byteEnd = len,
                fields = listOf(
                    ProtocolField("Frame Number", "$id", 0, len),
                    ProtocolField("Capture Length", "$len bytes ($len * 8 = ${len * 8} bits)", 0, len),
                    ProtocolField("Capture Source", captureSource.label, 0, len),
                    ProtocolField("Interface", interfaceLabel, 0, len),
                    ProtocolField(
                        "Direction",
                        if (direction == PacketDirection.OUTBOUND) "Outbound (Device → Network)" else "Inbound (Network → Device)",
                        0,
                        len
                    ),
                    ProtocolField("Relative Time", String.format(Locale.US, "%.6f s", relativeTimeMs / 1000.0), 0, len)
                )
            )
        )

        var l3Offset = 0
        when (linkLayerType) {
            LinkLayerType.ETHERNET -> {
                if (len < 14) {
                    return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Truncated Ethernet frame")
                        .copy(captureSource = captureSource)
                }
                val dstMac = macString(rawBytes, 0)
                val srcMac = macString(rawBytes, 6)
                val etherType = u16(rawBytes, 12)
                val etherTypeLabel = etherTypeName(etherType)
                layers.add(
                    ProtocolLayer(
                        name = "Ethernet II, Src: $srcMac, Dst: $dstMac",
                        byteStart = 0,
                        byteEnd = 14,
                        fields = listOf(
                            ProtocolField("Destination MAC", dstMac, 0, 6),
                            ProtocolField("Source MAC", srcMac, 6, 12),
                            ProtocolField("Type", etherTypeLabel, 12, 14)
                        )
                    )
                )
                l3Offset = 14
                if (etherType == 0x0806) {
                    return dissectArp(id, rawBytes, l3Offset, timestampMs, relativeTimeMs, direction, linkLayerType, layers)
                        .copy(captureSource = captureSource)
                }
                if (etherType != 0x0800 && etherType != 0x86DD) {
                    return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Ethernet $etherTypeLabel")
                        .copy(captureSource = captureSource)
                }
            }
            LinkLayerType.LINUX_SLL -> {
                if (len < 16) {
                    return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Truncated Linux SLL frame")
                        .copy(captureSource = captureSource)
                }
                val pktType = u16(rawBytes, 0)
                val addrLen = u16(rawBytes, 4).coerceAtMost(8)
                val srcMac = if (addrLen == 6) macString(rawBytes, 6) else "—"
                val etherType = u16(rawBytes, 14)
                val etherTypeLabel = etherTypeName(etherType)
                layers.add(
                    ProtocolLayer(
                        name = "Linux Cooked Capture v1 (SLL), Src: $srcMac",
                        byteStart = 0,
                        byteEnd = 16,
                        fields = listOf(
                            ProtocolField("Packet Type", "$pktType", 0, 2),
                            ProtocolField("Link Address", srcMac, 6, 14),
                            ProtocolField("Protocol", etherTypeLabel, 14, 16)
                        )
                    )
                )
                l3Offset = 16
                if (etherType == 0x0806) {
                    return dissectArp(id, rawBytes, l3Offset, timestampMs, relativeTimeMs, direction, linkLayerType, layers)
                        .copy(captureSource = captureSource)
                }
                if (etherType != 0x0800 && etherType != 0x86DD) {
                    return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Linux SLL $etherTypeLabel")
                        .copy(captureSource = captureSource)
                }
            }
            LinkLayerType.LINUX_SLL2 -> {
                if (len < 20) {
                    return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Truncated Linux SLL2 frame")
                        .copy(captureSource = captureSource)
                }
                val etherType = u16(rawBytes, 0)
                val ifIndex = u32(rawBytes, 4)
                val addrLen = u8(rawBytes, 11).coerceAtMost(8)
                val srcMac = if (addrLen == 6) macString(rawBytes, 12) else "—"
                val etherTypeLabel = etherTypeName(etherType)
                layers.add(
                    ProtocolLayer(
                        name = "Linux Cooked Capture v2 (SLL2), ifIndex=$ifIndex",
                        byteStart = 0,
                        byteEnd = 20,
                        fields = listOf(
                            ProtocolField("Protocol", etherTypeLabel, 0, 2),
                            ProtocolField("Interface Index", "$ifIndex", 4, 8),
                            ProtocolField("Link Address", srcMac, 12, 20)
                        )
                    )
                )
                l3Offset = 20
                if (etherType == 0x0806) {
                    return dissectArp(id, rawBytes, l3Offset, timestampMs, relativeTimeMs, direction, linkLayerType, layers)
                        .copy(captureSource = captureSource)
                }
                if (etherType != 0x0800 && etherType != 0x86DD) {
                    return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Linux SLL2 $etherTypeLabel")
                        .copy(captureSource = captureSource)
                }
            }
            LinkLayerType.RAW_TUN -> {
                if (captureSource == CaptureSource.LAN_PROMISCUOUS) {
                    layers.add(
                        ProtocolLayer(
                            name = "Link Layer: Wi-Fi LAN Promiscuous Multicast (wlan0)",
                            byteStart = 0,
                            byteEnd = 0,
                            fields = listOf(
                                ProtocolField("Capture Mode", "WifiManager.MulticastLock (mDNS / SSDP / LLMNR)", 0, 0),
                                ProtocolField("Scope", "Local Wi-Fi Broadcast / Multicast Domain", 0, 0)
                            )
                        )
                    )
                } else {
                    layers.add(
                        ProtocolLayer(
                            name = "Link Layer: Android VPN TUN (tun0, Raw IPv4/IPv6)",
                            byteStart = 0,
                            byteEnd = 0,
                            fields = listOf(
                                ProtocolField("Encapsulation", "Raw IP (LINKTYPE_RAW / 101)", 0, 0),
                                ProtocolField("Virtual Interface", "tun0 (MTU 1500)", 0, 0)
                            )
                        )
                    )
                }
            }
        }

        if (l3Offset >= len) {
            return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Truncated frame")
                .copy(captureSource = captureSource)
        }

        val ipVersion = (rawBytes[l3Offset].toInt() ushr 4) and 0x0F
        val parsed = when (ipVersion) {
            4 -> dissectIpv4(id, rawBytes, l3Offset, timestampMs, relativeTimeMs, direction, linkLayerType, layers)
            6 -> dissectIpv6(id, rawBytes, l3Offset, timestampMs, relativeTimeMs, direction, linkLayerType, layers)
            else -> fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, rawBytes, layers, "Unknown L3 version ($ipVersion)")
        }
        return parsed.copy(captureSource = captureSource)
    }

    private fun etherTypeName(etherType: Int): String = when (etherType) {
        0x0800 -> "IPv4 (0x0800)"
        0x86DD -> "IPv6 (0x86dd)"
        0x0806 -> "ARP (0x0806)"
        else -> "0x${etherType.toString(16).padStart(4, '0')}"
    }

    private fun dissectArp(
        id: Long,
        raw: ByteArray,
        offset: Int,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        linkLayerType: LinkLayerType,
        layers: MutableList<ProtocolLayer>
    ): CapturedPacket {
        if (offset + 28 > raw.size) {
            return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, raw, layers, "Truncated ARP packet")
        }
        val opCode = u16(raw, offset + 6)
        val senderMac = macString(raw, offset + 8)
        val senderIp = ipv4String(raw, offset + 14)
        val targetMac = macString(raw, offset + 18)
        val targetIp = ipv4String(raw, offset + 24)
        val opLabel = when (opCode) {
            1 -> "Request"
            2 -> "Reply"
            else -> "Op($opCode)"
        }
        val info = when (opCode) {
            1 -> "ARP Who has $targetIp? Tell $senderIp ($senderMac)"
            2 -> "ARP $senderIp is at $senderMac"
            else -> "ARP $opLabel $senderIp → $targetIp"
        }
        layers.add(
            ProtocolLayer(
                name = "Address Resolution Protocol ($opLabel)",
                byteStart = offset,
                byteEnd = offset + 28,
                fields = listOf(
                    ProtocolField("Opcode", "$opLabel ($opCode)", offset + 6, offset + 8),
                    ProtocolField("Sender MAC", senderMac, offset + 8, offset + 14),
                    ProtocolField("Sender IP", senderIp, offset + 14, offset + 18),
                    ProtocolField("Target MAC", targetMac, offset + 18, offset + 24),
                    ProtocolField("Target IP", targetIp, offset + 24, offset + 28)
                )
            )
        )
        return CapturedPacket(
            id = id,
            timestampMs = timestampMs,
            relativeTimeMs = relativeTimeMs,
            direction = direction,
            ipVersion = 0,
            srcIp = senderIp,
            dstIp = targetIp,
            srcPort = 0,
            dstPort = 0,
            transportProtocol = "ARP",
            protocol = ProtocolType.OTHER,
            length = raw.size,
            hostOrSni = null,
            infoSummary = info,
            tcpFlags = 0,
            payloadOffset = offset,
            payloadLength = 28,
            rawBytes = raw,
            layers = layers,
            linkLayerType = linkLayerType
        )
    }

    private fun dissectIpv4(
        id: Long,
        raw: ByteArray,
        l3Offset: Int,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        linkLayerType: LinkLayerType,
        layers: MutableList<ProtocolLayer>
    ): CapturedPacket {
        if (l3Offset + 20 > raw.size) {
            return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, raw, layers, "Malformed IPv4 (<20 bytes)")
        }
        val ihl = ((raw[l3Offset].toInt() and 0x0F) * 4).coerceIn(20, raw.size - l3Offset)
        val dscp = (raw[l3Offset + 1].toInt() and 0xFC) ushr 2
        val ecn = raw[l3Offset + 1].toInt() and 0x03
        val totalLen = u16(raw, l3Offset + 2).coerceAtMost(raw.size - l3Offset)
        val ident = u16(raw, l3Offset + 4)
        val flagsAndFrag = u16(raw, l3Offset + 6)
        val df = (flagsAndFrag and 0x4000) != 0
        val mf = (flagsAndFrag and 0x2000) != 0
        val fragOffset = flagsAndFrag and 0x1FFF
        val ttl = u8(raw, l3Offset + 8)
        val protoNum = u8(raw, l3Offset + 9)
        val headerChecksum = u16(raw, l3Offset + 10)
        val expectedChecksum = PacketChecksumUtils.computeIpv4Checksum(raw, l3Offset, ihl)
        val checksumStatus = if (headerChecksum == expectedChecksum) "valid" else "mismatch (exp 0x${expectedChecksum.toString(16)})"
        val srcIp = ipv4String(raw, l3Offset + 12)
        val dstIp = ipv4String(raw, l3Offset + 16)

        val protoName = when (protoNum) {
            1 -> "ICMP (1)"
            6 -> "TCP (6)"
            17 -> "UDP (17)"
            else -> "Proto ($protoNum)"
        }

        val flagText = buildList {
            if (df) add("DF")
            if (mf) add("MF")
            if (isEmpty()) add("None")
        }.joinToString(", ")

        layers.add(
            ProtocolLayer(
                name = "Internet Protocol Version 4, Src: $srcIp, Dst: $dstIp",
                byteStart = l3Offset,
                byteEnd = l3Offset + ihl,
                fields = listOf(
                    ProtocolField("Version", "4", l3Offset, l3Offset + 1),
                    ProtocolField("Header Length (IHL)", "$ihl bytes", l3Offset, l3Offset + 1),
                    ProtocolField("DSCP / ECN", "DSCP=$dscp, ECN=$ecn", l3Offset + 1, l3Offset + 2),
                    ProtocolField("Total Length", "$totalLen bytes", l3Offset + 2, l3Offset + 4),
                    ProtocolField("Identification", "0x${ident.toString(16).padStart(4, '0')} ($ident)", l3Offset + 4, l3Offset + 6),
                    ProtocolField("Flags & Fragment", "$flagText, Offset=$fragOffset", l3Offset + 6, l3Offset + 8),
                    ProtocolField("Time to Live (TTL)", "$ttl", l3Offset + 8, l3Offset + 9),
                    ProtocolField("Protocol", protoName, l3Offset + 9, l3Offset + 10),
                    ProtocolField("Header Checksum", "0x${headerChecksum.toString(16).padStart(4, '0')} [$checksumStatus]", l3Offset + 10, l3Offset + 12),
                    ProtocolField("Source Address", srcIp, l3Offset + 12, l3Offset + 16),
                    ProtocolField("Destination Address", dstIp, l3Offset + 16, l3Offset + 20)
                )
            )
        )

        val l4Offset = l3Offset + ihl
        val ipEnd = (l3Offset + totalLen).coerceAtLeast(l4Offset)
        if (fragOffset != 0) {
            // Non-first fragment: there is NO transport header at l4Offset. Parsing L4/DNS/HTTP
            // out of fragment payload fabricates ports and flags, feeds AlertMonitor phantom
            // SYNs, and can write bogus IP↔domain mappings into DnsResolutionCache. Show it as
            // a raw fragment instead (what Wireshark does).
            return CapturedPacket(
                id = id,
                timestampMs = timestampMs,
                relativeTimeMs = relativeTimeMs,
                direction = direction,
                ipVersion = 4,
                srcIp = srcIp,
                dstIp = dstIp,
                srcPort = 0,
                dstPort = 0,
                transportProtocol = "IP/$protoNum",
                protocol = ProtocolType.OTHER,
                length = raw.size,
                hostOrSni = null,
                infoSummary = "IPv4 fragment (offset=$fragOffset, ${raw.size} bytes)",
                tcpFlags = 0,
                payloadOffset = l4Offset,
                payloadLength = (ipEnd - l4Offset).coerceAtLeast(0),
                rawBytes = raw,
                layers = layers,
                linkLayerType = linkLayerType
            )
        }
        return dissectTransport(
            id = id,
            raw = raw,
            timestampMs = timestampMs,
            relativeTimeMs = relativeTimeMs,
            direction = direction,
            ipVersion = 4,
            srcIp = srcIp,
            dstIp = dstIp,
            protoNum = protoNum,
            l4Offset = l4Offset,
            ipEnd = ipEnd,
            linkLayerType = linkLayerType,
            layers = layers
        )
    }

    private fun dissectIpv6(
        id: Long,
        raw: ByteArray,
        l3Offset: Int,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        linkLayerType: LinkLayerType,
        layers: MutableList<ProtocolLayer>
    ): CapturedPacket {
        if (l3Offset + 40 > raw.size) {
            return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, raw, layers, "Malformed IPv6 (<40 bytes)")
        }
        val tc = ((u8(raw, l3Offset) and 0x0F) shl 4) or ((u8(raw, l3Offset + 1) and 0xF0) ushr 4)
        val flowLabel = ((u8(raw, l3Offset + 1) and 0x0F) shl 16) or u16(raw, l3Offset + 2)
        val payloadLen = u16(raw, l3Offset + 4)
        val nextHeader = u8(raw, l3Offset + 6)
        val hopLimit = u8(raw, l3Offset + 7)
        val srcIp = ipv6String(raw, l3Offset + 8)
        val dstIp = ipv6String(raw, l3Offset + 24)

        layers.add(
            ProtocolLayer(
                name = "Internet Protocol Version 6, Src: $srcIp, Dst: $dstIp",
                byteStart = l3Offset,
                byteEnd = l3Offset + 40,
                fields = listOf(
                    ProtocolField("Version", "6", l3Offset, l3Offset + 1),
                    ProtocolField("Traffic Class", "0x${tc.toString(16)}", l3Offset, l3Offset + 2),
                    ProtocolField("Flow Label", "0x${flowLabel.toString(16).padStart(5, '0')}", l3Offset + 1, l3Offset + 4),
                    ProtocolField("Payload Length", "$payloadLen bytes", l3Offset + 4, l3Offset + 6),
                    ProtocolField("Next Header", "$nextHeader", l3Offset + 6, l3Offset + 7),
                    ProtocolField("Hop Limit", "$hopLimit", l3Offset + 7, l3Offset + 8),
                    ProtocolField("Source Address", srcIp, l3Offset + 8, l3Offset + 24),
                    ProtocolField("Destination Address", dstIp, l3Offset + 24, l3Offset + 40)
                )
            )
        )

        val protoNum = if (nextHeader == 58) 1 else nextHeader
        val l4Offset = l3Offset + 40
        return dissectTransport(
            id = id,
            raw = raw,
            timestampMs = timestampMs,
            relativeTimeMs = relativeTimeMs,
            direction = direction,
            ipVersion = 6,
            srcIp = srcIp,
            dstIp = dstIp,
            protoNum = protoNum,
            l4Offset = l4Offset,
            ipEnd = minOf(raw.size, l4Offset + payloadLen),
            linkLayerType = linkLayerType,
            layers = layers
        )
    }

    private fun dissectTransport(
        id: Long,
        raw: ByteArray,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        ipVersion: Int,
        srcIp: String,
        dstIp: String,
        protoNum: Int,
        l4Offset: Int,
        ipEnd: Int,
        linkLayerType: LinkLayerType,
        layers: MutableList<ProtocolLayer>
    ): CapturedPacket {
        return when (protoNum) {
            6 -> dissectTcp(id, raw, timestampMs, relativeTimeMs, direction, ipVersion, srcIp, dstIp, l4Offset, ipEnd, linkLayerType, layers)
            17 -> dissectUdp(id, raw, timestampMs, relativeTimeMs, direction, ipVersion, srcIp, dstIp, l4Offset, ipEnd, linkLayerType, layers)
            1 -> dissectIcmp(id, raw, timestampMs, relativeTimeMs, direction, ipVersion, srcIp, dstIp, l4Offset, ipEnd, linkLayerType, layers)
            else -> CapturedPacket(
                id = id,
                timestampMs = timestampMs,
                relativeTimeMs = relativeTimeMs,
                direction = direction,
                ipVersion = ipVersion,
                srcIp = srcIp,
                dstIp = dstIp,
                srcPort = 0,
                dstPort = 0,
                transportProtocol = "IP/$protoNum",
                protocol = ProtocolType.OTHER,
                length = raw.size,
                hostOrSni = null,
                infoSummary = "IPv$ipVersion Protocol $protoNum (${raw.size} bytes)",
                tcpFlags = 0,
                payloadOffset = l4Offset,
                payloadLength = (ipEnd - l4Offset).coerceAtLeast(0),
                rawBytes = raw,
                layers = layers,
                linkLayerType = linkLayerType
            )
        }
    }

    private fun dissectTcp(
        id: Long,
        raw: ByteArray,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        ipVersion: Int,
        srcIp: String,
        dstIp: String,
        l4Offset: Int,
        ipEnd: Int,
        linkLayerType: LinkLayerType,
        layers: MutableList<ProtocolLayer>
    ): CapturedPacket {
        if (l4Offset + 20 > raw.size) {
            return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, raw, layers, "Malformed TCP header")
        }
        val srcPort = u16(raw, l4Offset)
        val dstPort = u16(raw, l4Offset + 2)
        val seq = u32(raw, l4Offset + 4)
        val ack = u32(raw, l4Offset + 8)
        val rawDataOffset = ((u8(raw, l4Offset + 12) ushr 4) and 0x0F) * 4
        val tcpHeaderLen = rawDataOffset.coerceIn(20, (raw.size - l4Offset).coerceAtLeast(20))
        val flags = u8(raw, l4Offset + 13)
        val window = u16(raw, l4Offset + 14)
        val checksum = u16(raw, l4Offset + 16)
        val urgentPtr = u16(raw, l4Offset + 18)

        val flagList = buildList {
            if ((flags and TCP_FLAG_SYN) != 0) add("SYN")
            if ((flags and TCP_FLAG_ACK) != 0) add("ACK")
            if ((flags and TCP_FLAG_PSH) != 0) add("PSH")
            if ((flags and TCP_FLAG_FIN) != 0) add("FIN")
            if ((flags and TCP_FLAG_RST) != 0) add("RST")
            if ((flags and TCP_FLAG_URG) != 0) add("URG")
            if ((flags and TCP_FLAG_ECE) != 0) add("ECE")
            if ((flags and TCP_FLAG_CWR) != 0) add("CWR")
        }
        val flagsStr = if (flagList.isEmpty()) "NONE" else flagList.joinToString(", ")

        val payloadOffset = (l4Offset + tcpHeaderLen).coerceAtMost(raw.size)
        val payloadLen = (ipEnd - payloadOffset).coerceAtLeast(0)

        val tcpFields = mutableListOf(
            ProtocolField("Source Port", "$srcPort", l4Offset, l4Offset + 2),
            ProtocolField("Destination Port", "$dstPort", l4Offset + 2, l4Offset + 4),
            ProtocolField("Sequence Number", "$seq (0x${seq.toString(16)})", l4Offset + 4, l4Offset + 8),
            ProtocolField("Acknowledgment Number", "$ack (0x${ack.toString(16)})", l4Offset + 8, l4Offset + 12),
            ProtocolField("Header Length", "$tcpHeaderLen bytes", l4Offset + 12, l4Offset + 13),
            ProtocolField("Flags", "0x${flags.toString(16).padStart(2, '0')} [$flagsStr]", l4Offset + 13, l4Offset + 14),
            ProtocolField("Window Size", "$window", l4Offset + 14, l4Offset + 16),
            ProtocolField("Checksum", "0x${checksum.toString(16).padStart(4, '0')}", l4Offset + 16, l4Offset + 18),
            ProtocolField("Urgent Pointer", "$urgentPtr", l4Offset + 18, l4Offset + 20)
        )

        if (tcpHeaderLen > 20) {
            parseTcpOptions(raw, l4Offset + 20, l4Offset + tcpHeaderLen, tcpFields)
        }
        if (payloadLen > 0) {
            tcpFields.add(ProtocolField("TCP Segment Payload", "$payloadLen bytes", payloadOffset, (payloadOffset + payloadLen).coerceAtMost(raw.size)))
        }

        layers.add(
            ProtocolLayer(
                name = "Transmission Control Protocol, Src Port: $srcPort, Dst Port: $dstPort, Len: $payloadLen",
                byteStart = l4Offset,
                byteEnd = payloadOffset,
                fields = tcpFields
            )
        )

        var detectedProtocol = ProtocolType.TCP
        var hostOrSni: String? = null
        var appInfo: String? = null
        var dnsMappings: List<DnsMapping> = emptyList()

        if (payloadLen > 0 && payloadOffset + payloadLen <= raw.size) {
            val httpDissection = dissectHttp(raw, payloadOffset, payloadLen)
            if (httpDissection != null) {
                detectedProtocol = ProtocolType.HTTP
                hostOrSni = httpDissection.host
                appInfo = httpDissection.summary
                layers.add(httpDissection.layer)
            } else {
                val tlsDissection = dissectTls(raw, payloadOffset, payloadLen)
                if (tlsDissection != null) {
                    detectedProtocol = ProtocolType.TLS
                    hostOrSni = tlsDissection.sni
                    appInfo = tlsDissection.summary
                    layers.add(tlsDissection.layer)
                } else if ((srcPort == 53 || dstPort == 53) && payloadLen > 14) {
                    val dnsDissection = dissectDns(raw, payloadOffset + 2, payloadLen - 2)
                    if (dnsDissection != null) {
                        detectedProtocol = ProtocolType.DNS
                        hostOrSni = dnsDissection.domain
                        appInfo = dnsDissection.summary
                        dnsMappings = dnsDissection.mappings
                        layers.add(dnsDissection.layer)
                    }
                } else {
                    layers.add(buildRawPayloadLayer("TCP Payload Data ($payloadLen bytes)", raw, payloadOffset, payloadLen))
                }
            }
        }

        val tcpBaseSummary = "$srcPort → $dstPort [$flagsStr] Seq=$seq Ack=$ack Win=$window Len=$payloadLen"
        val finalInfo = if (appInfo != null) "$appInfo  ($tcpBaseSummary)" else tcpBaseSummary

        return CapturedPacket(
            id = id,
            timestampMs = timestampMs,
            relativeTimeMs = relativeTimeMs,
            direction = direction,
            ipVersion = ipVersion,
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = srcPort,
            dstPort = dstPort,
            transportProtocol = "TCP",
            protocol = detectedProtocol,
            length = raw.size,
            hostOrSni = hostOrSni,
            infoSummary = finalInfo,
            tcpFlags = flags,
            payloadOffset = payloadOffset,
            payloadLength = payloadLen,
            rawBytes = raw,
            layers = layers,
            linkLayerType = linkLayerType,
            dnsMappings = dnsMappings
        )
    }

    private fun parseTcpOptions(
        raw: ByteArray,
        start: Int,
        end: Int,
        outFields: MutableList<ProtocolField>
    ) {
        var idx = start
        while (idx < end && idx < raw.size) {
            val kind = u8(raw, idx)
            if (kind == 0) break
            if (kind == 1) {
                idx += 1
                continue
            }
            if (idx + 1 >= end || idx + 1 >= raw.size) break
            val optLen = u8(raw, idx + 1).coerceAtLeast(2)
            val optEnd = minOf(idx + optLen, end, raw.size)
            when (kind) {
                2 -> if (optEnd - idx >= 4) {
                    val mss = u16(raw, idx + 2)
                    outFields.add(ProtocolField("Option: MSS", "$mss bytes", idx, optEnd))
                }
                3 -> if (optEnd - idx >= 3) {
                    val ws = u8(raw, idx + 2)
                    outFields.add(ProtocolField("Option: Window Scale", "shift $ws (x${1 shl ws.coerceAtMost(14)})", idx, optEnd))
                }
                4 -> outFields.add(ProtocolField("Option: SACK Permitted", "True", idx, optEnd))
                8 -> if (optEnd - idx >= 10) {
                    val tsVal = u32(raw, idx + 2)
                    val tsEcr = u32(raw, idx + 6)
                    outFields.add(ProtocolField("Option: Timestamps", "TSval=$tsVal TSecr=$tsEcr", idx, optEnd))
                }
            }
            idx = optEnd
        }
    }

    private fun dissectUdp(
        id: Long,
        raw: ByteArray,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        ipVersion: Int,
        srcIp: String,
        dstIp: String,
        l4Offset: Int,
        ipEnd: Int,
        linkLayerType: LinkLayerType,
        layers: MutableList<ProtocolLayer>
    ): CapturedPacket {
        if (l4Offset + 8 > raw.size) {
            return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, raw, layers, "Malformed UDP header")
        }
        val srcPort = u16(raw, l4Offset)
        val dstPort = u16(raw, l4Offset + 2)
        val udpLen = u16(raw, l4Offset + 4)
        val checksum = u16(raw, l4Offset + 6)
        val payloadOffset = l4Offset + 8
        val payloadLen = (minOf(ipEnd, l4Offset + udpLen) - payloadOffset).coerceAtLeast(0)

        layers.add(
            ProtocolLayer(
                name = "User Datagram Protocol, Src Port: $srcPort, Dst Port: $dstPort, Len: $payloadLen",
                byteStart = l4Offset,
                byteEnd = payloadOffset,
                fields = listOf(
                    ProtocolField("Source Port", "$srcPort", l4Offset, l4Offset + 2),
                    ProtocolField("Destination Port", "$dstPort", l4Offset + 2, l4Offset + 4),
                    ProtocolField("Length", "$udpLen bytes", l4Offset + 4, l4Offset + 6),
                    ProtocolField("Checksum", "0x${checksum.toString(16).padStart(4, '0')}", l4Offset + 6, l4Offset + 8),
                    ProtocolField("UDP Payload", "$payloadLen bytes", payloadOffset, (payloadOffset + payloadLen).coerceAtMost(raw.size))
                )
            )
        )

        var detectedProtocol = ProtocolType.UDP
        var hostOrSni: String? = null
        var infoSummary = "$srcPort → $dstPort Len=$payloadLen"
        var dnsMappings: List<DnsMapping> = emptyList()

        if (payloadLen > 0 && payloadOffset + payloadLen <= raw.size) {
            when {
                srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353 || srcPort == 5355 || dstPort == 5355 -> {
                    val isMdns = srcPort == 5353 || dstPort == 5353
                    val isLlmnr = srcPort == 5355 || dstPort == 5355
                    val dnsLabel = when {
                        isMdns -> "Multicast DNS (mDNS)"
                        isLlmnr -> "Link-Local Multicast Name Resolution (LLMNR)"
                        else -> "Domain Name System"
                    }
                    val dns = dissectDns(raw, payloadOffset, payloadLen, dnsLabel)
                    if (dns != null) {
                        detectedProtocol = ProtocolType.DNS
                        hostOrSni = dns.domain
                        infoSummary = dns.summary
                        dnsMappings = dns.mappings
                        layers.add(dns.layer)
                    } else {
                        layers.add(buildRawPayloadLayer("UDP Payload Data ($payloadLen bytes)", raw, payloadOffset, payloadLen))
                    }
                }
                srcPort == 1900 || dstPort == 1900 || srcPort == 3702 || dstPort == 3702 -> {
                    val ssdp = dissectSsdpOrDiscovery(raw, payloadOffset, payloadLen, srcIp)
                    if (ssdp != null) {
                        detectedProtocol = ProtocolType.HTTP
                        hostOrSni = ssdp.deviceLabel
                        infoSummary = ssdp.summary
                        if (ssdp.deviceLabel != null && !srcIp.startsWith("239.")) {
                            dnsMappings = listOf(DnsMapping(ip = srcIp, domain = ssdp.deviceLabel))
                        }
                        layers.add(ssdp.layer)
                    } else {
                        layers.add(buildRawPayloadLayer("UDP Discovery Payload ($payloadLen bytes)", raw, payloadOffset, payloadLen))
                    }
                }
                srcPort == 137 || dstPort == 137 -> {
                    val nbns = dissectNbns(raw, payloadOffset, payloadLen)
                    if (nbns != null) {
                        detectedProtocol = ProtocolType.DNS
                        hostOrSni = nbns.first
                        infoSummary = nbns.second
                        layers.add(buildRawPayloadLayer("NetBIOS Name Service (${nbns.first ?: "$payloadLen B"})", raw, payloadOffset, payloadLen))
                    } else {
                        layers.add(buildRawPayloadLayer("NetBIOS Payload ($payloadLen bytes)", raw, payloadOffset, payloadLen))
                    }
                }
                srcPort == 443 || dstPort == 443 -> {
                    val quic = dissectQuic(raw, payloadOffset, payloadLen, srcPort, dstPort)
                    if (quic != null) {
                        detectedProtocol = ProtocolType.QUIC
                        infoSummary = quic.summary
                        layers.add(quic.layer)
                    } else {
                        layers.add(buildRawPayloadLayer("UDP Payload Data ($payloadLen bytes)", raw, payloadOffset, payloadLen))
                    }
                }
                srcPort == 123 || dstPort == 123 -> {
                    infoSummary = "NTPv${(u8(raw, payloadOffset) ushr 3) and 0x07} packet ($payloadLen bytes)"
                    layers.add(buildRawPayloadLayer("NTP Payload ($payloadLen bytes)", raw, payloadOffset, payloadLen))
                }
                else -> {
                    layers.add(buildRawPayloadLayer("UDP Payload Data ($payloadLen bytes)", raw, payloadOffset, payloadLen))
                }
            }
        }

        return CapturedPacket(
            id = id,
            timestampMs = timestampMs,
            relativeTimeMs = relativeTimeMs,
            direction = direction,
            ipVersion = ipVersion,
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = srcPort,
            dstPort = dstPort,
            transportProtocol = "UDP",
            protocol = detectedProtocol,
            length = raw.size,
            hostOrSni = hostOrSni,
            infoSummary = infoSummary,
            tcpFlags = 0,
            payloadOffset = payloadOffset,
            payloadLength = payloadLen,
            rawBytes = raw,
            layers = layers,
            linkLayerType = linkLayerType,
            dnsMappings = dnsMappings
        )
    }

    private fun dissectIcmp(
        id: Long,
        raw: ByteArray,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        ipVersion: Int,
        srcIp: String,
        dstIp: String,
        l4Offset: Int,
        ipEnd: Int,
        linkLayerType: LinkLayerType,
        layers: MutableList<ProtocolLayer>
    ): CapturedPacket {
        if (l4Offset + 4 > raw.size) {
            return fallbackPacket(id, timestampMs, relativeTimeMs, direction, linkLayerType, raw, layers, "Malformed ICMP")
        }
        val type = u8(raw, l4Offset)
        val code = u8(raw, l4Offset + 1)
        val csum = u16(raw, l4Offset + 2)
        val typeLabel = when (type) {
            8 -> "Echo (ping) request"
            0 -> "Echo (ping) reply"
            3 -> "Destination unreachable (code $code)"
            11 -> "Time-to-live exceeded"
            else -> "Type $type Code $code"
        }
        val fields = mutableListOf(
            ProtocolField("Type", "$type ($typeLabel)", l4Offset, l4Offset + 1),
            ProtocolField("Code", "$code", l4Offset + 1, l4Offset + 2),
            ProtocolField("Checksum", "0x${csum.toString(16).padStart(4, '0')}", l4Offset + 2, l4Offset + 4)
        )
        if ((type == 8 || type == 0) && l4Offset + 8 <= raw.size) {
            val ident = u16(raw, l4Offset + 4)
            val seq = u16(raw, l4Offset + 6)
            fields.add(ProtocolField("Identifier", "0x${ident.toString(16).padStart(4, '0')} ($ident)", l4Offset + 4, l4Offset + 6))
            fields.add(ProtocolField("Sequence Number", "$seq", l4Offset + 6, l4Offset + 8))
        }
        layers.add(
            ProtocolLayer(
                name = "Internet Control Message Protocol ($typeLabel)",
                byteStart = l4Offset,
                byteEnd = ipEnd.coerceAtLeast(l4Offset + 4),
                fields = fields
            )
        )

        return CapturedPacket(
            id = id,
            timestampMs = timestampMs,
            relativeTimeMs = relativeTimeMs,
            direction = direction,
            ipVersion = ipVersion,
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = 0,
            dstPort = 0,
            transportProtocol = "ICMP",
            protocol = ProtocolType.ICMP,
            length = raw.size,
            hostOrSni = null,
            infoSummary = "$typeLabel (${raw.size} bytes)",
            tcpFlags = 0,
            payloadOffset = l4Offset + 4,
            payloadLength = (ipEnd - l4Offset - 4).coerceAtLeast(0),
            rawBytes = raw,
            layers = layers,
            linkLayerType = linkLayerType
        )
    }

    private fun buildRawPayloadLayer(name: String, raw: ByteArray, offset: Int, len: Int): ProtocolLayer {
        val end = minOf(raw.size, offset + len)
        val previewBytes = minOf(len, 240)
        val ascii = buildString(previewBytes) {
            for (i in offset until offset + previewBytes) {
                val b = raw[i].toInt() and 0xFF
                append(if (b in 32..126) b.toChar() else '.')
            }
        }
        val hexPreview = (offset until minOf(end, offset + 24)).joinToString(" ") { "%02x".format(raw[it]) }
        return ProtocolLayer(
            name = name,
            byteStart = offset,
            byteEnd = end,
            fields = listOf(
                ProtocolField("Payload Length", "$len bytes", offset, end),
                ProtocolField("Hex Prefix", hexPreview, offset, minOf(end, offset + 24)),
                ProtocolField("ASCII Preview", ascii, offset, end)
            )
        )
    }

    private data class DnsDissection(
        val domain: String?,
        val summary: String,
        val layer: ProtocolLayer,
        val mappings: List<DnsMapping>
    )

    private fun dissectDns(
        raw: ByteArray,
        offset: Int,
        len: Int,
        protocolLabel: String = "Domain Name System"
    ): DnsDissection? {
        if (len < 12 || offset + 12 > raw.size) return null
        val txId = u16(raw, offset)
        val flags = u16(raw, offset + 2)
        val isResponse = (flags and 0x8000) != 0
        val rcode = flags and 0x0F
        val qdCount = u16(raw, offset + 4)
        val anCount = u16(raw, offset + 6)
        val nsCount = u16(raw, offset + 8)
        val arCount = u16(raw, offset + 10)

        val fields = mutableListOf(
            ProtocolField("Transaction ID", "0x${txId.toString(16).padStart(4, '0')}", offset, offset + 2),
            ProtocolField("Flags", "0x${flags.toString(16).padStart(4, '0')} (${if (isResponse) "Response" else "Standard Query"}, RCODE=$rcode)", offset + 2, offset + 4),
            ProtocolField("Questions / Answers", "QD=$qdCount, AN=$anCount, NS=$nsCount, AR=$arCount", offset + 4, offset + 12)
        )

        var cursor = offset + 12
        val end = minOf(raw.size, offset + len)
        var firstDomain: String? = null
        var firstQType = ""

        for (q in 0 until minOf(qdCount, 6)) {
            if (cursor >= end) break
            val nameResult = readDnsName(raw, offset, end, cursor) ?: break
            val (name, nextCursor) = nameResult
            if (nextCursor + 4 > end) break
            val qType = u16(raw, nextCursor)
            val qClass = u16(raw, nextCursor + 2) and 0x7FFF
            val qTypeName = dnsTypeName(qType)
            if (firstDomain == null && name != "<root>") {
                firstDomain = name
                firstQType = qTypeName
            }
            fields.add(
                ProtocolField(
                    label = "Query ${q + 1}",
                    value = "$name ($qTypeName, Class $qClass)",
                    byteStart = cursor,
                    byteEnd = nextCursor + 4
                )
            )
            cursor = nextCursor + 4
        }

        val answerSummaries = mutableListOf<String>()
        val extractedMappings = mutableListOf<DnsMapping>()
        val cnameTargets = mutableSetOf<String>()

        fun parseResourceRecords(sectionLabel: String, count: Int, collectSummary: Boolean) {
            for (idx in 0 until minOf(count, 10)) {
                if (cursor >= end) break
                val nameResult = readDnsName(raw, offset, end, cursor) ?: break
                val (aName, nextCursor) = nameResult
                if (nextCursor + 10 > end) break
                val rType = u16(raw, nextCursor)
                val ttl = u32(raw, nextCursor + 4)
                val rdLen = u16(raw, nextCursor + 8)
                val rDataStart = nextCursor + 10
                val rDataEnd = (rDataStart + rdLen).coerceAtMost(end)
                val rTypeName = dnsTypeName(rType)
                val rDataText = when (rType) {
                    1 -> if (rDataEnd - rDataStart == 4) ipv4String(raw, rDataStart) else "$rdLen B"
                    28 -> if (rDataEnd - rDataStart == 16) ipv6String(raw, rDataStart) else "$rdLen B"
                    5, 12, 2 -> readDnsName(raw, offset, end, rDataStart)?.first ?: "$rdLen B"
                    33 -> if (rDataStart + 6 <= rDataEnd) {
                        val srvPort = u16(raw, rDataStart + 4)
                        val target = readDnsName(raw, offset, end, rDataStart + 6)?.first ?: "?"
                        "$target:$srvPort"
                    } else "$rdLen B"
                    else -> "$rdLen bytes"
                }

                if (rType == 5 && rDataText != "<root>" && !rDataText.endsWith(" B")) {
                    cnameTargets.add(rDataText)
                } else if ((rType == 1 && rDataEnd - rDataStart == 4) || (rType == 28 && rDataEnd - rDataStart == 16)) {
                    val resolvedDomain = when {
                        aName in cnameTargets && !firstDomain.isNullOrBlank() && firstDomain != "<root>" -> firstDomain
                        aName != "<root>" && aName.isNotBlank() -> aName
                        !firstDomain.isNullOrBlank() && firstDomain != "<root>" -> firstDomain
                        else -> null
                    }
                    if (resolvedDomain != null && !resolvedDomain.endsWith(".arpa", ignoreCase = true)) {
                        extractedMappings.add(DnsMapping(ip = rDataText, domain = resolvedDomain))
                        if (firstDomain == null) firstDomain = resolvedDomain
                    }
                } else if (rType == 12 && aName.endsWith(".in-addr.arpa", ignoreCase = true) && rDataText != "<root>" && !rDataText.endsWith(" B")) {
                    parsePtrArpaToIpv4(aName)?.let { ptrIp ->
                        extractedMappings.add(DnsMapping(ip = ptrIp, domain = rDataText))
                        if (firstDomain == null) firstDomain = rDataText
                    }
                } else if (rType == 12 && rDataText != "<root>" && !rDataText.endsWith(" B")) {
                    if (firstDomain == null || firstDomain?.startsWith("_services") == true) {
                        firstDomain = rDataText
                    }
                }

                if (collectSummary) answerSummaries.add(rDataText)
                fields.add(
                    ProtocolField(
                        label = "$sectionLabel ${idx + 1}",
                        value = "$aName → $rTypeName $rDataText (TTL ${ttl}s)",
                        byteStart = cursor,
                        byteEnd = rDataEnd
                    )
                )
                cursor = rDataEnd
            }
        }

        parseResourceRecords("Answer", anCount, collectSummary = true)
        parseResourceRecords("Authority", nsCount, collectSummary = false)
        parseResourceRecords("Additional", arCount, collectSummary = false)

        val rcodeText = when (rcode) {
            0 -> ""
            3 -> " NXDOMAIN"
            2 -> " SERVFAIL"
            else -> " RCODE=$rcode"
        }

        val summary = if (!isResponse) {
            "Standard query 0x${txId.toString(16).padStart(4, '0')} $firstQType ${firstDomain ?: ""}".trim()
        } else {
            val ansText = if (answerSummaries.isNotEmpty()) " → ${answerSummaries.joinToString(", ")}" else ""
            "Standard query response 0x${txId.toString(16).padStart(4, '0')}$rcodeText $firstQType ${firstDomain ?: ""}$ansText".trim()
        }

        return DnsDissection(
            domain = firstDomain,
            summary = summary,
            layer = ProtocolLayer(
                name = "$protocolLabel (${if (isResponse) "response" else "query"})",
                byteStart = offset,
                byteEnd = end,
                fields = fields
            ),
            mappings = extractedMappings
        )
    }

    private data class SsdpDissection(
        val deviceLabel: String?,
        val summary: String,
        val layer: ProtocolLayer
    )

    private fun dissectSsdpOrDiscovery(
        raw: ByteArray,
        offset: Int,
        len: Int,
        srcIp: String
    ): SsdpDissection? {
        if (len < 8 || offset + len > raw.size) return null
        val end = minOf(raw.size, offset + len)
        val text = String(raw, offset, end - offset, StandardCharsets.UTF_8)
        val lines = text.split("\r\n", "\n").filter { it.isNotBlank() }
        if (lines.isEmpty()) return null
        val firstLine = lines.first().trim()

        if (firstLine.startsWith("<?xml", ignoreCase = true) || text.contains("Probe", ignoreCase = true) && text.contains("schemas.xmlsoap.org")) {
            return SsdpDissection(
                deviceLabel = null,
                summary = "WS-Discovery XML ($len bytes)",
                layer = buildRawPayloadLayer("WS-Discovery Payload ($len bytes)", raw, offset, len)
            )
        }
        if (!firstLine.startsWith("M-SEARCH", ignoreCase = true) &&
            !firstLine.startsWith("NOTIFY", ignoreCase = true) &&
            !firstLine.startsWith("HTTP/1.", ignoreCase = true)
        ) {
            return null
        }

        val fields = mutableListOf(ProtocolField("Request / Status", firstLine, offset, end))
        var stOrNt: String? = null
        var serverHeader: String? = null
        var locationUrl: String? = null

        for (line in lines.drop(1).take(12)) {
            val colon = line.indexOf(':')
            if (colon > 0) {
                val k = line.substring(0, colon).trim()
                val v = line.substring(colon + 1).trim()
                fields.add(ProtocolField(k, v, offset, end))
                when {
                    k.equals("ST", ignoreCase = true) || k.equals("NT", ignoreCase = true) -> {
                        if (stOrNt == null) stOrNt = v
                    }
                    k.equals("SERVER", ignoreCase = true) -> serverHeader = v
                    k.equals("LOCATION", ignoreCase = true) -> locationUrl = v
                }
            }
        }

        val friendlyLabel = serverHeader
            ?.substringBefore(' ')
            ?.substringBefore('/')
            ?.takeIf { it.length >= 2 && it != "Linux" && it != "UPnP" }
            ?: stOrNt?.substringAfterLast(':')?.takeIf { it.isNotBlank() && it != "all" }

        val summary = buildString {
            append("SSDP ")
            append(firstLine.substringBefore(" HTTP/"))
            if (!stOrNt.isNullOrBlank()) append(" ($stOrNt)")
            else if (!locationUrl.isNullOrBlank()) append(" [$locationUrl]")
            else append(" from $srcIp")
        }

        return SsdpDissection(
            deviceLabel = friendlyLabel,
            summary = summary,
            layer = ProtocolLayer(
                name = "Simple Service Discovery Protocol (SSDP)",
                byteStart = offset,
                byteEnd = end,
                fields = fields
            )
        )
    }

    private fun dissectNbns(raw: ByteArray, offset: Int, len: Int): Pair<String?, String>? {
        if (len < 50 || offset + 50 > raw.size) return null
        val flags = u16(raw, offset + 2)
        val isResponse = (flags and 0x8000) != 0
        val nameLen = u8(raw, offset + 12)
        if (nameLen != 32 || offset + 13 + 32 > raw.size) return null
        val decoded = StringBuilder(16)
        for (i in 0 until 15) {
            val c1 = u8(raw, offset + 13 + i * 2) - 'A'.code
            val c2 = u8(raw, offset + 14 + i * 2) - 'A'.code
            val ch = ((c1 shl 4) or (c2 and 0x0F)).toChar()
            if (ch in ' '..'~') decoded.append(ch)
        }
        val hostName = decoded.toString().trim().takeIf { it.isNotBlank() }
        val kind = if (isResponse) "Registration / Response" else "Name Query"
        return hostName to "NBNS $kind ${hostName ?: ""}".trim()
    }

    private fun parsePtrArpaToIpv4(qname: String): String? {
        val trimmed = qname.lowercase().removeSuffix(".in-addr.arpa")
        val octets = trimmed.split('.')
        if (octets.size != 4) return null
        if (octets.any { it.toIntOrNull()?.let { v -> v !in 0..255 } != false }) return null
        return octets.reversed().joinToString(".")
    }

    private fun readDnsName(raw: ByteArray, dnsStart: Int, dnsEnd: Int, pos: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var curr = pos
        var jumped = false
        var returnPos = pos
        var jumps = 0

        while (curr < dnsEnd && curr < raw.size && jumps < 12) {
            val len = u8(raw, curr)
            if (len == 0) {
                if (!jumped) returnPos = curr + 1
                break
            }
            if ((len and 0xC0) == 0xC0) {
                if (curr + 1 >= dnsEnd) return null
                val ptr = ((len and 0x3F) shl 8) or u8(raw, curr + 1)
                if (!jumped) returnPos = curr + 2
                jumped = true
                curr = dnsStart + ptr
                jumps++
                if (curr < dnsStart || curr >= dnsEnd) return null
                continue
            }
            val labelLen = len and 0x3F
            curr++
            if (curr + labelLen > dnsEnd || curr + labelLen > raw.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(raw, curr, labelLen, StandardCharsets.US_ASCII))
            curr += labelLen
            if (!jumped) returnPos = curr
        }
        return (if (sb.isEmpty()) "<root>" else sb.toString()) to returnPos
    }

    private fun dnsTypeName(type: Int): String = when (type) {
        1 -> "A"
        2 -> "NS"
        5 -> "CNAME"
        12 -> "PTR"
        15 -> "MX"
        16 -> "TXT"
        28 -> "AAAA"
        33 -> "SRV"
        65 -> "HTTPS"
        else -> "TYPE$type"
    }

    private data class TlsDissection(val sni: String?, val summary: String, val layer: ProtocolLayer)

    private fun dissectTls(raw: ByteArray, offset: Int, len: Int): TlsDissection? {
        if (len < 5 || offset + 5 > raw.size) return null
        val contentType = u8(raw, offset)
        if (contentType !in 20..23) return null
        val verMajor = u8(raw, offset + 1)
        val verMinor = u8(raw, offset + 2)
        if (verMajor != 3 || verMinor !in 0..4) return null

        val recordLen = u16(raw, offset + 3)
        val recordTypeName = when (contentType) {
            20 -> "Change Cipher Spec"
            21 -> "Alert"
            22 -> "Handshake"
            23 -> "Application Data"
            else -> "Record"
        }
        var tlsVersionLabel = when (verMinor) {
            0 -> "SSL 3.0"
            1 -> "TLSv1.0"
            2 -> "TLSv1.1"
            3 -> "TLSv1.2"
            4 -> "TLSv1.3"
            else -> "TLS"
        }

        val fields = mutableListOf(
            ProtocolField("Content Type", "$recordTypeName ($contentType)", offset, offset + 1),
            ProtocolField("Legacy Record Version", "$tlsVersionLabel (0x030$verMinor)", offset + 1, offset + 3),
            ProtocolField("Record Length", "$recordLen bytes", offset + 3, offset + 5)
        )

        var sni: String? = null
        var handshakeName: String? = null
        val end = minOf(raw.size, offset + len)

        if (contentType == 22 && offset + 9 <= end) {
            val hsType = u8(raw, offset + 5)
            val hsLen = (u8(raw, offset + 6) shl 16) or u16(raw, offset + 7)
            handshakeName = when (hsType) {
                1 -> "Client Hello"
                2 -> "Server Hello"
                11 -> "Certificate"
                12 -> "Server Key Exchange"
                14 -> "Server Hello Done"
                16 -> "Client Key Exchange"
                20 -> "Finished"
                else -> "Handshake($hsType)"
            }
            fields.add(ProtocolField("Handshake Type", "$handshakeName ($hsType), Len=$hsLen", offset + 5, offset + 9))

            if (hsType == 1 && offset + 43 < end) {
                var cursor = offset + 9 + 2 + 32
                if (cursor < end) {
                    val sessionIdLen = u8(raw, cursor)
                    cursor += 1 + sessionIdLen
                }
                if (cursor + 2 <= end) {
                    val cipherSuitesLen = u16(raw, cursor)
                    fields.add(ProtocolField("Cipher Suites", "${cipherSuitesLen / 2} suites offered", cursor, minOf(cursor + 2 + cipherSuitesLen, end)))
                    cursor += 2 + cipherSuitesLen
                }
                if (cursor + 1 <= end) {
                    val compLen = u8(raw, cursor)
                    cursor += 1 + compLen
                }
                if (cursor + 2 <= end) {
                    val extTotalLen = u16(raw, cursor)
                    cursor += 2
                    val extEnd = minOf(cursor + extTotalLen, end)
                    while (cursor + 4 <= extEnd) {
                        val extType = u16(raw, cursor)
                        val extLen = u16(raw, cursor + 2)
                        val extDataStart = cursor + 4
                        val extDataEnd = minOf(extDataStart + extLen, extEnd)
                        if (extType == 0x0000 && extDataStart + 5 <= extDataEnd) {
                            val nameType = u8(raw, extDataStart + 2)
                            val nameLen = u16(raw, extDataStart + 3)
                            if (nameType == 0 && extDataStart + 5 + nameLen <= extDataEnd) {
                                sni = String(raw, extDataStart + 5, nameLen, StandardCharsets.UTF_8)
                                fields.add(ProtocolField("Server Name Indication (SNI)", sni, extDataStart + 5, extDataStart + 5 + nameLen))
                            }
                        } else if (extType == 0x0010 && extDataStart + 3 <= extDataEnd) {
                            val alpnListLen = u16(raw, extDataStart)
                            val alpnNames = mutableListOf<String>()
                            var p = extDataStart + 2
                            val pEnd = minOf(extDataStart + 2 + alpnListLen, extDataEnd)
                            while (p < pEnd) {
                                val l = u8(raw, p++)
                                if (p + l <= pEnd) {
                                    alpnNames.add(String(raw, p, l, StandardCharsets.US_ASCII))
                                }
                                p += l
                            }
                            if (alpnNames.isNotEmpty()) {
                                fields.add(ProtocolField("ALPN Protocols", alpnNames.joinToString(", "), extDataStart, extDataEnd))
                            }
                        } else if (extType == 0x002B && extDataStart + 3 <= extDataEnd) {
                            val listLen = u8(raw, extDataStart)
                            var p = extDataStart + 1
                            while (p + 1 < minOf(extDataStart + 1 + listLen, extDataEnd)) {
                                if (u16(raw, p) == 0x0304) {
                                    tlsVersionLabel = "TLSv1.3"
                                    break
                                }
                                p += 2
                            }
                        }
                        cursor = extDataEnd
                    }
                }
            }
        }

        val summary = buildString {
            append(tlsVersionLabel)
            append(" ")
            append(handshakeName ?: recordTypeName)
            if (sni != null) append(" (SNI: $sni)")
        }

        return TlsDissection(
            sni = sni,
            summary = summary,
            layer = ProtocolLayer(
                name = "Transport Layer Security ($tlsVersionLabel)",
                byteStart = offset,
                byteEnd = end,
                fields = fields
            )
        )
    }

    private data class HttpDissection(val host: String?, val summary: String, val layer: ProtocolLayer)

    private val httpMethods = listOf("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1.")

    private fun dissectHttp(raw: ByteArray, offset: Int, len: Int): HttpDissection? {
        if (len < 10 || offset + len > raw.size) return null
        val previewLen = minOf(len, 16)
        val prefix = String(raw, offset, previewLen, StandardCharsets.US_ASCII)
        if (httpMethods.none { prefix.startsWith(it) }) return null

        val maxInspect = minOf(len, 4096)
        val text = String(raw, offset, maxInspect, StandardCharsets.UTF_8)
        val headerSplit = text.indexOf("\r\n\r\n")
        val headerBlock = if (headerSplit >= 0) text.substring(0, headerSplit) else text
        val lines = headerBlock.split("\r\n").filter { it.isNotBlank() }
        if (lines.isEmpty()) return null

        val firstLine = lines.first()
        var host: String? = null
        val end = minOf(raw.size, offset + len)
        val fields = mutableListOf(
            ProtocolField("Start Line", firstLine, offset, minOf(offset + firstLine.length, end))
        )

        var byteCursor = offset + firstLine.length + 2
        for (i in 1 until minOf(lines.size, 24)) {
            val line = lines[i]
            val colonIdx = line.indexOf(':')
            if (colonIdx > 0) {
                val key = line.substring(0, colonIdx).trim()
                val value = line.substring(colonIdx + 1).trim()
                if (key.equals("Host", ignoreCase = true)) {
                    host = value
                }
                val fStart = byteCursor.coerceAtMost(end)
                val fEnd = (byteCursor + line.length).coerceAtMost(end)
                fields.add(ProtocolField("Header: $key", value, fStart, fEnd))
            }
            byteCursor += line.length + 2
        }

        if (headerSplit >= 0 && headerSplit + 4 < text.length) {
            val bodyPreview = text.substring(headerSplit + 4).take(320).replace("\r", " ").replace("\n", " ")
            if (bodyPreview.isNotBlank()) {
                val bodyStart = (offset + headerSplit + 4).coerceAtMost(end)
                fields.add(ProtocolField("Payload Body (${end - bodyStart} B)", bodyPreview, bodyStart, end))
            }
        }

        val summary = if (host != null) "$firstLine ($host)" else firstLine
        return HttpDissection(
            host = host,
            summary = summary,
            layer = ProtocolLayer(
                name = "Hypertext Transfer Protocol (HTTP)",
                byteStart = offset,
                byteEnd = end,
                fields = fields
            )
        )
    }

    private data class QuicDissection(val summary: String, val layer: ProtocolLayer)

    private fun dissectQuic(raw: ByteArray, offset: Int, len: Int, srcPort: Int, dstPort: Int): QuicDissection? {
        if (len < 5 || offset + len > raw.size) return null
        val b0 = u8(raw, offset)
        val isLong = (b0 and 0x80) != 0
        val end = minOf(raw.size, offset + len)
        return if (isLong) {
            val version = u32(raw, offset + 1)
            val pktTypeCode = (b0 ushr 4) and 0x03
            val pktType = when (pktTypeCode) {
                0 -> "Initial"
                1 -> "0-RTT"
                2 -> "Handshake"
                3 -> "Retry"
                else -> "Long"
            }
            val verLabel = when (version) {
                1L -> "QUICv1"
                0x6b3343cfL -> "QUICv2"
                0L -> "Version Negotiation"
                else -> "0x${version.toString(16)}"
            }
            QuicDissection(
                summary = "QUIC $pktType ($verLabel) $srcPort → $dstPort Len=$len",
                layer = ProtocolLayer(
                    name = "QUIC IETF ($verLabel $pktType)",
                    byteStart = offset,
                    byteEnd = end,
                    fields = listOf(
                        ProtocolField("Header Form", "Long Header (1)", offset, offset + 1),
                        ProtocolField("Packet Type", pktType, offset, offset + 1),
                        ProtocolField("Version", "$verLabel (0x${version.toString(16)})", offset + 1, minOf(offset + 5, end))
                    )
                )
            )
        } else {
            QuicDissection(
                summary = "QUIC Protected Payload (1-RTT) $srcPort → $dstPort Len=$len",
                layer = ProtocolLayer(
                    name = "QUIC IETF (Short Header 1-RTT)",
                    byteStart = offset,
                    byteEnd = end,
                    fields = listOf(
                        ProtocolField("Header Form", "Short Header (0)", offset, offset + 1),
                        ProtocolField("Payload Length", "$len bytes", offset, end)
                    )
                )
            )
        }
    }

    private fun fallbackPacket(
        id: Long,
        timestampMs: Long,
        relativeTimeMs: Long,
        direction: PacketDirection,
        linkLayerType: LinkLayerType,
        raw: ByteArray,
        layers: MutableList<ProtocolLayer>,
        reason: String
    ): CapturedPacket {
        return CapturedPacket(
            id = id,
            timestampMs = timestampMs,
            relativeTimeMs = relativeTimeMs,
            direction = direction,
            ipVersion = 0,
            srcIp = "—",
            dstIp = "—",
            srcPort = 0,
            dstPort = 0,
            transportProtocol = "RAW",
            protocol = ProtocolType.OTHER,
            length = raw.size,
            hostOrSni = null,
            infoSummary = reason,
            tcpFlags = 0,
            payloadOffset = 0,
            payloadLength = raw.size,
            rawBytes = raw,
            layers = layers,
            linkLayerType = linkLayerType
        )
    }

    private fun u8(buf: ByteArray, offset: Int): Int = buf[offset].toInt() and 0xFF
    private fun u16(buf: ByteArray, offset: Int): Int = ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
    private fun u32(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong() and 0xFF) shl 24) or
            ((buf[offset + 1].toLong() and 0xFF) shl 16) or
            ((buf[offset + 2].toLong() and 0xFF) shl 8) or
            (buf[offset + 3].toLong() and 0xFF)

    private fun macString(buf: ByteArray, offset: Int): String =
        (0 until 6).joinToString(":") { "%02x".format(u8(buf, offset + it)) }

    private fun ipv4String(buf: ByteArray, offset: Int): String =
        "${u8(buf, offset)}.${u8(buf, offset + 1)}.${u8(buf, offset + 2)}.${u8(buf, offset + 3)}"

    private fun ipv6String(buf: ByteArray, offset: Int): String {
        val groups = (0 until 8).map { i -> u16(buf, offset + i * 2).toString(16) }
        return groups.joinToString(":")
    }
}
