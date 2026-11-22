package com.example.dissector

import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.PacketDirection
import com.example.model.ProtocolType
import com.example.model.QuickFilter
import com.example.model.ResolvedHost
import java.nio.charset.StandardCharsets

data class ParsedDisplayFilter(
    val isValid: Boolean,
    val errorHint: String? = null,
    val matches: (CapturedPacket) -> Boolean
)

/**
 * Evaluates display filter expressions and deep payload keyword searches:
 * Examples:
 * - "dns", "tls", "http", "tcp", "udp", "quic", "icmp", "out", "in"
 * - "ip.addr == 8.8.8.8", "ip.src == 10.1.10.1", "ip.dst == 1.1.1.1"
 * - "port == 443", "tcp.port == 80", "udp.port == 53"
 * - "http.host contains example", "dns.qry.name contains google", "tls.sni contains github"
 * - "payload contains GET", "frame contains secret", or any plain keyword search across headers & payload
 * - Logical operators: "&&", "||", "!"
 */
object DisplayFilterParser {

    /**
     * Guards against pathological input: the parser recurses per leading '!' and per nested
     * '(' (and re-scans per level in splitTopLevel), and it runs on the main thread from a
     * flow combine. Without a cap, a pasted multi-KB string of "!!!!" or "(((((..." produces
     * a StackOverflowError — an Error, which the IllegalArgumentException catch below cannot
     * handle — and crashes the app. 512 chars bounds recursion to a few hundred frames.
     */
    private const val MAX_FILTER_LENGTH = 512

    fun parse(
        query: String,
        quickFilter: QuickFilter,
        resolvedDomains: Map<String, ResolvedHost> = emptyMap()
    ): ParsedDisplayFilter {
        val trimmed = query.trim()
        val quickPred: (CapturedPacket) -> Boolean = when (quickFilter) {
            QuickFilter.ALL -> { _ -> true }
            QuickFilter.TCP -> { p -> p.protocol == ProtocolType.TCP || p.transportProtocol == "TCP" }
            QuickFilter.TLS -> { p -> p.protocol == ProtocolType.TLS }
            QuickFilter.DNS -> { p -> p.protocol == ProtocolType.DNS }
            QuickFilter.HTTP -> { p -> p.protocol == ProtocolType.HTTP }
            QuickFilter.UDP -> { p -> p.protocol == ProtocolType.UDP || p.transportProtocol == "UDP" }
            QuickFilter.ICMP -> { p -> p.protocol == ProtocolType.ICMP }
        }

        if (trimmed.isEmpty()) {
            return ParsedDisplayFilter(isValid = true, matches = quickPred)
        }

        if (trimmed.length > MAX_FILTER_LENGTH) {
            return ParsedDisplayFilter(
                isValid = false,
                errorHint = "Filter too long (maximum $MAX_FILTER_LENGTH characters)",
                matches = { _ -> false }
            )
        }

        return try {
            val exprPred = parseOrExpression(trimmed, resolvedDomains)
            ParsedDisplayFilter(
                isValid = true,
                matches = { pkt -> quickPred(pkt) && exprPred(pkt) }
            )
        } catch (e: IllegalArgumentException) {
            val lower = trimmed.lowercase()
            ParsedDisplayFilter(
                isValid = false,
                errorHint = e.message ?: "Invalid filter syntax",
                matches = { pkt ->
                    quickPred(pkt) && matchesKeywordEverywhere(pkt, lower, resolvedDomains)
                }
            )
        }
    }

    private fun parseOrExpression(
        expr: String,
        resolvedDomains: Map<String, ResolvedHost>
    ): (CapturedPacket) -> Boolean {
        val parts = splitTopLevel(expr, "||")
        if (parts.any { it.isBlank() }) throw IllegalArgumentException("Empty operand around '||'")
        val predicates = parts.map { parseAndExpression(it.trim(), resolvedDomains) }
        return { pkt -> predicates.any { it(pkt) } }
    }

    private fun parseAndExpression(
        expr: String,
        resolvedDomains: Map<String, ResolvedHost>
    ): (CapturedPacket) -> Boolean {
        val parts = splitTopLevel(expr, "&&")
        if (parts.any { it.isBlank() }) throw IllegalArgumentException("Empty operand around '&&'")
        val predicates = parts.map { parseUnary(it.trim(), resolvedDomains) }
        return { pkt -> predicates.all { it(pkt) } }
    }

    private fun parseUnary(
        expr: String,
        resolvedDomains: Map<String, ResolvedHost>
    ): (CapturedPacket) -> Boolean {
        if (expr.startsWith("!")) {
            val inner = expr.substring(1).trim()
            if (inner.isEmpty()) throw IllegalArgumentException("Missing expression after '!'")
            val pred = parseUnary(inner, resolvedDomains)
            return { pkt -> !pred(pkt) }
        }
        if (expr.startsWith("(") && expr.endsWith(")")) {
            return parseOrExpression(expr.substring(1, expr.length - 1).trim(), resolvedDomains)
        }
        return parseAtom(expr, resolvedDomains)
    }

    private fun parseAtom(
        atom: String,
        resolvedDomains: Map<String, ResolvedHost>
    ): (CapturedPacket) -> Boolean {
        val lower = atom.lowercase()
        when (lower) {
            "tcp" -> return { it.protocol == ProtocolType.TCP || it.transportProtocol == "TCP" }
            "udp" -> return { it.protocol == ProtocolType.UDP || it.transportProtocol == "UDP" }
            "tls", "ssl" -> return { it.protocol == ProtocolType.TLS }
            "dns" -> return { it.protocol == ProtocolType.DNS }
            "http" -> return { it.protocol == ProtocolType.HTTP }
            "quic" -> return { it.protocol == ProtocolType.QUIC }
            "icmp" -> return { it.protocol == ProtocolType.ICMP }
            "arp" -> return { it.transportProtocol == "ARP" }
            "mdns" -> return { it.transportProtocol == "UDP" && (it.srcPort == 5353 || it.dstPort == 5353) }
            "ssdp" -> return { it.transportProtocol == "UDP" && (it.srcPort == 1900 || it.dstPort == 1900) }
            "out", "outbound" -> return { it.direction == PacketDirection.OUTBOUND }
            "in", "inbound" -> return { it.direction == PacketDirection.INBOUND }
            "lan", "promisc", "promiscuous" -> return { it.captureSource == CaptureSource.LAN_PROMISCUOUS }
            "phone", "device", "vpn", "tun0" -> return { it.captureSource == CaptureSource.DEVICE_VPN }
            "tcp.flags.syn" -> return { (it.tcpFlags and PacketDissector.TCP_FLAG_SYN) != 0 }
            "tcp.flags.rst" -> return { (it.tcpFlags and PacketDissector.TCP_FLAG_RST) != 0 }
            "tcp.flags.fin" -> return { (it.tcpFlags and PacketDissector.TCP_FLAG_FIN) != 0 }
        }

        val containsRegex = Regex("""^([a-z0-9_.]+)\s+contains\s+(.+)$""", RegexOption.IGNORE_CASE)
        containsRegex.matchEntire(atom)?.let { match ->
            val field = match.groupValues[1].lowercase()
            val value = match.groupValues[2].trim().trim('"', '\'').lowercase()
            if (value.isEmpty()) throw IllegalArgumentException("Missing value after 'contains'")
            return when (field) {
                "http.host", "tls.sni", "dns.qry.name", "dns.resolved", "dns.ptr", "host" -> { pkt ->
                    val srcResolved = resolvedDomains[pkt.srcIp]?.domain?.lowercase()
                    val dstResolved = resolvedDomains[pkt.dstIp]?.domain?.lowercase()
                    (pkt.hostOrSni?.lowercase()?.contains(value) == true) ||
                        pkt.infoSummary.lowercase().contains(value) ||
                        (srcResolved?.contains(value) == true) ||
                        (dstResolved?.contains(value) == true)
                }
                "payload", "data", "tcp.payload", "udp.payload", "http.file_data" -> { pkt ->
                    payloadContains(pkt, value)
                }
                "frame" -> { pkt -> matchesKeywordEverywhere(pkt, value, resolvedDomains) }
                "info", "frame.info" -> { pkt -> pkt.infoSummary.lowercase().contains(value) }
                "ip.addr" -> { pkt -> pkt.srcIp.contains(value) || pkt.dstIp.contains(value) }
                else -> throw IllegalArgumentException("Unknown field '$field'")
            }
        }

        val eqRegex = Regex("""^([a-z0-9_.]+)\s*(==|!=)\s*(.+)$""", RegexOption.IGNORE_CASE)
        eqRegex.matchEntire(atom)?.let { match ->
            val field = match.groupValues[1].lowercase()
            val op = match.groupValues[2]
            val value = match.groupValues[3].trim().trim('"', '\'')
            if (value.isEmpty()) throw IllegalArgumentException("Missing value after '$op'")
            val base: (CapturedPacket) -> Boolean = when (field) {
                "ip.addr" -> { pkt -> pkt.srcIp == value || pkt.dstIp == value }
                "ip.src" -> { pkt -> pkt.srcIp == value }
                "ip.dst" -> { pkt -> pkt.dstIp == value }
                "port" -> {
                    val port = value.toIntOrNull() ?: throw IllegalArgumentException("Port must be an integer")
                    val pred: (CapturedPacket) -> Boolean = { pkt -> pkt.srcPort == port || pkt.dstPort == port }
                    pred
                }
                "tcp.port" -> {
                    val port = value.toIntOrNull() ?: throw IllegalArgumentException("Port must be an integer")
                    val pred: (CapturedPacket) -> Boolean = { pkt -> pkt.transportProtocol == "TCP" && (pkt.srcPort == port || pkt.dstPort == port) }
                    pred
                }
                "udp.port" -> {
                    val port = value.toIntOrNull() ?: throw IllegalArgumentException("Port must be an integer")
                    val pred: (CapturedPacket) -> Boolean = { pkt -> pkt.transportProtocol == "UDP" && (pkt.srcPort == port || pkt.dstPort == port) }
                    pred
                }
                "tcp.srcport", "udp.srcport", "srcport" -> {
                    val port = value.toIntOrNull() ?: throw IllegalArgumentException("Port must be an integer")
                    val pred: (CapturedPacket) -> Boolean = { pkt -> pkt.srcPort == port }
                    pred
                }
                "tcp.dstport", "udp.dstport", "dstport" -> {
                    val port = value.toIntOrNull() ?: throw IllegalArgumentException("Port must be an integer")
                    val pred: (CapturedPacket) -> Boolean = { pkt -> pkt.dstPort == port }
                    pred
                }
                "frame.len" -> {
                    val len = value.toIntOrNull() ?: throw IllegalArgumentException("Length must be an integer")
                    val pred: (CapturedPacket) -> Boolean = { pkt -> pkt.length == len }
                    pred
                }
                "source", "capture.source" -> {
                    val lowerVal = value.lowercase()
                    val pred: (CapturedPacket) -> Boolean = when (lowerVal) {
                        "lan", "promisc", "promiscuous", "multicast", "wlan0" -> {
                            { pkt -> pkt.captureSource == CaptureSource.LAN_PROMISCUOUS }
                        }
                        "phone", "device", "vpn", "tun0" -> {
                            { pkt -> pkt.captureSource == CaptureSource.DEVICE_VPN }
                        }
                        else -> throw IllegalArgumentException("Source must be 'phone' or 'lan'")
                    }
                    pred
                }
                else -> throw IllegalArgumentException("Unknown filter field '$field'")
            }
            return if (op == "!=") { pkt -> !base(pkt) } else base
        }

        if (atom.contains("=") || atom.contains("<") || atom.contains(">")) {
            throw IllegalArgumentException("Expected 'field == value' or 'field contains value'")
        }

        // Plain keyword search across IP, resolved domain, port, host/SNI, protocol, dissected fields, info summary, and raw payload
        return { pkt -> matchesKeywordEverywhere(pkt, lower, resolvedDomains) }
    }

    private fun matchesKeywordEverywhere(
        pkt: CapturedPacket,
        lowerKeyword: String,
        resolvedDomains: Map<String, ResolvedHost>
    ): Boolean {
        val srcResolved = resolvedDomains[pkt.srcIp]?.domain?.lowercase()
        val dstResolved = resolvedDomains[pkt.dstIp]?.domain?.lowercase()
        if (pkt.infoSummary.lowercase().contains(lowerKeyword) ||
            pkt.srcIp.contains(lowerKeyword) ||
            pkt.dstIp.contains(lowerKeyword) ||
            (srcResolved?.contains(lowerKeyword) == true) ||
            (dstResolved?.contains(lowerKeyword) == true) ||
            pkt.srcPort.toString() == lowerKeyword ||
            pkt.dstPort.toString() == lowerKeyword ||
            pkt.protocol.label.lowercase().contains(lowerKeyword) ||
            (pkt.hostOrSni?.lowercase()?.contains(lowerKeyword) == true)
        ) {
            return true
        }
        // Search dissected layer fields
        for (layer in pkt.layers) {
            if (layer.name.lowercase().contains(lowerKeyword)) return true
            for (field in layer.fields) {
                if (field.label.lowercase().contains(lowerKeyword) ||
                    field.value.lowercase().contains(lowerKeyword)
                ) {
                    return true
                }
            }
        }
        return payloadContains(pkt, lowerKeyword)
    }

    private fun payloadContains(pkt: CapturedPacket, lowerKeyword: String): Boolean {
        if (pkt.payloadLength <= 0 || pkt.payloadOffset >= pkt.rawBytes.size) return false
        val len = minOf(pkt.payloadLength, pkt.rawBytes.size - pkt.payloadOffset)
        val ascii = String(pkt.rawBytes, pkt.payloadOffset, len, StandardCharsets.ISO_8859_1)
        return ascii.lowercase().contains(lowerKeyword)
    }

    private fun splitTopLevel(input: String, delimiter: String): List<String> {
        val result = mutableListOf<String>()
        var depth = 0
        var lastIdx = 0
        var i = 0
        while (i <= input.length - delimiter.length) {
            val ch = input[i]
            if (ch == '(') depth++
            else if (ch == ')') depth = (depth - 1).coerceAtLeast(0)
            if (depth == 0 && input.regionMatches(i, delimiter, 0, delimiter.length)) {
                result.add(input.substring(lastIdx, i))
                i += delimiter.length
                lastIdx = i
                continue
            }
            i++
        }
        result.add(input.substring(lastIdx))
        return result
    }
}
