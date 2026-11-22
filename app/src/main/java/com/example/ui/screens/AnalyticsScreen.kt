package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.util.Locale
import com.example.model.ConversationStream
import com.example.model.ProtocolStat
import com.example.model.ResolvedHost
import com.example.model.ThroughputPoint
import com.example.ui.components.CaptureSourceBadge
import com.example.ui.components.ProtocolBadge
import com.example.ui.components.formatByteCount
import com.example.ui.theme.LocalProtocolColors
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive
import com.example.viewmodel.CaptureUiState

@Composable
fun AnalyticsScreen(
    uiState: CaptureUiState,
    protocolStats: List<ProtocolStat>,
    conversations: List<ConversationStream>,
    topHosts: List<Pair<String, Int>>,
    onSelectConnection: (ConversationStream) -> Unit,
    onFilterHost: (String) -> Unit,
    onFilterIp: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = modifier
            .fillMaxSize()
            .testTag("analytics_screen")
    ) {
        item {
            ThroughputChartCard(
                points = uiState.throughputHistory,
                isCapturing = uiState.isCapturing,
                phonePackets = uiState.phonePacketCount,
                lanPackets = uiState.lanBufferedPacketCount,
                totalBytes = uiState.totalBytes
            )
        }

        item {
            ProtocolDistributionCard(protocolStats = protocolStats)
        }

        item {
            ActiveConnectionsCard(
                conversations = conversations.take(6),
                resolvedDomains = uiState.resolvedDomains,
                resolveHostnames = uiState.resolveHostnames,
                onSelectConnection = onSelectConnection
            )
        }

        item {
            TopResolvedHostsCard(
                topHosts = topHosts,
                onFilterHost = onFilterHost
            )
        }

        item {
            DnsResolutionCacheCard(
                resolvedDomains = uiState.resolvedDomains,
                onFilterIp = onFilterIp
            )
        }
    }
}

@Composable
private fun ThroughputChartCard(
    points: List<ThroughputPoint>,
    isCapturing: Boolean,
    phonePackets: Int,
    lanPackets: Int,
    totalBytes: Long
) {
    val protoColors = LocalProtocolColors.current
    val gridColor = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f)
    val latest = points.lastOrNull()
    val peakBps = points.maxOfOrNull { maxOf(it.bytesOut, it.bytesIn) }?.coerceAtLeast(1024L) ?: 1024L

    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Speed,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Column {
                        Text(
                            text = "Real-Time Throughput (30s)",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "$phonePackets Phone • $lanPackets LAN • ${formatByteCount(totalBytes)}",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Text(
                    text = if (isCapturing) "${latest?.packetsPerSec ?: 0} pkt/s" else "Standby",
                    style = MaterialTheme.typography.labelMedium.copy(
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    ),
                    color = if (isCapturing) WarmGoldLive else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Dual Outbound / Inbound Canvas Chart
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(160.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(protoColors.hexBg)
                    .padding(10.dp)
            ) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    // Horizontal reference grid lines
                    for (i in 1..3) {
                        val y = size.height * (i / 4f)
                        drawLine(
                            color = gridColor,
                            start = Offset(0f, y),
                            end = Offset(size.width, y),
                            strokeWidth = 1f
                        )
                    }

                    if (points.size >= 2) {
                        val stepX = size.width / (points.size - 1).coerceAtLeast(1)
                        val maxVal = peakBps.toFloat()

                        fun drawSeries(color: Color, selector: (ThroughputPoint) -> Long) {
                            val linePath = Path()
                            val fillPath = Path()
                            points.forEachIndexed { idx, pt ->
                                val x = idx * stepX
                                val ratio = (selector(pt) / maxVal).coerceIn(0f, 1f)
                                val y = size.height - (ratio * (size.height * 0.88f)) - 4f
                                if (idx == 0) {
                                    linePath.moveTo(x, y)
                                    fillPath.moveTo(x, size.height)
                                    fillPath.lineTo(x, y)
                                } else {
                                    linePath.lineTo(x, y)
                                    fillPath.lineTo(x, y)
                                }
                            }
                            fillPath.lineTo(size.width, size.height)
                            fillPath.close()

                            drawPath(
                                path = fillPath,
                                brush = Brush.verticalGradient(
                                    colors = listOf(color.copy(alpha = 0.28f), Color.Transparent)
                                )
                            )
                            drawPath(
                                path = linePath,
                                color = color,
                                style = Stroke(width = 3.5f, cap = StrokeCap.Round)
                            )
                        }

                        drawSeries(protoColors.outbound) { it.bytesOut }
                        drawSeries(protoColors.inbound) { it.bytesIn }
                    }
                }

                Text(
                    text = "Peak: ${formatByteCount(peakBps)}/s",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.align(Alignment.TopEnd)
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                LegendDot(
                    color = protoColors.outbound,
                    label = "Outbound: ${formatByteCount(latest?.bytesOut ?: 0L)}/s"
                )
                LegendDot(
                    color = protoColors.inbound,
                    label = "Inbound: ${formatByteCount(latest?.bytesIn ?: 0L)}/s"
                )
            }
        }
    }
}

@Composable
private fun LegendDot(color: Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color)
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ProtocolDistributionCard(protocolStats: List<ProtocolStat>) {
    val protoColors = LocalProtocolColors.current

    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                text = "Packet Type Distribution",
                style = MaterialTheme.typography.titleMedium
            )

            if (protocolStats.isEmpty()) {
                Text(
                    text = "No packets analyzed yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                // Stacked horizontal distribution bar
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(14.dp)
                        .clip(RoundedCornerShape(50))
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    protocolStats.forEach { stat ->
                        val weight = stat.fraction.coerceAtLeast(0.02f)
                        Box(
                            modifier = Modifier
                                .weight(weight)
                                .fillMaxHeight()
                                .background(protoColors.colorFor(stat.protocol))
                        )
                    }
                }

                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    protocolStats.forEach { stat ->
                        val pct = (stat.fraction * 100f)
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ProtocolBadge(protocol = stat.protocol)
                                Text(
                                    text = "${stat.packetCount} pkts",
                                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily)
                                )
                            }
                            Text(
                                text = "${formatByteCount(stat.totalBytes)} (${String.format(Locale.US, "%.1f%%", pct)})",
                                style = MaterialTheme.typography.labelMedium.copy(fontFamily = MonoFontFamily),
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ActiveConnectionsCard(
    conversations: List<ConversationStream>,
    resolvedDomains: Map<String, ResolvedHost>,
    resolveHostnames: Boolean,
    onSelectConnection: (ConversationStream) -> Unit
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Active Network Connections",
                style = MaterialTheme.typography.titleMedium
            )
            if (conversations.isEmpty()) {
                Text(
                    text = "Connections appear here dynamically as packets flow through tun0.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                conversations.forEach { conn ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(MaterialTheme.colorScheme.surfaceContainerLow)
                            .clickable { onSelectConnection(conn) }
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            ProtocolBadge(protocol = conn.protocol)
                            CaptureSourceBadge(captureSource = conn.captureSource)
                            Column(modifier = Modifier.weight(1f)) {
                                val resolvedName = conn.hostLabel
                                    ?: if (resolveHostnames) resolvedDomains[conn.remoteIp]?.domain else null
                                Text(
                                    text = resolvedName ?: conn.remoteEndpoint,
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.SemiBold
                                    ),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${conn.localEndpoint} → ${conn.remoteEndpoint}",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "${conn.packetCount}p • ${formatByteCount(conn.totalBytes)}",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TopResolvedHostsCard(
    topHosts: List<Pair<String, Int>>,
    onFilterHost: (String) -> Unit
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Rounded.Public,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.secondary
                )
                Text(
                    text = "Top Observed Hosts (DNS / SNI / HTTP)",
                    style = MaterialTheme.typography.titleMedium
                )
            }
            if (topHosts.isEmpty()) {
                Text(
                    text = "No DNS queries, TLS SNI hostnames, or HTTP Host headers observed yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                topHosts.forEach { (host, count) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.surfaceContainerLow)
                            .clickable { onFilterHost(host) }
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = host,
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = "$count frames",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DnsResolutionCacheCard(
    resolvedDomains: Map<String, ResolvedHost>,
    onFilterIp: (String) -> Unit
) {
    val entries = resolvedDomains.values.sortedByDescending { it.updatedAtMs }.take(12)
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("dns_resolution_cache_card")
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Dns,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "DNS IP → Domain Map",
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                Text(
                    text = "${resolvedDomains.size} mapped",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                    color = MaterialTheme.colorScheme.primary
                )
            }

            if (entries.isEmpty()) {
                Text(
                    text = "IP-to-domain mappings populate passively from captured DNS A/AAAA/PTR answers, mDNS/SSDP broadcasts, TLS SNI, and HTTP Host headers.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                entries.forEach { entry ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.surfaceContainerLow)
                            .clickable { onFilterIp(entry.ip) }
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = entry.domain,
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.SemiBold
                                ),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = entry.ip,
                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f)
                        ) {
                            Text(
                                text = entry.source.shortLabel,
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
