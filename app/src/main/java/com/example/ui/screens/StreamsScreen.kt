package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.FilterAlt
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.SwapHoriz
import androidx.compose.material.icons.rounded.WifiTethering
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.ConversationStream
import com.example.model.PacketDirection
import com.example.model.ResolvedHost
import com.example.model.TrafficScopeFilter
import com.example.ui.components.CaptureSourceBadge
import com.example.ui.components.ProtocolBadge
import com.example.ui.components.formatByteCount
import com.example.ui.theme.LocalProtocolColors
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive
import java.nio.charset.StandardCharsets

@Composable
fun StreamsScreen(
    streams: List<ConversationStream>,
    resolvedDomains: Map<String, ResolvedHost> = emptyMap(),
    resolveHostnames: Boolean = true,
    onSelectStream: (ConversationStream) -> Unit,
    onFilterToStream: (ConversationStream) -> Unit,
    modifier: Modifier = Modifier
) {
    if (streams.isEmpty()) {
        Box(
            modifier = modifier
                .fillMaxSize()
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Icon(
                    imageVector = Icons.Rounded.SwapHoriz,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(48.dp)
                )
                Text(
                    text = "No Active Network Streams",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = "Captured TCP and UDP 5-tuple connections will group here automatically with per-direction byte counters and reassembled payload views.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        return
    }

    var scopeFilter by remember { mutableStateOf(TrafficScopeFilter.ALL) }
    val lanStreamsCount = streams.count { it.captureSource == CaptureSource.LAN_PROMISCUOUS }
    val phoneStreamsCount = streams.size - lanStreamsCount
    val visibleStreams = remember(streams, scopeFilter) {
        when (scopeFilter) {
            TrafficScopeFilter.ALL -> streams
            TrafficScopeFilter.PHONE_ONLY -> streams.filter { it.captureSource == CaptureSource.DEVICE_VPN }
            TrafficScopeFilter.LAN_ONLY -> streams.filter { it.captureSource == CaptureSource.LAN_PROMISCUOUS }
        }
    }

    val nowMs = System.currentTimeMillis()
    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, end = 12.dp, top = 12.dp, bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            TrafficScopeFilter.entries.forEach { scope ->
                val selected = scopeFilter == scope
                val count = when (scope) {
                    TrafficScopeFilter.ALL -> streams.size
                    TrafficScopeFilter.PHONE_ONLY -> phoneStreamsCount
                    TrafficScopeFilter.LAN_ONLY -> lanStreamsCount
                }
                val isLanScope = scope == TrafficScopeFilter.LAN_ONLY
                FilterChip(
                    selected = selected,
                    onClick = { scopeFilter = scope },
                    leadingIcon = {
                        Icon(
                            imageVector = when (scope) {
                                TrafficScopeFilter.ALL -> Icons.Rounded.Layers
                                TrafficScopeFilter.PHONE_ONLY -> Icons.Rounded.Smartphone
                                TrafficScopeFilter.LAN_ONLY -> Icons.Rounded.WifiTethering
                            },
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    label = {
                        Text(
                            text = "${scope.label} ($count)",
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium
                            ),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = if (isLanScope) {
                            WarmGoldLive.copy(alpha = 0.22f)
                        } else {
                            MaterialTheme.colorScheme.primaryContainer
                        },
                        selectedLabelColor = if (isLanScope) WarmGoldLive else MaterialTheme.colorScheme.onPrimaryContainer,
                        selectedLeadingIconColor = if (isLanScope) WarmGoldLive else MaterialTheme.colorScheme.onPrimaryContainer
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("streams_scope_${scope.name.lowercase()}")
                )
            }
        }

        if (visibleStreams.isEmpty()) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Icon(
                        imageVector = if (scopeFilter == TrafficScopeFilter.LAN_ONLY) {
                            Icons.Rounded.WifiTethering
                        } else {
                            Icons.Rounded.Smartphone
                        },
                        contentDescription = null,
                        tint = if (scopeFilter == TrafficScopeFilter.LAN_ONLY) WarmGoldLive else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp)
                    )
                    Text(
                        text = if (scopeFilter == TrafficScopeFilter.LAN_ONLY) {
                            "No LAN Promiscuous Streams Yet"
                        } else {
                            "No Phone (tun0) Streams Yet"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        textAlign = TextAlign.Center
                    )
                    Text(
                        text = if (scopeFilter == TrafficScopeFilter.LAN_ONLY) {
                            "Enable passive Multicast Listen or start Root Capture in the Sandbox tab to group LAN mDNS & SSDP streams here."
                        } else {
                            "Start VPN Capture on tun0 to group Phone TCP and UDP conversations separately from LAN broadcasts."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                    OutlinedButton(onClick = { scopeFilter = TrafficScopeFilter.ALL }) {
                        Text("Show All Streams")
                    }
                }
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 4.dp, bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .testTag("streams_list")
            ) {
                items(visibleStreams, key = { it.key }) { stream ->
                    val isRecent = (nowMs - stream.lastSeenMs) < 15_000L
                    StreamCard(
                        stream = stream,
                        resolvedDomains = resolvedDomains,
                        resolveHostnames = resolveHostnames,
                        isActiveRecent = isRecent,
                        onClick = { onSelectStream(stream) },
                        onFilterClick = { onFilterToStream(stream) }
                    )
                }
            }
        }
    }
}

@Composable
private fun StreamCard(
    stream: ConversationStream,
    resolvedDomains: Map<String, ResolvedHost>,
    resolveHostnames: Boolean,
    isActiveRecent: Boolean,
    onClick: () -> Unit,
    onFilterClick: () -> Unit
) {
    val protoColors = LocalProtocolColors.current
    val accent = protoColors.colorFor(stream.protocol)
    val isLanStream = stream.captureSource == CaptureSource.LAN_PROMISCUOUS

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = if (isLanStream) {
            WarmGoldLive.copy(alpha = 0.06f)
        } else {
            MaterialTheme.colorScheme.surfaceContainerLow
        },
        border = BorderStroke(
            1.dp,
            if (isLanStream) WarmGoldLive.copy(alpha = 0.48f) else MaterialTheme.colorScheme.outlineVariant
        ),
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onClick)
            .testTag("stream_card_${stream.remoteIp}_${stream.remotePort}")
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    ProtocolBadge(protocol = stream.protocol)
                    CaptureSourceBadge(captureSource = stream.captureSource)
                    if (isActiveRecent) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(WarmGoldLive)
                            )
                            Text(
                                text = "ACTIVE",
                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                color = WarmGoldLive
                            )
                        }
                    }
                    Text(
                        text = "${stream.packetCount} pkts",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                IconButton(
                    onClick = onFilterClick
                ) {
                    Icon(
                        imageVector = Icons.Rounded.FilterAlt,
                        contentDescription = "Filter packets to this stream",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            val resolvedRemote = if (resolveHostnames) resolvedDomains[stream.remoteIp] else null
            val displayHost = stream.hostLabel ?: resolvedRemote?.domain
            if (!displayHost.isNullOrBlank()) {
                val badge = resolvedRemote?.source?.shortLabel?.let { " [$it]" }.orEmpty()
                Text(
                    text = "$displayHost$badge",
                    style = MaterialTheme.typography.titleSmall.copy(fontFamily = MonoFontFamily),
                    color = accent,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Text(
                text = "${stream.localEndpoint}  ↔  ${stream.remoteEndpoint}",
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text(
                    text = "↑ Out: ${formatByteCount(stream.bytesOut)}",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                    color = protoColors.outbound
                )
                Text(
                    text = "↓ In: ${formatByteCount(stream.bytesIn)}",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                    color = protoColors.inbound
                )
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    text = "Total: ${formatByteCount(stream.totalBytes)}",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    ),
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}

@Composable
fun FollowStreamDialog(
    streamKey: String,
    packets: List<CapturedPacket>,
    resolvedDomains: Map<String, ResolvedHost> = emptyMap(),
    resolveHostnames: Boolean = true,
    onFilterToStream: () -> Unit,
    onDismiss: () -> Unit
) {
    val protoColors = LocalProtocolColors.current
    val payloadPackets = packets.filter { it.payloadLength > 0 }
    val host = packets.firstNotNullOfOrNull { it.hostOrSni }
        ?: if (resolveHostnames) {
            packets.firstNotNullOfOrNull {
                resolvedDomains[it.dstIp]?.domain ?: resolvedDomains[it.srcIp]?.domain
            }
        } else null

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            modifier = Modifier
                .fillMaxWidth(0.94f)
                .heightIn(min = 320.dp, max = 640.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Follow Stream",
                            style = MaterialTheme.typography.titleLarge
                        )
                        Text(
                            text = host ?: streamKey.replace("|", " • "),
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Rounded.Close, contentDescription = "Close stream viewer")
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = protoColors.hexBg,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                ) {
                    if (payloadPackets.isEmpty()) {
                        Box(
                            modifier = Modifier.fillMaxSize().padding(16.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "Control frames only (${packets.size} packets, 0 payload bytes).",
                                style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        LazyColumn(
                            contentPadding = PaddingValues(10.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(payloadPackets, key = { it.id }) { pkt ->
                                val isOut = pkt.direction == PacketDirection.OUTBOUND
                                val color = if (isOut) protoColors.outbound else protoColors.inbound
                                val sliceEnd = (pkt.payloadOffset + pkt.payloadLength).coerceAtMost(pkt.rawBytes.size)
                                val slice = if (pkt.payloadOffset < sliceEnd) {
                                    pkt.rawBytes.copyOfRange(pkt.payloadOffset, sliceEnd)
                                } else ByteArray(0)
                                val decoded = decodePrintableStream(slice)

                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(color.copy(alpha = 0.08f))
                                        .padding(8.dp)
                                ) {
                                    Text(
                                        text = "#${pkt.id} ${if (isOut) "CLIENT → SERVER" else "SERVER → CLIENT"} (${pkt.payloadLength} B)",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.Bold
                                        ),
                                        color = color
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = decoded,
                                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Close")
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(onClick = onFilterToStream) {
                        Icon(Icons.Rounded.FilterAlt, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Filter Packets")
                    }
                }
            }
        }
    }
}

private fun decodePrintableStream(bytes: ByteArray): String {
    if (bytes.isEmpty()) return ""
    val asciiCount = bytes.count { b ->
        val c = b.toInt() and 0xFF
        c == 10 || c == 13 || c == 9 || c in 32..126
    }
    return if (asciiCount >= bytes.size * 0.65) {
        String(bytes, StandardCharsets.UTF_8)
            .replace(Regex("[^\\x09\\x0A\\x0D\\x20-\\x7E]"), ".")
            .take(1200)
    } else {
        bytes.take(256).joinToString(" ") { "%02x".format(it) } +
            if (bytes.size > 256) " … (+${bytes.size - 256} B)" else ""
    }
}
