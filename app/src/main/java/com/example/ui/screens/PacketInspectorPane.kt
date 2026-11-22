package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Timeline
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SecondaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.ProtocolLayer
import com.example.model.ResolvedHost
import com.example.ui.components.CaptureSourceBadge
import com.example.ui.components.DirectionPill
import com.example.ui.components.ProtocolBadge
import com.example.ui.theme.LocalProtocolColors
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun PacketInspectorPane(
    packet: CapturedPacket?,
    resolvedDomains: Map<String, ResolvedHost> = emptyMap(),
    resolveHostnames: Boolean = true,
    showBackButton: Boolean,
    onBack: () -> Unit,
    onFollowStream: (String) -> Unit,
    onCopiedHex: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (packet == null) {
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
                    imageVector = Icons.Rounded.Layers,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(48.dp)
                )
                Text(
                    text = "Select a Packet to Inspect",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = "Tap any captured frame to dissect IP/TCP/UDP/DNS/TLS/HTTP protocol layers and explore its interactive Hex & ASCII dump.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        return
    }

    var selectedTab by remember(packet.id) { mutableIntStateOf(0) }
    var highlightRange by remember(packet.id) { mutableStateOf<IntRange?>(null) }
    val expandedLayers = remember(packet.id) {
        mutableStateMapOf<Int, Boolean>().apply {
            packet.layers.indices.forEach { idx -> put(idx, idx > 0) }
        }
    }
    val context = LocalContext.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(start = 12.dp, end = 12.dp, top = 12.dp, bottom = 8.dp)
    ) {
        // Inspector Header
        val isLanPacket = packet.captureSource == CaptureSource.LAN_PROMISCUOUS
        Surface(
            shape = RoundedCornerShape(14.dp),
            color = MaterialTheme.colorScheme.surfaceContainer,
            border = BorderStroke(
                1.dp,
                if (isLanPacket) WarmGoldLive.copy(alpha = 0.55f) else MaterialTheme.colorScheme.outlineVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    FlowRow(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        if (showBackButton) {
                            IconButton(
                                onClick = onBack,
                                modifier = Modifier
                                    .align(Alignment.CenterVertically)
                                    .testTag("inspector_back_button")
                            ) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                                    contentDescription = "Back to packet list"
                                )
                            }
                        }
                        Text(
                            text = "Frame #${packet.id}",
                            style = MaterialTheme.typography.titleMedium.copy(fontFamily = MonoFontFamily),
                            modifier = Modifier.align(Alignment.CenterVertically)
                        )
                        ProtocolBadge(
                            protocol = packet.protocol,
                            modifier = Modifier.align(Alignment.CenterVertically)
                        )
                        CaptureSourceBadge(
                            captureSource = packet.captureSource,
                            modifier = Modifier.align(Alignment.CenterVertically)
                        )
                        DirectionPill(
                            direction = packet.direction,
                            modifier = Modifier.align(Alignment.CenterVertically)
                        )
                    }

                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "${packet.length} B",
                        style = MaterialTheme.typography.labelMedium.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.primary
                    )
                }

                val src = if (packet.srcPort > 0) "${packet.srcIp}:${packet.srcPort}" else packet.srcIp
                val dst = if (packet.dstPort > 0) "${packet.dstIp}:${packet.dstPort}" else packet.dstIp
                val srcHost = if (resolveHostnames) resolvedDomains[packet.srcIp]?.domain else null
                val dstHost = if (resolveHostnames) resolvedDomains[packet.dstIp]?.domain else null
                val srcHeader = if (srcHost != null) {
                    if (packet.srcPort > 0) "$srcHost:${packet.srcPort}" else srcHost
                } else src
                val dstHeader = if (dstHost != null) {
                    if (packet.dstPort > 0) "$dstHost:${packet.dstPort}" else dstHost
                } else dst
                Text(
                    text = "$srcHeader  →  $dstHeader",
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.SemiBold
                    )
                )

                if (!packet.hostOrSni.isNullOrBlank()) {
                    Text(
                        text = "Observed Host / SNI: ${packet.hostOrSni}",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.secondary
                    )
                }

                if (resolveHostnames) {
                    val srcResolved = resolvedDomains[packet.srcIp]
                    val dstResolved = resolvedDomains[packet.dstIp]
                    if (srcResolved != null || dstResolved != null) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.surfaceContainerLow)
                                .padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            if (srcResolved != null) {
                                Text(
                                    text = "Src DNS: ${srcResolved.domain} (${srcResolved.ip}) [${srcResolved.source.shortLabel}]",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                            if (dstResolved != null) {
                                Text(
                                    text = "Dst DNS: ${dstResolved.domain} (${dstResolved.ip}) [${dstResolved.source.shortLabel}]",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { onFollowStream(packet.streamKey) },
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 42.dp)
                            .testTag("follow_stream_button")
                    ) {
                        Icon(Icons.Rounded.Timeline, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Follow Stream", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    OutlinedButton(
                        onClick = {
                            val hexString = packet.rawBytes.joinToString(" ") { "%02x".format(it) }
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            cm.setPrimaryClip(ClipData.newPlainText("Packet Hex", hexString))
                            onCopiedHex("Copied ${packet.rawBytes.size} hex bytes to clipboard")
                        },
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 42.dp)
                            .testTag("copy_hex_button")
                    ) {
                        Icon(Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Copy Hex", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        SecondaryTabRow(
            selectedTabIndex = selectedTab,
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
            modifier = Modifier.clip(RoundedCornerShape(10.dp))
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = { Text("Protocol Tree (${packet.layers.size})") },
                modifier = Modifier.testTag("tab_protocol_tree")
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = { Text("Hex & ASCII (${packet.rawBytes.size}B)") },
                modifier = Modifier.testTag("tab_hex_dump")
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (selectedTab == 0) {
            LazyColumn(
                contentPadding = PaddingValues(bottom = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                itemsIndexed(packet.layers) { idx, layer ->
                    val expanded = expandedLayers[idx] ?: true
                    ProtocolLayerAccordion(
                        layer = layer,
                        expanded = expanded,
                        highlightRange = highlightRange,
                        onToggleExpand = { expandedLayers[idx] = !expanded },
                        onSelectRange = { range ->
                            highlightRange = range
                            selectedTab = 1 // Jump straight to highlighted bytes in Hex & ASCII!
                        }
                    )
                }
            }
        } else {
            HexAsciiDumpView(
                bytes = packet.rawBytes,
                highlightRange = highlightRange,
                onClearHighlight = { highlightRange = null },
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            )
        }
    }
}

@Composable
private fun ProtocolLayerAccordion(
    layer: ProtocolLayer,
    expanded: Boolean,
    highlightRange: IntRange?,
    onToggleExpand: () -> Unit,
    onSelectRange: (IntRange) -> Unit
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggleExpand)
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = layer.name,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = "Bytes [${layer.byteStart}..${(layer.byteEnd - 1).coerceAtLeast(layer.byteStart)}] (${(layer.byteEnd - layer.byteStart).coerceAtLeast(0)} B)",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Icon(
                    imageVector = if (expanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                    contentDescription = if (expanded) "Collapse layer" else "Expand layer"
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                        .padding(horizontal = 10.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    layer.fields.forEach { field ->
                        val fieldRange = field.byteStart until field.byteEnd
                        val isHighlighted = highlightRange == fieldRange
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(6.dp))
                                .background(
                                    if (isHighlighted) {
                                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
                                    } else {
                                        MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = 0.55f)
                                    }
                                )
                                .clickable { onSelectRange(fieldRange) }
                                .padding(horizontal = 8.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = field.label,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.weight(0.42f)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = field.value,
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Medium
                                ),
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(0.58f)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HexAsciiDumpView(
    bytes: ByteArray,
    highlightRange: IntRange?,
    onClearHighlight: () -> Unit,
    modifier: Modifier = Modifier
) {
    val protoColors = LocalProtocolColors.current
    val primaryColor = MaterialTheme.colorScheme.primary
    val onSurface = MaterialTheme.colorScheme.onSurface
    val mutedColor = MaterialTheme.colorScheme.onSurfaceVariant
    val rowCount = (bytes.size + 15) / 16

    Column(modifier = modifier) {
        if (highlightRange != null) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Highlighted bytes: ${highlightRange.first}..${highlightRange.last}",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                    color = primaryColor
                )
                Text(
                    text = "Clear highlight",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .clickable(onClick = onClearHighlight)
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                )
            }
        }

        Surface(
            shape = RoundedCornerShape(12.dp),
            color = protoColors.hexBg,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier.fillMaxSize()
        ) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .horizontalScroll(rememberScrollState())
                    .padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                items(rowCount) { row ->
                    val offset = row * 16
                    val lineText = buildAnnotatedString {
                        withStyle(SpanStyle(color = mutedColor)) {
                            append("%04x  ".format(offset))
                        }
                        for (col in 0 until 16) {
                            val idx = offset + col
                            if (col == 8) append(" ")
                            if (idx < bytes.size) {
                                val highlighted = highlightRange?.contains(idx) == true
                                withStyle(
                                    SpanStyle(
                                        color = if (highlighted) primaryColor else onSurface,
                                        background = if (highlighted) protoColors.hexHighlight else androidx.compose.ui.graphics.Color.Transparent,
                                        fontWeight = if (highlighted) FontWeight.Bold else FontWeight.Normal
                                    )
                                ) {
                                    append("%02x ".format(bytes[idx].toInt() and 0xFF))
                                }
                            } else {
                                append("   ")
                            }
                        }
                        append(" ")
                        for (col in 0 until 16) {
                            val idx = offset + col
                            if (idx < bytes.size) {
                                val b = bytes[idx].toInt() and 0xFF
                                val ch = if (b in 32..126) b.toChar() else '.'
                                val highlighted = highlightRange?.contains(idx) == true
                                withStyle(
                                    SpanStyle(
                                        color = if (highlighted) primaryColor else mutedColor,
                                        background = if (highlighted) protoColors.hexHighlight else androidx.compose.ui.graphics.Color.Transparent,
                                        fontWeight = if (highlighted) FontWeight.Bold else FontWeight.Normal
                                    )
                                ) {
                                    append(ch)
                                }
                            }
                        }
                    }

                    Text(
                        text = lineText,
                        style = MaterialTheme.typography.labelMedium.copy(
                            fontFamily = MonoFontFamily
                        ),
                        softWrap = false
                    )
                }
            }
        }
    }
}
