package com.example.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.CaptureSource
import com.example.model.CapturedPacket
import com.example.model.ResolvedHost
import com.example.ui.theme.LocalProtocolColors
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun PacketRowCard(
    packet: CapturedPacket,
    isSelected: Boolean,
    resolveHostnames: Boolean,
    resolvedDomains: Map<String, ResolvedHost>,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val protoColor = LocalProtocolColors.current.colorFor(packet.protocol)
    val isLanPacket = packet.captureSource == CaptureSource.LAN_PROMISCUOUS
    val stripeColor = if (isLanPacket) WarmGoldLive else protoColor
    val bgColor = when {
        isSelected -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.38f)
        isLanPacket -> WarmGoldLive.copy(alpha = 0.06f)
        else -> MaterialTheme.colorScheme.surfaceContainerLow
    }
    val borderColor = when {
        isSelected -> MaterialTheme.colorScheme.primary
        isLanPacket -> WarmGoldLive.copy(alpha = 0.45f)
        else -> MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.7f)
    }

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = bgColor,
        border = BorderStroke(1.dp, borderColor),
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .testTag("packet_row_${packet.id}")
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min)
        ) {
            Box(
                modifier = Modifier
                    .width(4.dp)
                    .fillMaxHeight()
                    .background(stripeColor)
            )

            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 10.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    FlowRow(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                        horizontalArrangement = Arrangement.spacedBy(5.dp)
                    ) {
                        Text(
                            text = "#${packet.id}",
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            ),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.align(Alignment.CenterVertically)
                        )
                        Text(
                            text = String.format(Locale.US, "%.3fs", packet.relativeTimeMs / 1000.0),
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
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
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                val srcText = if (packet.srcPort > 0) "${packet.srcIp}:${packet.srcPort}" else packet.srcIp
                val dstText = if (packet.dstPort > 0) "${packet.dstIp}:${packet.dstPort}" else packet.dstIp
                val srcResolved = if (resolveHostnames) resolvedDomains[packet.srcIp] else null
                val dstResolved = if (resolveHostnames) resolvedDomains[packet.dstIp] else null
                val srcDisplay = if (srcResolved != null) {
                    if (packet.srcPort > 0) "${srcResolved.domain}:${packet.srcPort}" else srcResolved.domain
                } else srcText
                val dstDisplay = if (dstResolved != null) {
                    if (packet.dstPort > 0) "${dstResolved.domain}:${packet.dstPort}" else dstResolved.domain
                } else dstText
                val anyResolved = srcResolved != null || dstResolved != null

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "$srcDisplay → $dstDisplay",
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.SemiBold
                        ),
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    if (!packet.hostOrSni.isNullOrBlank()) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = packet.hostOrSni,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = protoColor,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                if (anyResolved) {
                    val sourceTag = (dstResolved ?: srcResolved)?.source?.shortLabel
                    Text(
                        text = "$srcText → $dstText${if (sourceTag != null) "  [$sourceTag]" else ""}",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.85f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Text(
                    text = packet.infoSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}
