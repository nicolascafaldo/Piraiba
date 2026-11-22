package com.example.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.WifiTethering
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.model.CaptureSource
import com.example.model.PacketDirection
import com.example.model.ProtocolType
import com.example.model.ThroughputPoint
import com.example.ui.theme.LocalProtocolColors
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ProtocolBadge(
    protocol: ProtocolType,
    modifier: Modifier = Modifier
) {
    val protoColor = LocalProtocolColors.current.colorFor(protocol)
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(6.dp),
        color = protoColor.copy(alpha = 0.16f),
        border = androidx.compose.foundation.BorderStroke(1.dp, protoColor.copy(alpha = 0.45f))
    ) {
        Text(
            text = protocol.label,
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            ),
            color = protoColor,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
        )
    }
}

@Composable
fun DirectionPill(
    direction: PacketDirection,
    modifier: Modifier = Modifier
) {
    val colors = LocalProtocolColors.current
    val accent = if (direction == PacketDirection.OUTBOUND) colors.outbound else colors.inbound
    val arrow = if (direction == PacketDirection.OUTBOUND) "↑" else "↓"
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(5.dp))
            .background(accent.copy(alpha = 0.12f))
            .padding(horizontal = 5.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = "$arrow ${direction.shortLabel}",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.SemiBold
            ),
            color = accent
        )
    }
}

@Composable
fun CaptureSourceBadge(
    captureSource: CaptureSource,
    modifier: Modifier = Modifier
) {
    val isLan = captureSource == CaptureSource.LAN_PROMISCUOUS
    val accent = if (isLan) WarmGoldLive else MaterialTheme.colorScheme.secondary
    val bgColor = if (isLan) {
        WarmGoldLive.copy(alpha = 0.16f)
    } else {
        MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.36f)
    }
    val borderColor = if (isLan) {
        WarmGoldLive.copy(alpha = 0.55f)
    } else {
        MaterialTheme.colorScheme.secondary.copy(alpha = 0.35f)
    }
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(6.dp),
        color = bgColor,
        border = androidx.compose.foundation.BorderStroke(1.dp, borderColor)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Icon(
                imageVector = if (isLan) Icons.Rounded.WifiTethering else Icons.Rounded.Smartphone,
                contentDescription = captureSource.label,
                tint = accent,
                modifier = Modifier.size(11.dp)
            )
            Text(
                text = captureSource.shortLabel,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                ),
                color = accent
            )
        }
    }
}

@Composable
fun LiveCaptureIndicator(
    isCapturing: Boolean,
    modifier: Modifier = Modifier
) {
    val liveAccent = MaterialTheme.colorScheme.tertiary
    val dotColor by animateColorAsState(
        targetValue = if (isCapturing) liveAccent else MaterialTheme.colorScheme.onSurfaceVariant,
        label = "capture_dot"
    )
    val bgColor = if (isCapturing) {
        WarmGoldLive.copy(alpha = 0.15f)
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(bgColor)
            .border(
                width = 1.dp,
                color = if (isCapturing) liveAccent.copy(alpha = 0.45f) else MaterialTheme.colorScheme.outlineVariant,
                shape = RoundedCornerShape(50)
            )
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(7.dp)
                .clip(CircleShape)
                .background(dotColor)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = if (isCapturing) "LIVE" else "IDLE",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            ),
            color = if (isCapturing) liveAccent else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun MiniThroughputSparkline(
    points: List<ThroughputPoint>,
    modifier: Modifier = Modifier
) {
    val lineColor = MaterialTheme.colorScheme.primary
    val secondaryColor = MaterialTheme.colorScheme.secondary

    Canvas(modifier = modifier) {
        if (points.size < 2) {
            drawLine(
                color = lineColor.copy(alpha = 0.25f),
                start = Offset(0f, size.height * 0.7f),
                end = Offset(size.width, size.height * 0.7f),
                strokeWidth = 2f
            )
            return@Canvas
        }

        val maxPps = (points.maxOfOrNull { it.packetsPerSec } ?: 1).coerceAtLeast(4).toFloat()
        val stepX = size.width / (points.size - 1).coerceAtLeast(1)

        val linePath = Path()
        val fillPath = Path()

        points.forEachIndexed { idx, pt ->
            val x = idx * stepX
            val ratio = (pt.packetsPerSec / maxPps).coerceIn(0f, 1f)
            val y = size.height - (ratio * (size.height * 0.82f)) - (size.height * 0.08f)
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
                colors = listOf(lineColor.copy(alpha = 0.32f), Color.Transparent)
            )
        )
        drawPath(
            path = linePath,
            brush = Brush.horizontalGradient(listOf(lineColor, secondaryColor)),
            style = Stroke(width = 3f, cap = StrokeCap.Round)
        )
    }
}

@Composable
fun FilterHelpDialog(
    onSelectExample: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val examples = listOf(
        "lan" to "Show only Promiscuous LAN multicast packets",
        "phone" to "Show only Phone (tun0) app traffic",
        "dns" to "Show only DNS queries & responses",
        "tls" to "Show TLS handshakes & encrypted flows",
        "http" to "Show cleartext HTTP requests & responses",
        "tcp.port == 443" to "TCP traffic on port 443",
        "udp.port == 53" to "UDP traffic on DNS port 53",
        "ip.addr == 8.8.8.8" to "Packets to or from 8.8.8.8",
        "tls.sni contains google" to "TLS packets whose SNI contains 'google'",
        "dns.resolved contains example" to "Packets whose IP resolves to 'example'",
        "tcp && !tls" to "Raw TCP excluding dissected TLS"
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Display Filter Syntax",
                style = MaterialTheme.typography.titleLarge
            )
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Tap an example to apply it to the live filter bar:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                examples.forEach { (expr, desc) ->
                    Surface(
                        onClick = {
                            onSelectExample(expr)
                            onDismiss()
                        },
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.surfaceContainerHigh,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                            Text(
                                text = expr,
                                style = MaterialTheme.typography.labelMedium.copy(
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = MaterialTheme.colorScheme.primary
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = desc,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

@Composable
fun ExportPcapDialog(
    totalCount: Int,
    filteredCount: Int,
    hasActiveFilter: Boolean,
    totalBytes: Long,
    onSaveToDevice: (fileName: String, filteredOnly: Boolean) -> Unit,
    onSharePcap: (fileName: String, filteredOnly: Boolean) -> Unit,
    onDismiss: () -> Unit
) {
    val defaultName = remember {
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        "piraiba_$ts.pcap"
    }
    var fileName by remember { mutableStateOf(defaultName) }
    var filteredOnly by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Export Capture (.pcap)",
                style = MaterialTheme.typography.titleLarge
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Saves standard libpcap (.pcap) binary format compatible with standard desktop packet analyzers and tcpdump.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = fileName,
                    onValueChange = { fileName = it },
                    label = { Text("Capture Filename") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("export_filename_input")
                )

                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                    ) {
                        RadioButton(
                            selected = !filteredOnly,
                            onClick = { filteredOnly = false },
                            modifier = Modifier.testTag("export_scope_all")
                        )
                        Text(
                            text = "All captured packets ($totalCount pkts • ${formatByteCount(totalBytes)})",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    if (hasActiveFilter) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                        ) {
                            RadioButton(
                                selected = filteredOnly,
                                onClick = { filteredOnly = true },
                                enabled = filteredCount > 0,
                                modifier = Modifier.testTag("export_scope_filtered")
                            )
                            Text(
                                text = "Displayed packets only ($filteredCount pkts)",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (filteredCount > 0) {
                                    MaterialTheme.colorScheme.onSurface
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                }
                            )
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val normalized = ensurePcapExtension(fileName)
                            onSharePcap(normalized, filteredOnly)
                        },
                        enabled = (if (filteredOnly) filteredCount else totalCount) > 0,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("share_pcap_button")
                    ) {
                        Icon(Icons.Rounded.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Share")
                    }
                    Button(
                        onClick = {
                            val normalized = ensurePcapExtension(fileName)
                            onSaveToDevice(normalized, filteredOnly)
                        },
                        enabled = (if (filteredOnly) filteredCount else totalCount) > 0,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("save_pcap_device_button")
                    ) {
                        Icon(Icons.Rounded.FileDownload, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Save .pcap")
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

private fun ensurePcapExtension(name: String): String {
    val trimmed = name.trim().ifEmpty { "piraiba_capture.pcap" }
    return if (trimmed.endsWith(".pcap", ignoreCase = true)) trimmed else "$trimmed.pcap"
}

fun formatByteCount(bytes: Long): String = when {
    bytes < 1024L -> "$bytes B"
    bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    bytes < 1024L * 1024L * 1024L -> String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
    else -> String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
}
