package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.TrendingUp
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.AlertSeverity
import com.example.model.AlertThresholdConfig
import com.example.model.NetworkAlertEvent
import com.example.model.PortMonitorMode
import com.example.ui.theme.AmberAlert
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.RoseError
import com.example.ui.theme.WarmGoldLive
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

@Composable
fun AlertConfigScreen(
    config: AlertThresholdConfig,
    alerts: List<NetworkAlertEvent>,
    onUpdateConfig: (AlertThresholdConfig) -> Unit,
    onAddPort: (Int) -> Unit,
    onRemovePort: (Int) -> Unit,
    onToggleSystemNotifications: (Boolean) -> Unit,
    onResetDefaults: () -> Unit,
    onClearAlerts: () -> Unit,
    onInspectAlert: (NetworkAlertEvent) -> Unit,
    onScreenViewed: () -> Unit,
    modifier: Modifier = Modifier
) {
    LaunchedEffect(alerts.size) {
        onScreenViewed()
    }

    LazyColumn(
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = modifier
            .fillMaxSize()
            .testTag("alert_config_screen")
    ) {
        item {
            AlertEngineMasterCard(
                config = config,
                alertCount = alerts.size,
                onToggleEnabled = { enabled ->
                    onUpdateConfig(config.copy(alertsEnabled = enabled))
                }
            )
        }

        item {
            TriggeredAlertsCard(
                alerts = alerts,
                onClearAlerts = onClearAlerts,
                onInspectAlert = onInspectAlert
            )
        }

        item {
            HighLatencyThresholdCard(
                enabled = config.alertsEnabled && config.highLatencyEnabled,
                ruleChecked = config.highLatencyEnabled,
                maxLatencyMs = config.maxLatencyMs,
                onToggleRule = { checked ->
                    onUpdateConfig(config.copy(highLatencyEnabled = checked))
                },
                onLatencyChange = { newMs ->
                    onUpdateConfig(config.copy(maxLatencyMs = newMs))
                }
            )
        }

        item {
            UnauthorizedPortCard(
                enabled = config.alertsEnabled && config.unauthorizedPortEnabled,
                ruleChecked = config.unauthorizedPortEnabled,
                mode = config.portMonitorMode,
                ports = if (config.portMonitorMode == PortMonitorMode.WATCHED_PORTS) {
                    config.flaggedPorts
                } else {
                    config.allowedPorts
                },
                onToggleRule = { checked ->
                    onUpdateConfig(config.copy(unauthorizedPortEnabled = checked))
                },
                onSelectMode = { mode ->
                    onUpdateConfig(config.copy(portMonitorMode = mode))
                },
                onAddPort = onAddPort,
                onRemovePort = onRemovePort
            )
        }

        item {
            DataSpikeThresholdCard(
                enabled = config.alertsEnabled && config.dataSpikeEnabled,
                ruleChecked = config.dataSpikeEnabled,
                maxBytesPerSecKB = config.maxBytesPerSecKB,
                maxPacketsPerSec = config.maxPacketsPerSec,
                onToggleRule = { checked ->
                    onUpdateConfig(config.copy(dataSpikeEnabled = checked))
                },
                onBytesLimitChange = { kb ->
                    onUpdateConfig(config.copy(maxBytesPerSecKB = kb))
                },
                onPacketsLimitChange = { pps ->
                    onUpdateConfig(config.copy(maxPacketsPerSec = pps))
                }
            )
        }

        item {
            DeliveryAndResetCard(
                notifySystemBar = config.notifySystemBar,
                onToggleSystemNotifications = onToggleSystemNotifications,
                onResetDefaults = onResetDefaults
            )
        }
    }
}

@Composable
private fun AlertEngineMasterCard(
    config: AlertThresholdConfig,
    alertCount: Int,
    onToggleEnabled: (Boolean) -> Unit
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(
            1.dp,
            if (config.alertsEnabled) WarmGoldLive.copy(alpha = 0.5f) else MaterialTheme.colorScheme.outlineVariant
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = Icons.Rounded.NotificationsActive,
                    contentDescription = null,
                    tint = if (config.alertsEnabled) WarmGoldLive else MaterialTheme.colorScheme.onSurfaceVariant
                )
                Column {
                    Text(
                        text = "Network Alert Thresholds",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = if (config.alertsEnabled) {
                            "Monitoring live flows • $alertCount alert(s) triggered"
                        } else {
                            "Threshold monitoring paused"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Switch(
                checked = config.alertsEnabled,
                onCheckedChange = onToggleEnabled,
                modifier = Modifier.testTag("alerts_master_switch")
            )
        }
    }
}

@Composable
private fun TriggeredAlertsCard(
    alerts: List<NetworkAlertEvent>,
    onClearAlerts: () -> Unit,
    onInspectAlert: (NetworkAlertEvent) -> Unit
) {
    val timeFormatter = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }

    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("triggered_alerts_card")
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
                        imageVector = Icons.Rounded.WarningAmber,
                        contentDescription = null,
                        tint = if (alerts.isNotEmpty()) AmberAlert else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "Triggered Events (${alerts.size})",
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                if (alerts.isNotEmpty()) {
                    IconButton(
                        onClick = onClearAlerts,
                        modifier = Modifier.testTag("clear_alerts_button")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.DeleteSweep,
                            contentDescription = "Clear alert log"
                        )
                    }
                }
            }

            if (alerts.isEmpty()) {
                Text(
                    text = "No threshold breaches detected yet. Adjust thresholds below and start packet capture to audit live traffic.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                alerts.take(8).forEach { event ->
                    val sevColor = if (event.severity == AlertSeverity.CRITICAL) RoseError else AmberAlert
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(MaterialTheme.colorScheme.surfaceContainerLow)
                            .clickable(enabled = event.filterExpr != null || event.packetId != null) {
                                onInspectAlert(event)
                            }
                            .padding(10.dp),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = sevColor.copy(alpha = 0.16f)
                        ) {
                            Text(
                                text = if (event.severity == AlertSeverity.CRITICAL) "CRIT" else "WARN",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = sevColor,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = event.title,
                                    style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    text = timeFormatter.format(Date(event.timestampMs)),
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Spacer(Modifier.height(2.dp))
                            Text(
                                text = event.detail,
                                style = MaterialTheme.typography.bodySmall,
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
private fun HighLatencyThresholdCard(
    enabled: Boolean,
    ruleChecked: Boolean,
    maxLatencyMs: Int,
    onToggleRule: (Boolean) -> Unit,
    onLatencyChange: (Int) -> Unit
) {
    val presets = listOf(50, 150, 250, 500, 1000)

    RuleConfigCard(
        icon = Icons.Rounded.Speed,
        iconTint = MaterialTheme.colorScheme.primary,
        title = "High Latency Threshold",
        subtitle = "TCP SYN→SYN/ACK handshake, DNS response, or HTTP TTFB RTT",
        checked = ruleChecked,
        switchTestTag = "latency_alert_switch",
        onToggle = onToggleRule
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Alert above RTT",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "$maxLatencyMs ms",
                style = MaterialTheme.typography.titleSmall.copy(
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                ),
                color = MaterialTheme.colorScheme.primary
            )
        }

        Slider(
            value = maxLatencyMs.toFloat().coerceIn(50f, 2000f),
            onValueChange = { onLatencyChange((it / 10f).roundToInt() * 10) },
            valueRange = 50f..2000f,
            enabled = enabled,
            modifier = Modifier.testTag("latency_threshold_slider")
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            presets.forEach { preset ->
                FilterChip(
                    selected = maxLatencyMs == preset,
                    enabled = enabled,
                    onClick = { onLatencyChange(preset) },
                    label = {
                        Text(
                            text = "${preset}ms",
                            style = MaterialTheme.typography.labelMedium.copy(fontFamily = MonoFontFamily)
                        )
                    },
                    modifier = Modifier.testTag("latency_preset_$preset")
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun UnauthorizedPortCard(
    enabled: Boolean,
    ruleChecked: Boolean,
    mode: PortMonitorMode,
    ports: Set<Int>,
    onToggleRule: (Boolean) -> Unit,
    onSelectMode: (PortMonitorMode) -> Unit,
    onAddPort: (Int) -> Unit,
    onRemovePort: (Int) -> Unit
) {
    var portInput by remember { mutableStateOf("") }
    val focusManager = LocalFocusManager.current

    fun submitPort() {
        val parsed = portInput.trim().toIntOrNull()
        if (parsed != null && parsed in 1..65535) {
            onAddPort(parsed)
            portInput = ""
            focusManager.clearFocus()
        }
    }

    RuleConfigCard(
        icon = Icons.Rounded.Security,
        iconTint = RoseError,
        title = "Unauthorized Port Activity",
        subtitle = mode.description,
        checked = ruleChecked,
        switchTestTag = "port_alert_switch",
        onToggle = onToggleRule
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            PortMonitorMode.entries.forEach { option ->
                FilterChip(
                    selected = mode == option,
                    enabled = enabled,
                    onClick = { onSelectMode(option) },
                    label = { Text(option.label) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag(
                            if (option == PortMonitorMode.WATCHED_PORTS) "port_mode_watched" else "port_mode_allowlist"
                        )
                )
            }
        }

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            ports.sorted().forEach { port ->
                InputChip(
                    selected = false,
                    enabled = enabled,
                    onClick = { onRemovePort(port) },
                    label = {
                        Text(
                            text = ":$port",
                            style = MaterialTheme.typography.labelMedium.copy(fontFamily = MonoFontFamily)
                        )
                    },
                    trailingIcon = {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = "Remove port $port",
                            modifier = Modifier.size(14.dp)
                        )
                    },
                    modifier = Modifier.testTag("port_chip_$port")
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = portInput,
                onValueChange = { txt -> portInput = txt.filter { it.isDigit() }.take(5) },
                enabled = enabled,
                singleLine = true,
                label = { Text(if (mode == PortMonitorMode.WATCHED_PORTS) "Add watched port" else "Add allowed port") },
                placeholder = { Text("e.g. 8080") },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Number,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = { submitPort() }),
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                modifier = Modifier
                    .weight(1f)
                    .testTag("add_port_input")
            )
            Button(
                onClick = ::submitPort,
                enabled = enabled && (portInput.toIntOrNull() in 1..65535),
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag("add_port_button")
            ) {
                Icon(Icons.Rounded.Add, contentDescription = "Add port")
                Spacer(Modifier.width(4.dp))
                Text("Add")
            }
        }
    }
}

@Composable
private fun DataSpikeThresholdCard(
    enabled: Boolean,
    ruleChecked: Boolean,
    maxBytesPerSecKB: Int,
    maxPacketsPerSec: Int,
    onToggleRule: (Boolean) -> Unit,
    onBytesLimitChange: (Int) -> Unit,
    onPacketsLimitChange: (Int) -> Unit
) {
    RuleConfigCard(
        icon = Icons.AutoMirrored.Rounded.TrendingUp,
        iconTint = AmberAlert,
        title = "Unexpected Data Spikes",
        subtitle = "Detects sudden 1-second bandwidth or packet-rate bursts",
        checked = ruleChecked,
        switchTestTag = "spike_alert_switch",
        onToggle = onToggleRule
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "Throughput Spike Limit",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "$maxBytesPerSecKB KB/s",
                style = MaterialTheme.typography.titleSmall.copy(
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                ),
                color = AmberAlert
            )
        }
        Slider(
            value = maxBytesPerSecKB.toFloat().coerceIn(64f, 4096f),
            onValueChange = { onBytesLimitChange((it / 32f).roundToInt() * 32) },
            valueRange = 64f..4096f,
            enabled = enabled,
            modifier = Modifier.testTag("bandwidth_spike_slider")
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "Packet Burst Limit",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "$maxPacketsPerSec pkt/s",
                style = MaterialTheme.typography.titleSmall.copy(
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                ),
                color = MaterialTheme.colorScheme.secondary
            )
        }
        Slider(
            value = maxPacketsPerSec.toFloat().coerceIn(25f, 1000f),
            onValueChange = { onPacketsLimitChange((it / 25f).roundToInt() * 25) },
            valueRange = 25f..1000f,
            enabled = enabled,
            modifier = Modifier.testTag("packet_spike_slider")
        )

        val presets = listOf(
            Triple("Mobile", 256, 80),
            Triple("Balanced", 512, 150),
            Triple("High Burst", 2048, 500)
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            presets.forEach { (label, kb, pps) ->
                FilterChip(
                    selected = maxBytesPerSecKB == kb && maxPacketsPerSec == pps,
                    enabled = enabled,
                    onClick = {
                        onBytesLimitChange(kb)
                        onPacketsLimitChange(pps)
                    },
                    label = { Text("$label ($kb KB/s)") }
                )
            }
        }
    }
}

@Composable
private fun DeliveryAndResetCard(
    notifySystemBar: Boolean,
    onToggleSystemNotifications: (Boolean) -> Unit,
    onResetDefaults: () -> Unit
) {
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
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "System Status-Bar Notifications",
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        text = "Post a device notification when a threshold breach occurs while capturing in background",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(Modifier.width(8.dp))
                Switch(
                    checked = notifySystemBar,
                    onCheckedChange = onToggleSystemNotifications,
                    modifier = Modifier.testTag("system_notify_switch")
                )
            }

            OutlinedButton(
                onClick = onResetDefaults,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag("reset_alert_defaults_button")
            ) {
                Icon(Icons.Rounded.RestartAlt, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text("Reset Alert Thresholds to Defaults")
            }
        }
    }
}

@Composable
private fun RuleConfigCard(
    icon: ImageVector,
    iconTint: Color,
    title: String,
    subtitle: String,
    checked: Boolean,
    switchTestTag: String,
    onToggle: (Boolean) -> Unit,
    content: @Composable () -> Unit
) {
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
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(imageVector = icon, contentDescription = null, tint = iconTint)
                    Column {
                        Text(text = title, style = MaterialTheme.typography.titleMedium)
                        Text(
                            text = subtitle,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Switch(
                    checked = checked,
                    onCheckedChange = onToggle,
                    modifier = Modifier.testTag(switchTestTag)
                )
            }

            content()
        }
    }
}
