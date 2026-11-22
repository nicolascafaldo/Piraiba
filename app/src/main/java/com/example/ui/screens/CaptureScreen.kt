package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.HelpOutline
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.VerticalAlignBottom
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.model.CapturedPacket
import com.example.model.QuickFilter
import com.example.model.TrafficScopeFilter
import com.example.ui.components.FilterHelpDialog
import com.example.ui.components.MiniThroughputSparkline
import com.example.ui.components.PacketRowCard
import com.example.ui.components.formatByteCount
import com.example.ui.theme.AmberAlert
import com.example.ui.theme.ConsoleBgDark
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive
import com.example.viewmodel.CaptureUiState

@Composable
fun CaptureScreen(
    uiState: CaptureUiState,
    onStartCapture: () -> Unit,
    onOpenPcap: () -> Unit,
    onFilterQueryChange: (String) -> Unit,
    onQuickFilterSelected: (QuickFilter) -> Unit,
    onTrafficScopeSelected: (TrafficScopeFilter) -> Unit,
    onToggleAutoScroll: () -> Unit,
    onToggleResolveHostnames: () -> Unit,
    onSelectPacket: (CapturedPacket) -> Unit,
    modifier: Modifier = Modifier
) {
    var showFilterHelp by remember { mutableStateOf(false) }
    var showFilterBuilder by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val focusManager = LocalFocusManager.current

    LaunchedEffect(uiState.packets.size, uiState.autoScroll) {
        if (uiState.autoScroll && uiState.packets.isNotEmpty()) {
            listState.scrollToItem(uiState.packets.lastIndex)
        }
    }

    if (showFilterHelp) {
        FilterHelpDialog(
            onSelectExample = { onFilterQueryChange(it) },
            onDismiss = { showFilterHelp = false }
        )
    }

    if (showFilterBuilder) {
        CriteriaFilterDialog(
            currentQuickFilter = uiState.quickFilter,
            onApply = { expr, quick ->
                onQuickFilterSelected(quick)
                onFilterQueryChange(expr)
                showFilterBuilder = false
            },
            onDismiss = { showFilterBuilder = false }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(start = 12.dp, end = 12.dp, top = 12.dp)
    ) {
        TelemetrySummaryStrip(
            uiState = uiState,
            onToggleAutoScroll = onToggleAutoScroll,
            onToggleResolveHostnames = onToggleResolveHostnames
        )

        Spacer(modifier = Modifier.height(10.dp))

        val hasQuery = uiState.filterQuery.isNotBlank()
        val isFilterValid = uiState.filterValidation.isValid
        val borderColor = when {
            !hasQuery -> MaterialTheme.colorScheme.outlineVariant
            isFilterValid -> WarmGoldLive
            else -> AmberAlert
        }

        OutlinedTextField(
            value = uiState.filterQuery,
            onValueChange = onFilterQueryChange,
            singleLine = true,
            placeholder = {
                Text(
                    text = "Search payload, host, or filter (ip.src == ..., port == 443)",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            },
            leadingIcon = {
                Icon(
                    imageVector = when {
                        !hasQuery -> Icons.Rounded.Search
                        isFilterValid -> Icons.Rounded.CheckCircle
                        else -> Icons.Rounded.WarningAmber
                    },
                    contentDescription = "Search and filter status",
                    tint = when {
                        !hasQuery -> MaterialTheme.colorScheme.onSurfaceVariant
                        isFilterValid -> WarmGoldLive
                        else -> AmberAlert
                    }
                )
            },
            trailingIcon = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (hasQuery) {
                        IconButton(
                            onClick = { onFilterQueryChange("") },
                            modifier = Modifier.testTag("clear_filter_button")
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Clear,
                                contentDescription = "Clear filter"
                            )
                        }
                    }
                    IconButton(
                        onClick = { showFilterBuilder = true },
                        modifier = Modifier.testTag("filter_builder_button")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Tune,
                            contentDescription = "Structured criteria filter"
                        )
                    }
                    IconButton(
                        onClick = { showFilterHelp = true },
                        modifier = Modifier.testTag("filter_help_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Rounded.HelpOutline,
                            contentDescription = "Filter syntax help"
                        )
                    }
                }
            },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            keyboardActions = KeyboardActions(onSearch = { focusManager.clearFocus() }),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = borderColor,
                unfocusedBorderColor = borderColor,
                focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("display_filter_input")
        )

        if (hasQuery && !isFilterValid && uiState.filterValidation.errorHint != null) {
            Text(
                text = "${uiState.filterValidation.errorHint} — matching as keyword & payload search",
                style = MaterialTheme.typography.labelSmall,
                color = AmberAlert,
                modifier = Modifier.padding(start = 6.dp, top = 4.dp)
            )
        }

        Spacer(modifier = Modifier.height(6.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            TrafficScopeFilter.entries.forEach { scope ->
                val selected = uiState.trafficScopeFilter == scope
                val countSuffix = when (scope) {
                    TrafficScopeFilter.ALL -> "${uiState.phonePacketCount + uiState.lanBufferedPacketCount}"
                    TrafficScopeFilter.PHONE_ONLY -> "${uiState.phonePacketCount}"
                    TrafficScopeFilter.LAN_ONLY -> "${uiState.lanBufferedPacketCount}"
                }
                FilterChip(
                    selected = selected,
                    onClick = { onTrafficScopeSelected(scope) },
                    label = {
                        Text(
                            text = "${scope.label} ($countSuffix)",
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium
                            )
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = if (scope == TrafficScopeFilter.LAN_ONLY) {
                            WarmGoldLive.copy(alpha = 0.22f)
                        } else {
                            MaterialTheme.colorScheme.secondaryContainer
                        },
                        selectedLabelColor = if (scope == TrafficScopeFilter.LAN_ONLY) {
                            WarmGoldLive
                        } else {
                            MaterialTheme.colorScheme.onSecondaryContainer
                        }
                    ),
                    modifier = Modifier.testTag("scope_filter_${scope.name.lowercase()}")
                )
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(vertical = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            QuickFilter.entries.forEach { filter ->
                val selected = uiState.quickFilter == filter
                FilterChip(
                    selected = selected,
                    onClick = { onQuickFilterSelected(filter) },
                    label = {
                        Text(
                            text = filter.label,
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium
                            )
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                        selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer
                    ),
                    modifier = Modifier.testTag("quick_filter_${filter.name.lowercase()}")
                )
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        if (uiState.packets.isEmpty()) {
            EmptyCaptureView(
                isCapturing = uiState.isCapturing,
                hasActiveFilter = hasQuery ||
                    uiState.quickFilter != QuickFilter.ALL ||
                    uiState.trafficScopeFilter != TrafficScopeFilter.ALL,
                totalBufferedPackets = uiState.phonePacketCount + uiState.lanBufferedPacketCount,
                onStartCapture = onStartCapture,
                onOpenPcap = onOpenPcap,
                onResetFilters = {
                    onFilterQueryChange("")
                    onQuickFilterSelected(QuickFilter.ALL)
                    onTrafficScopeSelected(TrafficScopeFilter.ALL)
                },
                modifier = Modifier.weight(1f)
            )
        } else {
            LazyColumn(
                state = listState,
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(top = 2.dp, bottom = 16.dp),
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .testTag("packet_list")
            ) {
                items(
                    items = uiState.packets,
                    key = { it.id }
                ) { packet ->
                    PacketRowCard(
                        packet = packet,
                        isSelected = packet.id == uiState.selectedPacketId,
                        resolveHostnames = uiState.resolveHostnames,
                        resolvedDomains = uiState.resolvedDomains,
                        onClick = { onSelectPacket(packet) }
                    )
                }
            }
        }
    }
}

@Composable
private fun CriteriaFilterDialog(
    currentQuickFilter: QuickFilter,
    onApply: (String, QuickFilter) -> Unit,
    onDismiss: () -> Unit
) {
    var srcIp by remember { mutableStateOf("") }
    var dstIp by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    var payloadKeyword by remember { mutableStateOf("") }
    var selectedQuick by remember { mutableStateOf(currentQuickFilter) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Filter Packet Criteria",
                style = MaterialTheme.typography.titleLarge
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    QuickFilter.entries.forEach { q ->
                        FilterChip(
                            selected = selectedQuick == q,
                            onClick = { selectedQuick = q },
                            label = { Text(q.label) }
                        )
                    }
                }
                OutlinedTextField(
                    value = srcIp,
                    onValueChange = { srcIp = it },
                    label = { Text("Source IP (ip.src)") },
                    placeholder = { Text("e.g. 10.1.10.1") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_src_ip_input")
                )
                OutlinedTextField(
                    value = dstIp,
                    onValueChange = { dstIp = it },
                    label = { Text("Destination IP (ip.dst)") },
                    placeholder = { Text("e.g. 8.8.8.8") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_dst_ip_input")
                )
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it.filter { ch -> ch.isDigit() } },
                    label = { Text("Port Number (src or dst)") },
                    placeholder = { Text("e.g. 443 or 53") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_port_input")
                )
                OutlinedTextField(
                    value = payloadKeyword,
                    onValueChange = { payloadKeyword = it },
                    label = { Text("Payload Keyword") },
                    placeholder = { Text("e.g. example.com or GET") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_payload_input")
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val clauses = buildList {
                        if (srcIp.isNotBlank()) add("ip.src == ${srcIp.trim()}")
                        if (dstIp.isNotBlank()) add("ip.dst == ${dstIp.trim()}")
                        if (port.isNotBlank()) add("port == ${port.trim()}")
                        if (payloadKeyword.isNotBlank()) add("payload contains \"${payloadKeyword.trim()}\"")
                    }
                    onApply(clauses.joinToString(" && "), selectedQuick)
                },
                modifier = Modifier.testTag("apply_criteria_button")
            ) {
                Text("Apply Filter")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
private fun TelemetrySummaryStrip(
    uiState: CaptureUiState,
    onToggleAutoScroll: () -> Unit,
    onToggleResolveHostnames: () -> Unit
) {
    val latestPps = uiState.throughputHistory.lastOrNull()?.packetsPerSec ?: 0
    val resolvedCount = uiState.resolvedDomains.size
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "${uiState.packets.size} shown • ${formatByteCount(uiState.totalBytes)}",
                    style = MaterialTheme.typography.titleSmall.copy(fontFamily = MonoFontFamily),
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(2.dp))
                val dnsStatus = if (uiState.resolveHostnames && resolvedCount > 0) " • $resolvedCount DNS" else ""
                val rateText = if (uiState.isCapturing) "$latestPps/s" else "idle"
                Text(
                    text = "${uiState.phonePacketCount} phone • ${uiState.lanBufferedPacketCount} LAN • $rateText$dnsStatus",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            MiniThroughputSparkline(
                points = uiState.throughputHistory,
                modifier = Modifier
                    .width(56.dp)
                    .height(28.dp)
            )

            Surface(
                onClick = onToggleResolveHostnames,
                shape = RoundedCornerShape(8.dp),
                color = if (uiState.resolveHostnames) {
                    MaterialTheme.colorScheme.secondaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag("resolve_dns_toggle")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Dns,
                        contentDescription = "Toggle DNS IP-to-domain resolution",
                        tint = if (uiState.resolveHostnames) {
                            MaterialTheme.colorScheme.onSecondaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        modifier = Modifier.size(15.dp)
                    )
                    Text(
                        text = "DNS",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        ),
                        color = if (uiState.resolveHostnames) {
                            MaterialTheme.colorScheme.onSecondaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }
            }

            Surface(
                onClick = onToggleAutoScroll,
                shape = RoundedCornerShape(8.dp),
                color = if (uiState.autoScroll) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag("autoscroll_toggle")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Rounded.VerticalAlignBottom,
                        contentDescription = "Auto-scroll to newest packets",
                        tint = if (uiState.autoScroll) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun EmptyCaptureView(
    isCapturing: Boolean,
    hasActiveFilter: Boolean,
    totalBufferedPackets: Int,
    onStartCapture: () -> Unit,
    onOpenPcap: () -> Unit,
    onResetFilters: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(top = 4.dp, bottom = 16.dp),
        contentAlignment = Alignment.TopCenter
    ) {
        Surface(
            shape = RoundedCornerShape(18.dp),
            color = MaterialTheme.colorScheme.surfaceContainer,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (hasActiveFilter && totalBufferedPackets > 0) {
                    Icon(
                        imageVector = Icons.Rounded.Search,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp)
                    )
                    Text(
                        text = "No Packets Match Active Filter",
                        style = MaterialTheme.typography.titleMedium,
                        textAlign = TextAlign.Center
                    )
                    Text(
                        text = "$totalBufferedPackets packets captured in buffer, hidden by your current scope or display filter.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.88f),
                        textAlign = TextAlign.Center
                    )
                    Button(
                        onClick = onResetFilters,
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag("reset_filters_button")
                    ) {
                        Text("Reset Display Filters")
                    }
                } else {
                    Image(
                        painter = painterResource(id = R.drawable.img_catfish_signals_1794857518067),
                        contentDescription = "Amazon Piraíba catfish catching wireless signal waves",
                        contentScale = ContentScale.Fit,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(124.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(ConsoleBgDark)
                    )
                    Text(
                        text = if (isCapturing) "Listening on tun0 (10.1.10.1)..." else stringResource(R.string.empty_capture_title),
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Center
                    )
                    Text(
                        text = if (isCapturing) {
                            "Switch to any app or browser on your device to inspect real-time network packets as they flow through tun0."
                        } else {
                            stringResource(R.string.empty_capture_subtitle)
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.90f),
                        textAlign = TextAlign.Center
                    )
                    if (!isCapturing) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Button(
                                onClick = onStartCapture,
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("empty_start_capture_button")
                            ) {
                                Icon(Icons.Rounded.PlayArrow, contentDescription = null)
                                Spacer(Modifier.width(6.dp))
                                Text("Start Capture")
                            }
                            OutlinedButton(
                                onClick = onOpenPcap,
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("empty_open_pcap_button")
                            ) {
                                Icon(Icons.Rounded.FolderOpen, contentDescription = null)
                                Spacer(Modifier.width(6.dp))
                                Text("Open .pcap")
                            }
                        }
                    }
                }
            }
        }
    }
}
