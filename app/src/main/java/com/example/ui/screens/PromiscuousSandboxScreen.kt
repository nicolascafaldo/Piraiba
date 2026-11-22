package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.VerticalAlignBottom
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material.icons.rounded.WifiTethering
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.dissector.DisplayFilterParser
import com.example.model.CapturedPacket
import com.example.model.QuickFilter
import com.example.model.ResolvedHost
import com.example.model.RootSandboxState
import com.example.model.RootSandboxStatus
import com.example.ui.components.PacketRowCard
import com.example.ui.theme.AmberAlert
import com.example.ui.theme.ConsoleBgDark
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive
import com.example.viewmodel.SandboxUiState

@Composable
fun PromiscuousSandboxScreen(
    uiState: SandboxUiState,
    onFilterQueryChange: (String) -> Unit,
    onQuickFilterSelected: (QuickFilter) -> Unit,
    onToggleAutoScroll: () -> Unit,
    onToggleResolveHostnames: () -> Unit,
    onToggleLanMulticast: () -> Unit,
    onProbeRoot: () -> Unit,
    onSelectInterface: (String) -> Unit,
    onBpfFilterChange: (String) -> Unit,
    onTogglePromiscuousMode: (Boolean) -> Unit,
    onStartRootCapture: () -> Unit,
    onStopRootCapture: () -> Unit,
    onSelectPacket: (CapturedPacket) -> Unit,
    modifier: Modifier = Modifier
) {
    var showSearchDialog by remember { mutableStateOf(false) }
    var setupExpanded by rememberSaveable { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val hasQuery = uiState.filterQuery.isNotBlank()

    LaunchedEffect(uiState.packets.size, uiState.autoScroll) {
        if (uiState.autoScroll && uiState.packets.isNotEmpty()) {
            listState.scrollToItem(uiState.packets.lastIndex)
        }
    }

    if (showSearchDialog) {
        SandboxSearchDialog(
            initialQuery = uiState.filterQuery,
            resolvedDomains = uiState.resolvedDomains,
            onApply = { query ->
                onFilterQueryChange(query)
                showSearchDialog = false
            },
            onDismiss = { showSearchDialog = false }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(start = 12.dp, end = 12.dp, top = 12.dp)
            .testTag("promiscuous_sandbox_screen")
    ) {
        SandboxControlHeader(
            uiState = uiState,
            setupExpanded = setupExpanded,
            hasActiveSearch = hasQuery,
            onOpenSearch = { showSearchDialog = true },
            onToggleExpand = { setupExpanded = !setupExpanded },
            onToggleAutoScroll = onToggleAutoScroll,
            onToggleResolveHostnames = onToggleResolveHostnames,
            onToggleLanMulticast = onToggleLanMulticast,
            onProbeRoot = onProbeRoot,
            onSelectInterface = onSelectInterface,
            onBpfFilterChange = onBpfFilterChange,
            onTogglePromiscuousMode = onTogglePromiscuousMode,
            onStartRootCapture = onStartRootCapture,
            onStopRootCapture = onStopRootCapture
        )

        if (hasQuery) {
            Spacer(modifier = Modifier.height(8.dp))
            ActiveSandboxFilterBanner(
                query = uiState.filterQuery,
                isValidExpression = uiState.filterValidation.isValid,
                onEdit = { showSearchDialog = true },
                onClear = { onFilterQueryChange("") }
            )
        }

        Spacer(modifier = Modifier.height(6.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(vertical = 4.dp),
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
                        selectedContainerColor = WarmGoldLive.copy(alpha = 0.22f),
                        selectedLabelColor = WarmGoldLive
                    ),
                    modifier = Modifier.testTag("sandbox_quick_filter_${filter.name.lowercase()}")
                )
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        if (uiState.packets.isEmpty()) {
            EmptySandboxView(
                hasActiveFilter = hasQuery || uiState.quickFilter != QuickFilter.ALL,
                totalLanFrames = uiState.totalBufferedLanPackets,
                lanMulticastEnabled = uiState.lanMulticastEnabled,
                rootStatus = uiState.rootSandboxState.status,
                onEnableLanMulticast = onToggleLanMulticast,
                onProbeRoot = onProbeRoot,
                onResetFilters = {
                    onFilterQueryChange("")
                    onQuickFilterSelected(QuickFilter.ALL)
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
                    .testTag("sandbox_packet_list")
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
private fun ActiveSandboxFilterBanner(
    query: String,
    isValidExpression: Boolean,
    onEdit: () -> Unit,
    onClear: () -> Unit
) {
    Surface(
        onClick = onEdit,
        shape = RoundedCornerShape(10.dp),
        color = if (isValidExpression) WarmGoldLive.copy(alpha = 0.14f) else AmberAlert.copy(alpha = 0.14f),
        border = BorderStroke(
            1.dp,
            if (isValidExpression) WarmGoldLive.copy(alpha = 0.5f) else AmberAlert.copy(alpha = 0.5f)
        ),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag("sandbox_active_filter_banner")
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(
                imageVector = Icons.Rounded.Search,
                contentDescription = null,
                tint = if (isValidExpression) WarmGoldLive else AmberAlert,
                modifier = Modifier.size(16.dp)
            )
            Text(
                text = "Search: $query",
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Medium
                ),
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            IconButton(
                onClick = onClear,
                modifier = Modifier.testTag("sandbox_clear_active_filter_button")
            ) {
                Icon(
                    imageVector = Icons.Rounded.Clear,
                    contentDescription = "Clear active search filter"
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SandboxSearchDialog(
    initialQuery: String,
    resolvedDomains: Map<String, ResolvedHost>,
    onApply: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var draftQuery by remember(initialQuery) { mutableStateOf(initialQuery) }
    val focusManager = LocalFocusManager.current
    val validation = remember(draftQuery, resolvedDomains) {
        DisplayFilterParser.parse(draftQuery, QuickFilter.ALL, resolvedDomains)
    }
    val hasDraft = draftQuery.isNotBlank()
    val presets = remember {
        listOf(
            "mdns",
            "ssdp",
            "arp",
            "dns",
            "udp.port == 5353",
            "udp.port == 1900",
            "tcp && !tls",
            "dns.resolved contains local"
        )
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier
                .fillMaxWidth(0.92f)
                .widthIn(max = 520.dp)
                .testTag("sandbox_search_dialog")
        ) {
            Column(
                modifier = Modifier
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
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
                            imageVector = Icons.Rounded.Search,
                            contentDescription = null,
                            tint = WarmGoldLive
                        )
                        Text(
                            text = "Search Sandbox Traffic",
                            style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = "Close search dialog"
                        )
                    }
                }

                OutlinedTextField(
                    value = draftQuery,
                    onValueChange = { draftQuery = it },
                    minLines = 2,
                    maxLines = 4,
                    label = { Text("Display filter or keyword") },
                    placeholder = {
                        Text(
                            text = "e.g. mdns, port == 5353, ip.addr == 192.168.1.1, or payload text",
                            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily)
                        )
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = when {
                                !hasDraft -> Icons.Rounded.Search
                                validation.isValid -> Icons.Rounded.CheckCircle
                                else -> Icons.Rounded.WarningAmber
                            },
                            contentDescription = null,
                            tint = when {
                                !hasDraft -> MaterialTheme.colorScheme.onSurfaceVariant
                                validation.isValid -> WarmGoldLive
                                else -> AmberAlert
                            }
                        )
                    },
                    trailingIcon = {
                        if (hasDraft) {
                            IconButton(
                                onClick = { draftQuery = "" },
                                modifier = Modifier.testTag("sandbox_dialog_clear_input")
                            ) {
                                Icon(Icons.Rounded.Clear, contentDescription = "Clear query")
                            }
                        }
                    },
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(
                        onSearch = {
                            focusManager.clearFocus()
                            onApply(draftQuery.trim())
                        }
                    ),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = if (hasDraft && validation.isValid) WarmGoldLive else MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
                        focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow
                    ),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("sandbox_dialog_filter_input")
                )

                Text(
                    text = when {
                        !hasDraft -> "Matches hostnames, resolved IPs, packet summaries, decoded payloads, or boolean expressions (&&, ||, !)."
                        validation.isValid -> "Valid filter expression ready to apply."
                        else -> "${validation.errorHint ?: "Custom keyword"} — matches hosts, domains & payloads as text."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (hasDraft && !validation.isValid) AmberAlert else MaterialTheme.colorScheme.onSurfaceVariant
                )

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

                Text(
                    text = "Quick Filter Expressions",
                    style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold),
                    color = MaterialTheme.colorScheme.onSurface
                )

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    presets.forEach { preset ->
                        SuggestionChip(
                            onClick = { draftQuery = preset },
                            label = {
                                Text(
                                    text = preset,
                                    style = MaterialTheme.typography.labelMedium.copy(fontFamily = MonoFontFamily)
                                )
                            }
                        )
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (initialQuery.isNotBlank() || draftQuery.isNotBlank()) {
                        TextButton(
                            onClick = { onApply("") },
                            modifier = Modifier.heightIn(min = 48.dp)
                        ) {
                            Text("Reset")
                        }
                    }
                    TextButton(
                        onClick = onDismiss,
                        modifier = Modifier.heightIn(min = 48.dp)
                    ) {
                        Text("Cancel")
                    }
                    Spacer(Modifier.width(8.dp))
                    Button(
                        onClick = { onApply(draftQuery.trim()) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = WarmGoldLive,
                            contentColor = ConsoleBgDark
                        ),
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag("sandbox_dialog_apply_button")
                    ) {
                        Icon(Icons.Rounded.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Apply")
                    }
                }
            }
        }
    }
}

@Composable
private fun SandboxControlHeader(
    uiState: SandboxUiState,
    setupExpanded: Boolean,
    hasActiveSearch: Boolean,
    onOpenSearch: () -> Unit,
    onToggleExpand: () -> Unit,
    onToggleAutoScroll: () -> Unit,
    onToggleResolveHostnames: () -> Unit,
    onToggleLanMulticast: () -> Unit,
    onProbeRoot: () -> Unit,
    onSelectInterface: (String) -> Unit,
    onBpfFilterChange: (String) -> Unit,
    onTogglePromiscuousMode: (Boolean) -> Unit,
    onStartRootCapture: () -> Unit,
    onStopRootCapture: () -> Unit
) {
    val sandboxState = uiState.rootSandboxState
    val isRootRunning = sandboxState.status == RootSandboxStatus.ROOT_RUNNING
    val isChecking = sandboxState.status == RootSandboxStatus.CHECKING
    val rootReady = sandboxState.suAvailable && sandboxState.tcpdumpPath != null
    val anyActive = isRootRunning || uiState.lanMulticastActive

    val statusColor = when {
        isRootRunning || sandboxState.status == RootSandboxStatus.ROOT_READY -> WarmGoldLive
        uiState.lanMulticastActive -> WarmGoldLive
        isChecking -> MaterialTheme.colorScheme.secondary
        sandboxState.status == RootSandboxStatus.NO_ROOT_OR_DENIED ||
            sandboxState.status == RootSandboxStatus.NO_TCPDUMP -> AmberAlert
        sandboxState.status == RootSandboxStatus.ERROR -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(
            1.dp,
            if (anyActive) WarmGoldLive.copy(alpha = 0.55f) else MaterialTheme.colorScheme.outlineVariant
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Rounded.Terminal,
                    contentDescription = null,
                    tint = if (anyActive) WarmGoldLive else MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .clip(CircleShape)
                                .background(statusColor)
                        )
                        Text(
                            text = if (isRootRunning) {
                                "Root Promiscuous: ${sandboxState.selectedInterface}"
                            } else {
                                "Promiscuous Sandbox"
                            },
                            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        text = "${uiState.packets.size} shown • ${uiState.totalBufferedLanPackets} LAN • ${sandboxState.status.label}",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Surface(
                    onClick = onToggleExpand,
                    shape = RoundedCornerShape(8.dp),
                    color = if (setupExpanded) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    },
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag("sandbox_toggle_setup_button")
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Tune,
                            contentDescription = null,
                            tint = if (setupExpanded) {
                                MaterialTheme.colorScheme.onPrimaryContainer
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Setup",
                            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                            color = if (setupExpanded) {
                                MaterialTheme.colorScheme.onPrimaryContainer
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            }
                        )
                        Icon(
                            imageVector = if (setupExpanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                            contentDescription = if (setupExpanded) "Collapse sandbox setup" else "Expand sandbox setup",
                            tint = if (setupExpanded) {
                                MaterialTheme.colorScheme.onPrimaryContainer
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }

            // Capture action row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = uiState.lanMulticastEnabled,
                    onClick = onToggleLanMulticast,
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Rounded.WifiTethering,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    label = {
                        Text(
                            text = if (uiState.lanMulticastEnabled) "Multicast ON" else "Multicast",
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = WarmGoldLive.copy(alpha = 0.22f),
                        selectedLabelColor = WarmGoldLive,
                        selectedLeadingIconColor = WarmGoldLive
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("sandbox_multicast_toggle")
                )

                Button(
                    onClick = when {
                        isRootRunning -> onStopRootCapture
                        rootReady -> onStartRootCapture
                        else -> onProbeRoot
                    },
                    enabled = !isChecking,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = when {
                            isRootRunning -> MaterialTheme.colorScheme.error
                            rootReady -> WarmGoldLive
                            else -> MaterialTheme.colorScheme.primaryContainer
                        },
                        contentColor = when {
                            isRootRunning -> MaterialTheme.colorScheme.onError
                            rootReady -> ConsoleBgDark
                            else -> MaterialTheme.colorScheme.onPrimaryContainer
                        }
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("sandbox_root_action_button")
                ) {
                    Icon(
                        imageVector = when {
                            isRootRunning -> Icons.Rounded.Stop
                            rootReady -> Icons.Rounded.PlayArrow
                            else -> Icons.Rounded.Refresh
                        },
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        text = when {
                            isRootRunning -> "Stop Root"
                            rootReady -> "Start Root"
                            isChecking -> "Checking..."
                            else -> "Check Root"
                        },
                        style = MaterialTheme.typography.labelMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            // Utility toolbar row: Pop-out Search, DNS resolution, Auto-scroll
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    onClick = onOpenSearch,
                    shape = RoundedCornerShape(8.dp),
                    color = if (hasActiveSearch) {
                        WarmGoldLive.copy(alpha = 0.22f)
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    },
                    border = if (hasActiveSearch) {
                        BorderStroke(1.dp, WarmGoldLive.copy(alpha = 0.6f))
                    } else null,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("sandbox_open_search_button")
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Search,
                            contentDescription = "Open sandbox search and filter",
                            tint = if (hasActiveSearch) WarmGoldLive else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(5.dp))
                        Text(
                            text = if (hasActiveSearch) "Filtered" else "Search",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = if (hasActiveSearch) WarmGoldLive else MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                }

                Surface(
                    onClick = onToggleResolveHostnames,
                    shape = RoundedCornerShape(8.dp),
                    color = if (uiState.resolveHostnames) {
                        MaterialTheme.colorScheme.secondaryContainer
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("sandbox_resolve_dns_toggle")
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Dns,
                            contentDescription = "Toggle DNS name resolution",
                            tint = if (uiState.resolveHostnames) {
                                MaterialTheme.colorScheme.onSecondaryContainer
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(5.dp))
                        Text(
                            text = if (uiState.resolveHostnames) "DNS ON" else "DNS OFF",
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            ),
                            color = if (uiState.resolveHostnames) {
                                MaterialTheme.colorScheme.onSecondaryContainer
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            maxLines = 1
                        )
                    }
                }

                Surface(
                    onClick = onToggleAutoScroll,
                    shape = RoundedCornerShape(8.dp),
                    color = if (uiState.autoScroll) {
                        WarmGoldLive.copy(alpha = 0.22f)
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("sandbox_autoscroll_toggle")
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.VerticalAlignBottom,
                            contentDescription = "Auto-scroll sandbox packets",
                            tint = if (uiState.autoScroll) WarmGoldLive else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(5.dp))
                        Text(
                            text = "Auto",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                            color = if (uiState.autoScroll) WarmGoldLive else MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                }
            }

            AnimatedVisibility(visible = setupExpanded) {
                RootSandboxDetailsPanel(
                    sandboxState = sandboxState,
                    isRootRunning = isRootRunning,
                    isChecking = isChecking,
                    statusColor = statusColor,
                    onProbeRoot = onProbeRoot,
                    onSelectInterface = onSelectInterface,
                    onBpfFilterChange = onBpfFilterChange,
                    onTogglePromiscuousMode = onTogglePromiscuousMode
                )
            }
        }
    }
}

@Composable
private fun RootSandboxDetailsPanel(
    sandboxState: RootSandboxState,
    isRootRunning: Boolean,
    isChecking: Boolean,
    statusColor: Color,
    onProbeRoot: () -> Unit,
    onSelectInterface: (String) -> Unit,
    onBpfFilterChange: (String) -> Unit,
    onTogglePromiscuousMode: (Boolean) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 280.dp)
            .verticalScroll(rememberScrollState())
            .padding(top = 6.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Surface(
            shape = RoundedCornerShape(10.dp),
            color = MaterialTheme.colorScheme.surfaceContainerLow,
            border = BorderStroke(1.dp, statusColor.copy(alpha = 0.45f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = sandboxState.statusDetail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f)
                    )
                    if (!isRootRunning && !isChecking) {
                        Spacer(Modifier.width(8.dp))
                        OutlinedButton(
                            onClick = onProbeRoot,
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                            modifier = Modifier
                                .heightIn(min = 48.dp)
                                .testTag("sandbox_recheck_root_button")
                        ) {
                            Text("Re-check", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }

                if (sandboxState.status == RootSandboxStatus.NO_ROOT_OR_DENIED ||
                    sandboxState.status == RootSandboxStatus.UNCHECKED
                ) {
                    Row(
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Security,
                            contentDescription = null,
                            tint = AmberAlert,
                            modifier = Modifier
                                .padding(top = 2.dp)
                                .size(14.dp)
                        )
                        Text(
                            text = "Raw wlan0 hardware promiscuous sniffing requires root (su + tcpdump). Non-rooted Android blocks UID 0 / CAP_NET_RAW, while Multicast Listen still captures mDNS, SSDP, LLMNR & WSD broadcasts.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "NIC:",
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            sandboxState.availableInterfaces.forEach { iface ->
                val selected = sandboxState.selectedInterface == iface
                FilterChip(
                    selected = selected,
                    enabled = !isRootRunning,
                    onClick = { onSelectInterface(iface) },
                    label = {
                        Text(
                            text = iface,
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily)
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = WarmGoldLive.copy(alpha = 0.2f),
                        selectedLabelColor = WarmGoldLive
                    )
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Hardware Promiscuous Flag (IFF_PROMISC)",
                    style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium)
                )
                Text(
                    text = "Omit -p so tcpdump captures all frames visible to NIC",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = sandboxState.promiscuousMode,
                enabled = !isRootRunning,
                onCheckedChange = onTogglePromiscuousMode,
                modifier = Modifier.testTag("root_promiscuous_switch")
            )
        }

        OutlinedTextField(
            value = sandboxState.bpfFilter,
            onValueChange = onBpfFilterChange,
            enabled = !isRootRunning,
            singleLine = true,
            label = { Text("tcpdump BPF Filter (optional)") },
            placeholder = { Text("e.g. not port 5555 and (arp or udp or tcp)") },
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 2.dp)
                .testTag("root_bpf_input")
        )

        Surface(
            shape = RoundedCornerShape(10.dp),
            color = ConsoleBgDark,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 64.dp, max = 110.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(8.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                val logs = if (sandboxState.consoleLogs.isEmpty()) {
                    listOf("[sandbox] Ready. Tap Check Root to inspect su + tcpdump availability.")
                } else {
                    sandboxState.consoleLogs
                }
                logs.forEach { line ->
                    Text(
                        text = line,
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.88f)
                    )
                }
            }
        }
    }
}

@Composable
private fun EmptySandboxView(
    hasActiveFilter: Boolean,
    totalLanFrames: Int,
    lanMulticastEnabled: Boolean,
    rootStatus: RootSandboxStatus,
    onEnableLanMulticast: () -> Unit,
    onProbeRoot: () -> Unit,
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
                if (hasActiveFilter && totalLanFrames > 0) {
                    Icon(
                        imageVector = Icons.Rounded.Search,
                        contentDescription = null,
                        tint = WarmGoldLive,
                        modifier = Modifier.size(40.dp)
                    )
                    Text(
                        text = "No LAN Frames Match Filter",
                        style = MaterialTheme.typography.titleMedium,
                        textAlign = TextAlign.Center
                    )
                    Text(
                        text = "$totalLanFrames LAN promiscuous frames buffered, hidden by your current filter.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                    Button(
                        onClick = onResetFilters,
                        modifier = Modifier.heightIn(min = 48.dp)
                    ) {
                        Text("Reset Sandbox Filter")
                    }
                } else {
                    Icon(
                        imageVector = Icons.Rounded.WifiTethering,
                        contentDescription = null,
                        tint = WarmGoldLive,
                        modifier = Modifier.size(44.dp)
                    )
                    Text(
                        text = "Isolated Promiscuous Sandbox",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        textAlign = TextAlign.Center
                    )
                    Text(
                        text = "LAN frames captured via root tcpdump or Wi-Fi Multicast (mDNS, SSDP, LLMNR, WS-Discovery) live here—completely separate from your Phone's tun0 traffic.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                    if (!lanMulticastEnabled) {
                        Button(
                            onClick = onEnableLanMulticast,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = WarmGoldLive,
                                contentColor = ConsoleBgDark
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .testTag("sandbox_empty_enable_multicast_button")
                        ) {
                            Icon(Icons.Rounded.WifiTethering, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Enable LAN Multicast Listen")
                        }
                    }
                    if (rootStatus == RootSandboxStatus.UNCHECKED) {
                        OutlinedButton(
                            onClick = onProbeRoot,
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .testTag("sandbox_empty_check_root_button")
                        ) {
                            Text("Check Root Access", maxLines = 1)
                        }
                    }
                }
            }
        }
    }
}
