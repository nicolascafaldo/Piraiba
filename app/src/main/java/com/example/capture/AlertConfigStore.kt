package com.example.capture

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.MainActivity
import com.example.R
import com.example.model.AlertThresholdConfig
import com.example.model.NetworkAlertEvent
import com.example.model.PortMonitorMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.alertConfigDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "wiretrace_alert_config"
)

/**
 * Persists user-configured network alert thresholds using Jetpack DataStore Preferences.
 */
object AlertConfigStore {

    private val KEY_ALERTS_ENABLED = booleanPreferencesKey("alerts_enabled")
    private val KEY_HIGH_LATENCY_ENABLED = booleanPreferencesKey("high_latency_enabled")
    private val KEY_MAX_LATENCY_MS = intPreferencesKey("max_latency_ms")
    private val KEY_UNAUTH_PORT_ENABLED = booleanPreferencesKey("unauth_port_enabled")
    private val KEY_PORT_MONITOR_MODE = stringPreferencesKey("port_monitor_mode")
    private val KEY_FLAGGED_PORTS = stringPreferencesKey("flagged_ports")
    private val KEY_ALLOWED_PORTS = stringPreferencesKey("allowed_ports")
    private val KEY_DATA_SPIKE_ENABLED = booleanPreferencesKey("data_spike_enabled")
    private val KEY_MAX_BYTES_PER_SEC_KB = intPreferencesKey("max_bytes_per_sec_kb")
    private val KEY_MAX_PACKETS_PER_SEC = intPreferencesKey("max_packets_per_sec")
    private val KEY_NOTIFY_SYSTEM_BAR = booleanPreferencesKey("notify_system_bar")
    private val KEY_VPN_DISCLOSURE_ACCEPTED = booleanPreferencesKey("vpn_disclosure_accepted")

    fun observeConfig(context: Context): Flow<AlertThresholdConfig> =
        context.applicationContext.alertConfigDataStore.data.map { prefs ->
            AlertThresholdConfig(
                alertsEnabled = prefs[KEY_ALERTS_ENABLED] ?: true,
                highLatencyEnabled = prefs[KEY_HIGH_LATENCY_ENABLED] ?: true,
                maxLatencyMs = (prefs[KEY_MAX_LATENCY_MS] ?: 250).coerceIn(10, 10_000),
                unauthorizedPortEnabled = prefs[KEY_UNAUTH_PORT_ENABLED] ?: true,
                portMonitorMode = prefs[KEY_PORT_MONITOR_MODE]?.let { name ->
                    PortMonitorMode.entries.find { it.name == name }
                } ?: PortMonitorMode.WATCHED_PORTS,
                flaggedPorts = prefs[KEY_FLAGGED_PORTS]?.let(::decodePorts)
                    ?: AlertThresholdConfig.DEFAULT_FLAGGED_PORTS,
                allowedPorts = prefs[KEY_ALLOWED_PORTS]?.let(::decodePorts)
                    ?: AlertThresholdConfig.DEFAULT_ALLOWED_PORTS,
                dataSpikeEnabled = prefs[KEY_DATA_SPIKE_ENABLED] ?: true,
                maxBytesPerSecKB = (prefs[KEY_MAX_BYTES_PER_SEC_KB] ?: 512).coerceIn(16, 100_000),
                maxPacketsPerSec = (prefs[KEY_MAX_PACKETS_PER_SEC] ?: 150).coerceIn(10, 50_000),
                notifySystemBar = prefs[KEY_NOTIFY_SYSTEM_BAR] ?: false
            )
        }

    suspend fun saveConfig(context: Context, config: AlertThresholdConfig) {
        context.applicationContext.alertConfigDataStore.edit { prefs ->
            prefs[KEY_ALERTS_ENABLED] = config.alertsEnabled
            prefs[KEY_HIGH_LATENCY_ENABLED] = config.highLatencyEnabled
            prefs[KEY_MAX_LATENCY_MS] = config.maxLatencyMs
            prefs[KEY_UNAUTH_PORT_ENABLED] = config.unauthorizedPortEnabled
            prefs[KEY_PORT_MONITOR_MODE] = config.portMonitorMode.name
            prefs[KEY_FLAGGED_PORTS] = encodePorts(config.flaggedPorts)
            prefs[KEY_ALLOWED_PORTS] = encodePorts(config.allowedPorts)
            prefs[KEY_DATA_SPIKE_ENABLED] = config.dataSpikeEnabled
            prefs[KEY_MAX_BYTES_PER_SEC_KB] = config.maxBytesPerSecKB
            prefs[KEY_MAX_PACKETS_PER_SEC] = config.maxPacketsPerSec
            prefs[KEY_NOTIFY_SYSTEM_BAR] = config.notifySystemBar
        }
    }

    fun observeVpnDisclosureAccepted(context: Context): Flow<Boolean> =
        context.applicationContext.alertConfigDataStore.data.map { prefs ->
            prefs[KEY_VPN_DISCLOSURE_ACCEPTED] ?: false
        }

    suspend fun setVpnDisclosureAccepted(context: Context, accepted: Boolean) {
        context.applicationContext.alertConfigDataStore.edit { prefs ->
            prefs[KEY_VPN_DISCLOSURE_ACCEPTED] = accepted
        }
    }

    internal fun encodePorts(ports: Set<Int>): String =
        ports.sorted().joinToString(",")

    internal fun decodePorts(raw: String): Set<Int> {
        if (raw.isBlank()) return emptySet()
        return raw.split(',')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }
            .toSet()
    }

    private const val ALERT_CHANNEL_ID = "wiretrace_threshold_alerts"

    fun showAlertNotification(context: Context, event: NetworkAlertEvent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return
        }
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                ALERT_CHANNEL_ID,
                "Network Threshold Alerts",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Alerts triggered for high latency, unauthorized ports, or data spikes"
            }
            manager.createNotificationChannel(channel)
        }
        val launchIntent = PendingIntent.getActivity(
            context,
            event.id.toInt(),
            Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_piraiba)
            .setContentTitle("${event.category.label}: ${event.title}")
            .setContentText(event.detail)
            .setAutoCancel(true)
            .setContentIntent(launchIntent)
            .build()
        manager.notify(2000 + (event.id % 50).toInt(), notification)
    }
}
