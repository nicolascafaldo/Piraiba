package com.example

import com.example.capture.CaptureRepository
import com.example.capture.DnsResolutionCache
import com.example.dissector.PacketDissector
import com.example.model.AlertCategory
import com.example.model.AlertSeverity
import com.example.model.CaptureSource
import com.example.model.LinkLayerType
import com.example.model.NetworkAlertEvent
import com.example.model.PacketDirection
import com.example.model.QuickFilter
import com.example.model.TrafficScopeFilter
import com.example.viewmodel.WireTraceViewModel
import com.example.vpn.PacketChecksumUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class WireTraceViewModelTest {

    private val mainDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(mainDispatcher)
        DnsResolutionCache.setAutoPtrEnabled(false)
        CaptureRepository.clearCapture()
    }

    @After
    fun tearDown() {
        CaptureRepository.clearCapture()
        DnsResolutionCache.setAutoPtrEnabled(false)
        Dispatchers.resetMain()
    }

    @Test
    fun uiStateAndSandboxUiStateIsolatePhoneAndLanTrafficByDefault() = runBlocking {
        val viewModel = WireTraceViewModel()
        val uiCollector = launch(mainDispatcher) { viewModel.uiState.collect {} }
        val sandboxCollector = launch(mainDispatcher) { viewModel.sandboxUiState.collect {} }
        try {
            val phoneRaw = buildIpv4Udp(
                srcIp = byteArrayOf(10, 0, 0, 2),
                dstIp = byteArrayOf(93, 184.toByte(), 215.toByte(), 14),
                srcPort = 51111,
                dstPort = 443
            )
            val lanRaw = buildIpv4Udp(
                srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 50),
                dstIp = byteArrayOf(224.toByte(), 0, 0, 251.toByte()),
                srcPort = 5353,
                dstPort = 5353
            )
            val phonePkt = PacketDissector.dissect(
                id = 1L,
                rawBytes = phoneRaw,
                timestampMs = 1_700_000_000_000L,
                relativeTimeMs = 0L,
                direction = PacketDirection.OUTBOUND,
                linkLayerType = LinkLayerType.RAW_TUN,
                captureSource = CaptureSource.DEVICE_VPN
            )
            val lanPkt = PacketDissector.dissect(
                id = 2L,
                rawBytes = lanRaw,
                timestampMs = 1_700_000_000_100L,
                relativeTimeMs = 100L,
                direction = PacketDirection.INBOUND,
                linkLayerType = LinkLayerType.RAW_TUN,
                captureSource = CaptureSource.LAN_PROMISCUOUS
            )
            CaptureRepository.replaceWithImportedPackets(listOf(phonePkt, lanPkt))

            val defaultUi = withTimeout(3_000) {
                viewModel.uiState.first {
                    it.phonePacketCount == 1 && it.lanBufferedPacketCount == 1 && it.packets.size == 1
                }
            }
            assertEquals(TrafficScopeFilter.PHONE_ONLY, defaultUi.trafficScopeFilter)
            assertEquals(CaptureSource.DEVICE_VPN, defaultUi.packets.single().captureSource)

            val sandbox = withTimeout(3_000) {
                viewModel.sandboxUiState.first {
                    it.totalBufferedLanPackets == 1 && it.packets.size == 1
                }
            }
            assertEquals(CaptureSource.LAN_PROMISCUOUS, sandbox.packets.single().captureSource)

            viewModel.setTrafficScopeFilter(TrafficScopeFilter.ALL)
            val allUi = withTimeout(3_000) {
                viewModel.uiState.first {
                    it.trafficScopeFilter == TrafficScopeFilter.ALL && it.packets.size == 2
                }
            }
            assertEquals(2, allUi.packets.size)

            viewModel.setTrafficScopeFilter(TrafficScopeFilter.LAN_ONLY)
            val lanUi = withTimeout(3_000) {
                viewModel.uiState.first {
                    it.trafficScopeFilter == TrafficScopeFilter.LAN_ONLY && it.packets.size == 1
                }
            }
            assertEquals(CaptureSource.LAN_PROMISCUOUS, lanUi.packets.single().captureSource)
        } finally {
            uiCollector.cancel()
            sandboxCollector.cancel()
        }
    }

    @Test
    fun filterToStreamRoutesPhoneAndLanStreamsToMatchingTabFilters() = runBlocking {
        val viewModel = WireTraceViewModel()
        val uiCollector = launch(mainDispatcher) { viewModel.uiState.collect {} }
        val sandboxCollector = launch(mainDispatcher) { viewModel.sandboxUiState.collect {} }
        val convCollector = launch(mainDispatcher) { viewModel.conversations.collect {} }
        try {
            val phoneA = PacketDissector.dissect(
                id = 10L,
                rawBytes = buildIpv4Udp(
                    srcIp = byteArrayOf(10, 0, 0, 2),
                    dstIp = byteArrayOf(8, 8, 8, 8),
                    srcPort = 41000,
                    dstPort = 53
                ),
                timestampMs = 1_700_000_001_000L,
                relativeTimeMs = 0L,
                direction = PacketDirection.OUTBOUND,
                captureSource = CaptureSource.DEVICE_VPN
            )
            val phoneB = PacketDissector.dissect(
                id = 11L,
                rawBytes = buildIpv4Udp(
                    srcIp = byteArrayOf(10, 0, 0, 2),
                    dstIp = byteArrayOf(1, 1, 1, 1),
                    srcPort = 41001,
                    dstPort = 443
                ),
                timestampMs = 1_700_000_001_010L,
                relativeTimeMs = 10L,
                direction = PacketDirection.OUTBOUND,
                captureSource = CaptureSource.DEVICE_VPN
            )
            val lanA = PacketDissector.dissect(
                id = 12L,
                rawBytes = buildIpv4Udp(
                    srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 30),
                    dstIp = byteArrayOf(224.toByte(), 0, 0, 251.toByte()),
                    srcPort = 5353,
                    dstPort = 5353
                ),
                timestampMs = 1_700_000_001_020L,
                relativeTimeMs = 20L,
                direction = PacketDirection.INBOUND,
                captureSource = CaptureSource.LAN_PROMISCUOUS
            )
            val lanB = PacketDissector.dissect(
                id = 13L,
                rawBytes = buildIpv4Udp(
                    srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 40),
                    dstIp = byteArrayOf(239.toByte(), 255.toByte(), 255.toByte(), 250.toByte()),
                    srcPort = 49999,
                    dstPort = 1900
                ),
                timestampMs = 1_700_000_001_030L,
                relativeTimeMs = 30L,
                direction = PacketDirection.INBOUND,
                captureSource = CaptureSource.LAN_PROMISCUOUS
            )
            CaptureRepository.replaceWithImportedPackets(listOf(phoneA, phoneB, lanA, lanB))

            val streams = withTimeout(3_000) {
                viewModel.conversations.first { it.size == 4 }
            }
            val phoneStream = streams.first {
                it.captureSource == CaptureSource.DEVICE_VPN && it.remoteIp == "8.8.8.8"
            }
            val lanStream = streams.first {
                it.captureSource == CaptureSource.LAN_PROMISCUOUS && it.remoteIp == "192.168.1.40"
            }

            // First ensure sandbox has a non-empty filter so we can verify phone stream routing leaves it intact,
            // and vice versa.
            viewModel.setTrafficScopeFilter(TrafficScopeFilter.ALL)
            viewModel.filterToStream(phoneStream)
            val phoneUi = withTimeout(3_000) {
                viewModel.uiState.first {
                    it.filterQuery == "ip.addr == 8.8.8.8 && port == 53" && it.packets.size == 1
                }
            }
            assertEquals(QuickFilter.ALL, phoneUi.quickFilter)
            assertEquals(TrafficScopeFilter.PHONE_ONLY, phoneUi.trafficScopeFilter)
            assertEquals("8.8.8.8", phoneUi.packets.single().dstIp)
            assertTrue(viewModel.sandboxUiState.value.filterQuery.isEmpty())

            viewModel.filterToStream(lanStream)
            val lanSandbox = withTimeout(3_000) {
                viewModel.sandboxUiState.first {
                    it.filterQuery == "ip.addr == 192.168.1.40 && port == 49999" && it.packets.size == 1
                }
            }
            assertEquals(QuickFilter.ALL, lanSandbox.quickFilter)
            assertEquals("192.168.1.40", lanSandbox.packets.single().srcIp)
            assertEquals("ip.addr == 8.8.8.8 && port == 53", viewModel.uiState.value.filterQuery)
        } finally {
            uiCollector.cancel()
            sandboxCollector.cancel()
            convCollector.cancel()
        }
    }

    @Test
    fun applyAlertInspectionRoutesLanAlertsToSandboxAndPhoneAlertsToPhoneScope() = runBlocking {
        val viewModel = WireTraceViewModel()
        val uiCollector = launch(mainDispatcher) { viewModel.uiState.collect {} }
        val sandboxCollector = launch(mainDispatcher) { viewModel.sandboxUiState.collect {} }
        try {
            val lanPkt = PacketDissector.dissect(
                id = 1L,
                rawBytes = buildIpv4Udp(
                    srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 77),
                    dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
                    srcPort = 51000,
                    dstPort = 23
                ),
                timestampMs = 1_700_000_002_000L,
                relativeTimeMs = 0L,
                direction = PacketDirection.INBOUND,
                captureSource = CaptureSource.LAN_PROMISCUOUS
            )
            val phonePkt = PacketDissector.dissect(
                id = 2L,
                rawBytes = buildIpv4Udp(
                    srcIp = byteArrayOf(10, 0, 0, 2),
                    dstIp = byteArrayOf(9, 9, 9, 9),
                    srcPort = 52000,
                    dstPort = 22
                ),
                timestampMs = 1_700_000_002_100L,
                relativeTimeMs = 100L,
                direction = PacketDirection.OUTBOUND,
                captureSource = CaptureSource.DEVICE_VPN
            )
            val retained = CaptureRepository.replaceWithImportedPackets(listOf(lanPkt, phonePkt))
            val retainedLan = retained[0]
            val retainedPhone = retained[1]

            // Seed quick/scope filters with non-defaults to prove inspection resets cleanly
            viewModel.setSandboxQuickFilter(QuickFilter.TCP)
            val isLanRoute = viewModel.applyAlertInspection(
                NetworkAlertEvent(
                    id = 10L,
                    timestampMs = 1_700_000_002_000L,
                    category = AlertCategory.UNAUTHORIZED_PORT,
                    severity = AlertSeverity.CRITICAL,
                    title = "Unauthorized Port (:23)",
                    detail = "LAN telnet",
                    packetId = retainedLan.id,
                    filterExpr = "ip.addr == 192.168.1.77 && port == 23",
                    captureSource = CaptureSource.LAN_PROMISCUOUS
                )
            )
            assertTrue(isLanRoute)
            val sandboxState = withTimeout(3_000) {
                viewModel.sandboxUiState.first {
                    it.filterQuery == "ip.addr == 192.168.1.77 && port == 23" &&
                        it.selectedPacketId == retainedLan.id &&
                        it.packets.size == 1
                }
            }
            assertEquals(QuickFilter.ALL, sandboxState.quickFilter)
            assertEquals(retainedLan.id, sandboxState.packets.single().id)

            // Phone alert resets Packets tab cleanly to PHONE_ONLY + ALL quick filter
            viewModel.setTrafficScopeFilter(TrafficScopeFilter.ALL)
            viewModel.setQuickFilter(QuickFilter.UDP)
            val isLanForPhone = viewModel.applyAlertInspection(
                NetworkAlertEvent(
                    id = 11L,
                    timestampMs = 1_700_000_002_100L,
                    category = AlertCategory.UNAUTHORIZED_PORT,
                    severity = AlertSeverity.CRITICAL,
                    title = "Unauthorized Port (:22)",
                    detail = "Phone ssh",
                    packetId = retainedPhone.id,
                    filterExpr = "ip.addr == 9.9.9.9 && port == 22",
                    captureSource = CaptureSource.DEVICE_VPN
                )
            )
            assertFalse(isLanForPhone)
            val phoneState = withTimeout(3_000) {
                viewModel.uiState.first {
                    it.filterQuery == "ip.addr == 9.9.9.9 && port == 22" &&
                        it.selectedPacketId == retainedPhone.id &&
                        it.packets.size == 1
                }
            }
            assertEquals(TrafficScopeFilter.PHONE_ONLY, phoneState.trafficScopeFilter)
            assertEquals(QuickFilter.ALL, phoneState.quickFilter)
            assertEquals(retainedPhone.id, phoneState.packets.single().id)
        } finally {
            uiCollector.cancel()
            sandboxCollector.cancel()
        }
    }

    @Test
    fun vpnDisclosureAcceptedDefaultsFalseAndTransitionsOnAccept() = runBlocking {
        val viewModel = WireTraceViewModel()
        assertFalse(viewModel.vpnDisclosureAccepted.value)
        viewModel.acceptVpnDisclosure()
        assertTrue(viewModel.vpnDisclosureAccepted.value)
    }

    private fun buildIpv4Udp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payloadSize: Int = 8
    ): ByteArray {
        val udpLen = 8 + payloadSize
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64
        pkt[9] = 17
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 17, udpLen)
        return pkt
    }
}
