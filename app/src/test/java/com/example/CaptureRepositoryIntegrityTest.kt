package com.example

import com.example.capture.CaptureRepository
import com.example.capture.DnsResolutionCache
import com.example.dissector.PacketDissector
import com.example.model.PacketDirection
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Pins batch-1/batch-5 integrity fixes in [CaptureRepository]:
 *  - imported packets are remapped to fresh, unique ids (duplicate ids previously
 *    collided with live packets and crashed the LazyColumn keys),
 *  - the id sequence stays monotonic across imports and clear(),
 *  - header counters describe the buffer actually held after an import.
 */
class CaptureRepositoryIntegrityTest {

    private val baseTimestamp = 1_700_000_000_000L

    @Before
    fun setUp() {
        DnsResolutionCache.setAutoPtrEnabled(false) // no live PTR queries from unit tests
        CaptureRepository.clearCapture()
    }

    @After
    fun tearDown() {
        CaptureRepository.clearCapture()
        DnsResolutionCache.setAutoPtrEnabled(false)
    }

    @Test
    fun importRemapsDuplicateIdsAndKeepsIdSequenceMonotonic() {
        val raw = buildUdp(srcPort = 12345, dstPort = 53)
        CaptureRepository.recordRawPacket(raw, PacketDirection.OUTBOUND)
        CaptureRepository.recordRawPacket(raw, PacketDirection.OUTBOUND)
        val liveIds = CaptureRepository.snapshotAllPackets().map { it.id }
        assertEquals(2, liveIds.size)
        val maxLiveId = liveIds.max()

        // Imported packets with COLLIDING ids (worst-case corrupt/hostile pcap).
        val base = PacketDissector.dissect(777L, raw, baseTimestamp, 0L, PacketDirection.INBOUND)
        val retained = CaptureRepository.replaceWithImportedPackets(
            listOf(base.copy(id = 777L), base.copy(id = 777L))
        )

        assertEquals(2, retained.size)
        assertEquals(2, retained.map { it.id }.toSet().size) // unique after remap
        assertTrue(retained.all { it.id > maxLiveId })       // fresh ids, not reused

        // A live packet recorded AFTER the import still gets a higher id (sequence never
        // rewinds across replace/clear).
        CaptureRepository.recordRawPacket(raw, PacketDirection.INBOUND)
        val newId = CaptureRepository.snapshotAllPackets().last().id
        assertTrue(newId > retained.maxOf { it.id })
    }

    @Test
    fun importSyncsHeaderCountersToRetainedBuffer() {
        val raw = buildUdp(srcPort = 40000, dstPort = 443)
        val imported = (1..4001).map { i ->
            PacketDissector.dissect(
                i.toLong(), raw, baseTimestamp + i, 0L, PacketDirection.OUTBOUND
            )
        }
        val retained = CaptureRepository.replaceWithImportedPackets(imported)

        // Ring-buffer cap respected, and the "All captured packets (N pkts • B)" header
        // reflects the retained set — not the pre-import live session.
        assertEquals(4000, retained.size)
        assertEquals(4000L, CaptureRepository.totalPacketCount.value)
        assertEquals(
            retained.sumOf { it.rawBytes.size.toLong() },
            CaptureRepository.totalBytes.value
        )
    }

    @Test
    fun clearResetsCountersButNotTheIdSequence() {
        val raw = buildUdp(srcPort = 12345, dstPort = 80)
        CaptureRepository.recordRawPacket(raw, PacketDirection.OUTBOUND)
        CaptureRepository.recordRawPacket(raw, PacketDirection.OUTBOUND)
        val maxIdBeforeClear = CaptureRepository.snapshotAllPackets().maxOf { it.id }

        CaptureRepository.clearCapture()

        assertEquals(0L, CaptureRepository.totalPacketCount.value)
        assertEquals(0L, CaptureRepository.totalBytes.value)
        assertTrue(CaptureRepository.snapshotAllPackets().isEmpty())

        CaptureRepository.recordRawPacket(raw, PacketDirection.OUTBOUND)
        val idAfterClear = CaptureRepository.snapshotAllPackets().single().id
        assertTrue(
            "id must never be reused after clear (was $maxIdBeforeClear, got $idAfterClear)",
            idAfterClear > maxIdBeforeClear
        )
    }

    // Non-zero length required: recordRawPacket ignores empty frames.
    private fun buildUdp(srcPort: Int, dstPort: Int): ByteArray {
        val payload = ByteArray(4)
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64
        pkt[9] = 17
        System.arraycopy(byteArrayOf(10, 1, 10, 1), 0, pkt, 12, 4)
        System.arraycopy(byteArrayOf(1, 1, 1, 1), 0, pkt, 16, 4)
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        return pkt
    }
}
