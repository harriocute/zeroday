package com.zeroday.antivirus.dns

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import com.zeroday.antivirus.R
import com.zeroday.antivirus.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

/**
 * DnsVpnService — Android VpnService that intercepts DNS queries.
 *
 * How it works:
 * 1. Opens a local VPN tunnel (tun0) that captures all DNS traffic (port 53)
 * 2. Reads raw IP/UDP packets from the tun interface
 * 3. Parses the DNS query to extract the requested hostname
 * 4. Checks the hostname against DnsBlocker
 * 5a. If BLOCKED → responds with 0.0.0.0 (NXDOMAIN / null IP)
 * 5b. If ALLOWED → forwards to upstream DNS (1.1.1.1 / 8.8.8.8) and returns real answer
 */
class DnsVpnService : VpnService() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var vpnInterface: ParcelFileDescriptor? = null
    private lateinit var blocker: DnsBlocker
    private var isRunning = false

    // Upstream DNS servers (Cloudflare + Google fallback)
    private val upstreamDns = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")

    companion object {
        const val CHANNEL_ID    = "zeroday_dns"
        const val NOTIF_ID      = 3001
        const val ACTION_START  = "com.zeroday.antivirus.DNS_START"
        const val ACTION_STOP   = "com.zeroday.antivirus.DNS_STOP"
        private const val VPN_MTU = 1500
        private const val DNS_PORT = 53

        fun start(context: Context) {
            context.startService(Intent(context, DnsVpnService::class.java).apply {
                action = ACTION_START
            })
        }

        fun stop(context: Context) {
            context.startService(Intent(context, DnsVpnService::class.java).apply {
                action = ACTION_STOP
            })
        }

        fun createPrepareIntent(context: Context): Intent? =
            prepare(context)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    override fun onRevoke() {
        stopVpn()
    }

    private fun startVpn() {
        if (isRunning) return
        blocker = DnsBlocker(this)
        createChannel()
        startForeground(NOTIF_ID, buildNotification("DNS blocker active"))

        scope.launch {
            // Seed blocklist on first run
            blocker.seedBlocklist()
            blocker.loadCache()

            // Build VPN interface
            vpnInterface = Builder()
                .setSession("Zeroday DNS")
                .addAddress("10.0.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("10.0.0.2")   // our fake local DNS
                .setMtu(VPN_MTU)
                .setBlocking(false)
                .also { builder ->
                    // Exclude our own package so we can reach upstream DNS
                    try { builder.addDisallowedApplication(packageName) }
                    catch (e: Exception) {}
                }
                .establish()

            if (vpnInterface == null) {
                stopSelf()
                return@launch
            }

            isRunning = true
            runPacketLoop()
        }
    }

    private fun stopVpn() {
        isRunning = false
        scope.cancel()
        try { vpnInterface?.close() } catch (e: Exception) {}
        vpnInterface = null
        stopForeground(true)
        stopSelf()
    }

    /**
     * Main packet processing loop.
     * Reads IP packets, extracts DNS queries, applies block rules.
     */
    private suspend fun runPacketLoop() = withContext(Dispatchers.IO) {
        val tunFd = vpnInterface ?: return@withContext
        val input  = FileInputStream(tunFd.fileDescriptor)
        val output = FileOutputStream(tunFd.fileDescriptor)
        val buffer = ByteBuffer.allocate(VPN_MTU)

        while (isRunning) {
            try {
                buffer.clear()
                val len = input.read(buffer.array())
                if (len <= 0) {
                    delay(1)
                    continue
                }
                buffer.limit(len)

                // Parse IP header to get protocol and addresses
                val ipVersion = (buffer.get(0).toInt() ushr 4) and 0xF
                if (ipVersion != 4) continue  // IPv6 not handled yet

                val protocol = buffer.get(9).toInt() and 0xFF
                if (protocol != 17) continue  // not UDP, skip

                // Extract UDP header offsets
                val ipHeaderLen = (buffer.get(0).toInt() and 0xF) * 4
                val destPort = ((buffer.get(ipHeaderLen + 2).toInt() and 0xFF) shl 8) or
                               (buffer.get(ipHeaderLen + 3).toInt() and 0xFF)

                if (destPort != DNS_PORT) continue  // not DNS query

                // Extract source IP + port for response routing
                val srcIp = ByteArray(4) { buffer.get(12 + it) }
                val srcPort = ((buffer.get(ipHeaderLen).toInt() and 0xFF) shl 8) or
                              (buffer.get(ipHeaderLen + 1).toInt() and 0xFF)

                // Extract DNS payload
                val dnsOffset = ipHeaderLen + 8
                val dnsLen = len - dnsOffset
                if (dnsLen < 12) continue  // too short to be valid DNS

                val dnsPayload = buffer.array().copyOfRange(dnsOffset, dnsOffset + dnsLen)

                // Parse DNS query hostname
                val hostname = parseDnsQuery(dnsPayload) ?: continue
                val txId = ((dnsPayload[0].toInt() and 0xFF) shl 8) or
                           (dnsPayload[1].toInt() and 0xFF)

                val start = System.currentTimeMillis()
                val result = blocker.checkDomain(hostname)
                val elapsed = System.currentTimeMillis() - start

                // Log asynchronously
                launch {
                    blocker.logQuery(hostname, "unknown", result, elapsed)
                }

                if (result.blocked) {
                    // Return 0.0.0.0 (blocked response)
                    val blocked = buildBlockedResponse(txId, dnsPayload)
                    val packet = buildIpUdpPacket(
                        srcData = blocked,
                        destIp  = srcIp,
                        destPort = srcPort,
                        srcIp   = byteArrayOf(10, 0, 0, 2),
                        srcPort = DNS_PORT
                    )
                    output.write(packet)
                } else {
                    // Forward to upstream DNS
                    val response = forwardToUpstream(dnsPayload)
                    if (response != null) {
                        val packet = buildIpUdpPacket(
                            srcData  = response,
                            destIp   = srcIp,
                            destPort = srcPort,
                            srcIp    = byteArrayOf(10, 0, 0, 2),
                            srcPort  = DNS_PORT
                        )
                        output.write(packet)
                    }
                }
            } catch (e: Exception) {
                if (!isRunning) break
                delay(5)
            }
        }
    }

    /** Parse DNS wire format to extract the queried hostname */
    private fun parseDnsQuery(dns: ByteArray): String? {
        return try {
            val sb = StringBuilder()
            var pos = 12  // skip DNS header
            while (pos < dns.size) {
                val len = dns[pos].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append('.')
                pos++
                if (pos + len > dns.size) return null
                sb.append(String(dns, pos, len, Charsets.US_ASCII))
                pos += len
            }
            if (sb.isEmpty()) null else sb.toString().lowercase()
        } catch (e: Exception) { null }
    }

    /** Build a DNS NXDOMAIN / 0.0.0.0 blocked response */
    private fun buildBlockedResponse(txId: Int, query: ByteArray): ByteArray {
        val response = ByteArray(query.size)
        System.arraycopy(query, 0, response, 0, query.size)
        // Set response flags: QR=1, AA=1, RCODE=0, ANCOUNT=1
        response[0] = (txId shr 8).toByte()
        response[1] = (txId and 0xFF).toByte()
        response[2] = 0x81.toByte()  // QR + RD
        response[3] = 0x80.toByte()  // RA
        // ANCOUNT = 1
        response[6] = 0
        response[7] = 1
        // Append answer record: pointer to name (0xC00C), A record, TTL=0, 0.0.0.0
        return response + byteArrayOf(
            0xC0.toByte(), 0x0C,       // name pointer
            0x00, 0x01,                // type A
            0x00, 0x01,                // class IN
            0x00, 0x00, 0x00, 0x00,   // TTL 0
            0x00, 0x04,                // rdlength 4
            0x00, 0x00, 0x00, 0x00    // 0.0.0.0
        )
    }

    /** Forward DNS query to upstream server and return response */
    private fun forwardToUpstream(query: ByteArray): ByteArray? {
        for (dns in upstreamDns) {
            try {
                val socket = DatagramSocket()
                protect(socket)  // exclude from VPN tunnel
                socket.soTimeout = 3000
                val addr = InetAddress.getByName(dns)
                socket.send(DatagramPacket(query, query.size, addr, DNS_PORT))
                val buf = ByteArray(4096)
                val resp = DatagramPacket(buf, buf.size)
                socket.receive(resp)
                socket.close()
                return buf.copyOf(resp.length)
            } catch (e: Exception) { continue }
        }
        return null
    }

    /** Wrap DNS data in a UDP/IP packet to write back to the tun interface */
    private fun buildIpUdpPacket(
        srcData: ByteArray, destIp: ByteArray, destPort: Int,
        srcIp: ByteArray, srcPort: Int
    ): ByteArray {
        val udpLen = 8 + srcData.size
        val ipLen  = 20 + udpLen
        val packet = ByteArray(ipLen)

        // IP header
        packet[0]  = 0x45                                      // version + IHL
        packet[1]  = 0                                         // DSCP
        packet[2]  = (ipLen shr 8).toByte()
        packet[3]  = (ipLen and 0xFF).toByte()
        packet[8]  = 64                                        // TTL
        packet[9]  = 17                                        // UDP
        System.arraycopy(srcIp,  0, packet, 12, 4)
        System.arraycopy(destIp, 0, packet, 16, 4)

        // UDP header
        packet[20] = (srcPort shr 8).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = (destPort shr 8).toByte()
        packet[23] = (destPort and 0xFF).toByte()
        packet[24] = (udpLen shr 8).toByte()
        packet[25] = (udpLen and 0xFF).toByte()

        // DNS payload
        System.arraycopy(srcData, 0, packet, 28, srcData.size)

        // IP checksum
        var sum = 0
        for (i in 0 until 20 step 2) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val checksum = sum.inv() and 0xFFFF
        packet[10] = (checksum shr 8).toByte()
        packet[11] = (checksum and 0xFF).toByte()

        return packet
    }

    private fun buildNotification(text: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_shield)
        .setContentTitle("Zeroday — DNS Blocker")
        .setContentText(text)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true)
        .setContentIntent(
            PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE
            )
        )
        .build()

    private fun createChannel() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "DNS Blocker",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "DNS-level ad and malware blocking" }
        )
    }
}
