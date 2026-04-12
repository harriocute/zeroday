package com.zeroday.antivirus.scanner

import android.content.Context
import android.net.wifi.WifiManager
import com.zeroday.antivirus.model.ThreatLevel
import com.zeroday.antivirus.model.WifiThreat

class WifiScanner(private val context: Context) {

    private val wifiManager = context.applicationContext
        .getSystemService(Context.WIFI_SERVICE) as WifiManager

    // Known rogue/evil-twin SSID patterns
    private val suspiciousSsids = listOf(
        Regex(".*free.*wifi.*", RegexOption.IGNORE_CASE),
        Regex(".*airport.*free.*", RegexOption.IGNORE_CASE),
        Regex(".*hotel.*wifi.*", RegexOption.IGNORE_CASE),
        Regex(".*public.*", RegexOption.IGNORE_CASE),
        Regex(".*starbucks.*", RegexOption.IGNORE_CASE),
        Regex("^wifi$", RegexOption.IGNORE_CASE),
        Regex("^free$", RegexOption.IGNORE_CASE),
        Regex(".*xfinity.*", RegexOption.IGNORE_CASE)
    )

    @Suppress("DEPRECATION")
    fun scanNetworks(): List<WifiThreat> {
        val results = mutableListOf<WifiThreat>()

        try {
            val scanResults = wifiManager.scanResults ?: return emptyList()

            // Group by SSID to detect evil-twin (same SSID, different BSSID, weaker signal)
            val ssidGroups = scanResults.groupBy { it.SSID }

            for ((ssid, networks) in ssidGroups) {
                if (ssid.isNullOrBlank()) continue

                // Evil twin detection: same SSID, multiple different BSSIDs
                if (networks.size > 2) {
                    results.add(WifiThreat(
                        ssid = ssid,
                        bssid = networks.first().BSSID,
                        threatLevel = ThreatLevel.HIGH,
                        reason = "Possible evil-twin attack: ${networks.size} APs broadcasting same SSID"
                    ))
                }

                // Open network check (no security)
                val openNetworks = networks.filter {
                    it.capabilities.contains("ESS") && !it.capabilities.contains("WPA") &&
                            !it.capabilities.contains("WEP")
                }
                if (openNetworks.isNotEmpty()) {
                    val isSuspicious = suspiciousSsids.any { it.containsMatchIn(ssid) }
                    results.add(WifiThreat(
                        ssid = ssid,
                        bssid = openNetworks.first().BSSID,
                        threatLevel = if (isSuspicious) ThreatLevel.HIGH else ThreatLevel.MEDIUM,
                        reason = "Open network (no encryption). ${if (isSuspicious) "Matches known honeypot pattern." else "Traffic may be interceptable."}"
                    ))
                }

                // WEP (weak encryption)
                val wepNetworks = networks.filter { it.capabilities.contains("WEP") }
                if (wepNetworks.isNotEmpty()) {
                    results.add(WifiThreat(
                        ssid = ssid,
                        bssid = wepNetworks.first().BSSID,
                        threatLevel = ThreatLevel.MEDIUM,
                        reason = "WEP encryption detected — easily crackable, avoid sensitive traffic"
                    ))
                }
            }
        } catch (e: SecurityException) {
            // Location permission not granted
        }

        return results.distinctBy { it.ssid + it.reason }
    }

    fun getCurrentNetworkRisk(): ThreatLevel {
        val connectionInfo = wifiManager.connectionInfo ?: return ThreatLevel.CLEAN
        val ssid = connectionInfo.ssid?.replace("\"", "") ?: return ThreatLevel.CLEAN
        val threats = scanNetworks()
        return threats.find { it.ssid == ssid }?.threatLevel ?: ThreatLevel.CLEAN
    }
}
