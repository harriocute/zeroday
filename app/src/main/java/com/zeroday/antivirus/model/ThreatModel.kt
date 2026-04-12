package com.zeroday.antivirus.model

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class ThreatLevel { CRITICAL, HIGH, MEDIUM, LOW, CLEAN }
enum class ThreatType { TROJAN, ADWARE, SPYWARE, RANSOMWARE, PHISHING, SUSPICIOUS_PERMISSION, MALWARE, CLEAN }

@Entity(tableName = "threats")
data class ThreatResult(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val packageName: String,
    val appName: String,
    val apkPath: String,
    val threatType: ThreatType,
    val threatLevel: ThreatLevel,
    val description: String,
    val aiConfidence: Float,          // 0.0 - 1.0
    val isQuarantined: Boolean = false,
    val detectedAt: Long = System.currentTimeMillis(),
    val permissions: String = "",     // JSON list of flagged permissions
    val signatureHash: String = "",
    val networkActivity: String = ""  // JSON of suspicious network calls
)

data class ScanStats(
    val totalScanned: Int,
    val threatsFound: Int,
    val atRisk: Int,
    val cleanApps: Int,
    val scanDurationMs: Long,
    val lastScanTime: Long = System.currentTimeMillis()
)

data class AppInfo(
    val packageName: String,
    val appName: String,
    val apkPath: String,
    val installTime: Long,
    val permissions: List<String>,
    val isSystemApp: Boolean,
    val versionName: String,
    val signatureHash: String
)

data class WifiThreat(
    val ssid: String,
    val bssid: String,
    val threatLevel: ThreatLevel,
    val reason: String
)
