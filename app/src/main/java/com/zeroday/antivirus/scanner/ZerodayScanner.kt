package com.zeroday.antivirus.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.zeroday.antivirus.model.*
import com.zeroday.antivirus.util.HashUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext

class ZerodayScanner(private val context: Context) {

    private val pm: PackageManager = context.packageManager

    private val dangerousPermissions = setOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.GET_ACCOUNTS",
        "android.permission.USE_BIOMETRIC",
        "android.permission.BODY_SENSORS",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO"
    )

    private val criticalCombos = listOf(
        Pair("android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.READ_SMS"),
        Pair("android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.RECORD_AUDIO"),
        Pair("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECEIVE_BOOT_COMPLETED"),
        Pair("android.permission.READ_SMS", "android.permission.SEND_SMS"),
        Pair("android.permission.BIND_DEVICE_ADMIN", "android.permission.READ_CONTACTS")
    )

    private val maliciousPatterns = listOf(
        Regex(".*crack.*", RegexOption.IGNORE_CASE),
        Regex(".*hack.*", RegexOption.IGNORE_CASE),
        Regex(".*mod\\.apk.*", RegexOption.IGNORE_CASE),
        Regex(".*cheat.*", RegexOption.IGNORE_CASE),
        Regex(".*keygen.*", RegexOption.IGNORE_CASE),
        Regex(".*injector.*", RegexOption.IGNORE_CASE),
        Regex(".*spyware.*", RegexOption.IGNORE_CASE),
        Regex(".*keylogger.*", RegexOption.IGNORE_CASE),
        Regex(".*trojan.*", RegexOption.IGNORE_CASE),
        Regex(".*rat\\..*", RegexOption.IGNORE_CASE)
    )

    private val trustedPublishers = setOf(
        "com.google", "com.android", "com.samsung", "com.whatsapp",
        "com.facebook", "com.instagram", "com.twitter", "com.spotify",
        "com.netflix", "com.microsoft", "com.amazon", "com.adobe",
        "com.snapchat", "com.tiktok", "com.linkedin", "com.paypal",
        "com.uber", "com.airbnb", "org.telegram", "com.discord"
    )

    fun scanAllApps(): Flow<ScanProgress> = flow {
        val packages = try {
            getInstalledApps()
        } catch (e: Exception) {
            emit(ScanProgress.Error("Failed to read installed apps: ${e.message}"))
            return@flow
        }

        val total = packages.size
        val results = mutableListOf<ThreatResult>()
        val startTime = System.currentTimeMillis()

        emit(ScanProgress.Started(total))

        packages.forEachIndexed { index, appInfo ->
            try {
                val result = analyzeApp(appInfo)
                results.add(result)
                emit(ScanProgress.Scanning(
                    current = index + 1,
                    total = total,
                    appName = appInfo.appName,
                    currentResult = result
                ))
            } catch (e: Exception) {
                // Skip this app if analysis fails, don't crash
            }
        }

        val duration = System.currentTimeMillis() - startTime
        val stats = ScanStats(
            totalScanned = total,
            threatsFound = results.count {
                it.threatLevel == ThreatLevel.CRITICAL || it.threatLevel == ThreatLevel.HIGH
            },
            atRisk = results.count {
                it.threatLevel == ThreatLevel.MEDIUM || it.threatLevel == ThreatLevel.LOW
            },
            cleanApps = results.count { it.threatLevel == ThreatLevel.CLEAN },
            scanDurationMs = duration
        )
        emit(ScanProgress.Complete(results, stats))
    }.flowOn(Dispatchers.IO)  // ← CRITICAL: runs on IO thread, never blocks UI

    suspend fun analyzeApp(appInfo: AppInfo): ThreatResult = withContext(Dispatchers.Default) {
        val flags = mutableListOf<String>()
        var riskScore = 0f

        // 1. Dangerous permission count
        val flaggedPerms = appInfo.permissions.filter { it in dangerousPermissions }
        val dangerousCount = flaggedPerms.size
        if (dangerousCount > 0) riskScore += (dangerousCount.toFloat() / dangerousPermissions.size) * 35f
        if (dangerousCount >= 6) flags.add("Requests $dangerousCount dangerous permissions")

        // 2. Critical permission combinations
        for ((p1, p2) in criticalCombos) {
            if (appInfo.permissions.contains(p1) && appInfo.permissions.contains(p2)) {
                flags.add("Critical combo: ${p1.substringAfterLast('.')} + ${p2.substringAfterLast('.')}")
                riskScore += 30f
            }
        }

        // 3. Malicious package name patterns
        if (maliciousPatterns.any { it.containsMatchIn(appInfo.packageName) }) {
            flags.add("Suspicious package name pattern")
            riskScore += 25f
        }

        // 4. System app impersonation
        if (!appInfo.isSystemApp && isSuspiciousSystemName(appInfo.appName)) {
            flags.add("App name impersonates a system app")
            riskScore += 35f
        }

        // 5. Trusted publisher discount
        if (trustedPublishers.any { appInfo.packageName.startsWith(it) }) {
            riskScore = (riskScore - 30f).coerceAtLeast(0f)
        }

        // 6. Side-loaded APK penalty
        if (!appInfo.isSystemApp && isSideloaded(appInfo)) {
            flags.add("Side-loaded APK (not from Play Store)")
            riskScore += 10f
        }

        // 7. Background location abuse
        if (appInfo.permissions.contains("android.permission.ACCESS_BACKGROUND_LOCATION")
            && !appInfo.isSystemApp) {
            flags.add("Requests background location tracking")
            riskScore += 15f
        }

        riskScore = riskScore.coerceIn(0f, 100f)

        val (level, type) = classifyThreat(riskScore, flags)
        val confidence = if (level == ThreatLevel.CLEAN) 0.97f
                         else (riskScore / 100f).coerceIn(0.5f, 0.99f)

        ThreatResult(
            packageName = appInfo.packageName,
            appName = appInfo.appName,
            apkPath = appInfo.apkPath,
            threatType = type,
            threatLevel = level,
            description = buildDescription(level, flags),
            aiConfidence = confidence,
            permissions = flaggedPerms.joinToString(","),
            signatureHash = appInfo.signatureHash
        )
    }

    private fun classifyThreat(score: Float, flags: List<String>): Pair<ThreatLevel, ThreatType> {
        val type = when {
            flags.any { it.contains("Accessibility", true) || it.contains("combo", true) } -> ThreatType.SPYWARE
            flags.any { it.contains("install", true) || it.contains("boot", true) } -> ThreatType.TROJAN
            flags.any { it.contains("impersonates", true) } -> ThreatType.MALWARE
            flags.any { it.contains("location", true) } -> ThreatType.SPYWARE
            flags.isNotEmpty() -> ThreatType.SUSPICIOUS_PERMISSION
            else -> ThreatType.CLEAN
        }
        val level = when {
            score >= 75f -> ThreatLevel.CRITICAL
            score >= 55f -> ThreatLevel.HIGH
            score >= 30f -> ThreatLevel.MEDIUM
            score >= 10f -> ThreatLevel.LOW
            else -> ThreatLevel.CLEAN
        }
        return Pair(level, type)
    }

    private fun buildDescription(level: ThreatLevel, flags: List<String>): String {
        if (level == ThreatLevel.CLEAN || flags.isEmpty())
            return "No threats detected. App behavior appears normal and permissions are within expected range."
        return "AI detected ${flags.size} risk indicator(s): ${flags.joinToString("; ")}."
    }

    private fun isSuspiciousSystemName(name: String): Boolean {
        val systemNames = listOf("System", "Android", "Google Play", "Settings",
            "Phone", "Messages", "Contacts", "Gallery", "Camera")
        return systemNames.any { name.equals(it, ignoreCase = true) }
    }

    private fun isSideloaded(app: AppInfo): Boolean = try {
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(app.packageName).initiatingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(app.packageName)
        }
        installer != "com.android.vending" && installer != "com.google.android.packageinstaller"
    } catch (e: Exception) { false }

    fun getInstalledApps(): List<AppInfo> {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PackageManager.PackageInfoFlags.of(
                (PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES).toLong()
            )
        } else null

        val packages = if (flags != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(flags)
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES)
        }

        return packages.mapNotNull { pkg ->
            try {
                val isSystem = (pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                AppInfo(
                    packageName  = pkg.packageName,
                    appName      = pm.getApplicationLabel(pkg.applicationInfo).toString(),
                    apkPath      = pkg.applicationInfo.sourceDir ?: "",
                    installTime  = pkg.firstInstallTime,
                    permissions  = pkg.requestedPermissions?.toList() ?: emptyList(),
                    isSystemApp  = isSystem,
                    versionName  = pkg.versionName ?: "unknown",
                    signatureHash = HashUtil.getSignatureHash(pkg)
                )
            } catch (e: Exception) { null }
        }
    }
}

sealed class ScanProgress {
    data class Started(val total: Int) : ScanProgress()
    data class Scanning(
        val current: Int,
        val total: Int,
        val appName: String,
        val currentResult: ThreatResult
    ) : ScanProgress()
    data class Complete(val results: List<ThreatResult>, val stats: ScanStats) : ScanProgress()
    data class Error(val message: String) : ScanProgress()
}
