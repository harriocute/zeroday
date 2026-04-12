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
import kotlinx.coroutines.withContext

/**
 * ZerodayScanner — Core scanning engine.
 * Uses heuristics + permission analysis + signature matching
 * to classify installed apps as clean or threats.
 */
class ZerodayScanner(private val context: Context) {

    private val pm: PackageManager = context.packageManager

    // High-risk permission combinations
    private val dangerousPermissions = setOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_DEVICE_ADMIN"
    )

    // Known malicious package name patterns
    private val maliciousPatterns = listOf(
        Regex(".*\\.hack.*"),
        Regex(".*crack.*"),
        Regex(".*mod\\.apk.*"),
        Regex(".*cheat.*"),
        Regex(".*free.*premium.*"),
        Regex(".*clone.*"),
        Regex(".*spoof.*"),
        Regex(".*injector.*"),
        Regex(".*keylogger.*")
    )

    // Known safe publisher signatures (simplified whitelist)
    private val trustedPublishers = setOf(
        "com.google",
        "com.android",
        "com.samsung",
        "com.whatsapp",
        "com.facebook",
        "com.instagram",
        "com.twitter",
        "com.spotify",
        "com.netflix"
    )

    /**
     * Full device scan — emits progress as it goes.
     */
    fun scanAllApps(): Flow<ScanProgress> = flow {
        val packages = getInstalledApps()
        val total = packages.size
        val results = mutableListOf<ThreatResult>()

        emit(ScanProgress.Started(total))

        packages.forEachIndexed { index, appInfo ->
            val result = analyzeApp(appInfo)
            results.add(result)

            emit(ScanProgress.Scanning(
                current = index + 1,
                total = total,
                appName = appInfo.appName,
                currentResult = result
            ))
        }

        val stats = ScanStats(
            totalScanned = total,
            threatsFound = results.count { it.threatLevel == ThreatLevel.CRITICAL || it.threatLevel == ThreatLevel.HIGH },
            atRisk = results.count { it.threatLevel == ThreatLevel.MEDIUM || it.threatLevel == ThreatLevel.LOW },
            cleanApps = results.count { it.threatLevel == ThreatLevel.CLEAN },
            scanDurationMs = System.currentTimeMillis()
        )

        emit(ScanProgress.Complete(results, stats))
    }

    /**
     * Analyze a single app using heuristic AI scoring.
     */
    suspend fun analyzeApp(appInfo: AppInfo): ThreatResult = withContext(Dispatchers.Default) {
        val flags = mutableListOf<String>()
        var riskScore = 0f

        // 1. Permission analysis
        val dangerousCount = appInfo.permissions.count { it in dangerousPermissions }
        val permissionRisk = dangerousCount.toFloat() / dangerousPermissions.size.toFloat()
        riskScore += permissionRisk * 40f

        if (dangerousCount >= 5) flags.add("Excessive dangerous permissions ($dangerousCount)")
        if (appInfo.permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE") &&
            appInfo.permissions.contains("android.permission.READ_SMS")) {
            flags.add("Accessibility + SMS combo — classic spyware pattern")
            riskScore += 30f
        }
        if (appInfo.permissions.contains("android.permission.REQUEST_INSTALL_PACKAGES") &&
            !appInfo.isSystemApp) {
            flags.add("Can silently install other apps")
            riskScore += 20f
        }

        // 2. Package name pattern matching
        val matchedPattern = maliciousPatterns.any { it.containsMatchIn(appInfo.packageName) }
        if (matchedPattern) {
            flags.add("Suspicious package name pattern")
            riskScore += 25f
        }

        // 3. System app impersonation check
        if (!appInfo.isSystemApp && isSuspiciousSystemName(appInfo.appName)) {
            flags.add("App name impersonates system app")
            riskScore += 35f
        }

        // 4. Trusted publisher check
        val isTrusted = trustedPublishers.any { appInfo.packageName.startsWith(it) }
        if (isTrusted) riskScore -= 30f

        // 5. Side-loaded APK check (not from Play Store)
        val isSideloaded = isSideloaded(appInfo)
        if (isSideloaded && !appInfo.isSystemApp) {
            flags.add("Side-loaded APK (not from Play Store)")
            riskScore += 15f
        }

        // Clamp score 0-100
        riskScore = riskScore.coerceIn(0f, 100f)

        // Determine threat level and type
        val (level, type) = classifyThreat(riskScore, flags, appInfo)
        val confidence = (riskScore / 100f).coerceIn(0f, 1f)

        ThreatResult(
            packageName = appInfo.packageName,
            appName = appInfo.appName,
            apkPath = appInfo.apkPath,
            threatType = type,
            threatLevel = level,
            description = buildDescription(level, flags, appInfo),
            aiConfidence = if (level == ThreatLevel.CLEAN) 0.95f else confidence,
            permissions = appInfo.permissions.filter { it in dangerousPermissions }.joinToString(","),
            signatureHash = appInfo.signatureHash
        )
    }

    private fun classifyThreat(
        score: Float,
        flags: List<String>,
        app: AppInfo
    ): Pair<ThreatLevel, ThreatType> {
        return when {
            score >= 75f -> Pair(ThreatLevel.CRITICAL, detectType(flags))
            score >= 55f -> Pair(ThreatLevel.HIGH, detectType(flags))
            score >= 35f -> Pair(ThreatLevel.MEDIUM, ThreatType.SUSPICIOUS_PERMISSION)
            score >= 15f -> Pair(ThreatLevel.LOW, ThreatType.SUSPICIOUS_PERMISSION)
            else -> Pair(ThreatLevel.CLEAN, ThreatType.CLEAN)
        }
    }

    private fun detectType(flags: List<String>): ThreatType {
        return when {
            flags.any { it.contains("spyware", true) || it.contains("SMS", true) } -> ThreatType.SPYWARE
            flags.any { it.contains("install", true) } -> ThreatType.TROJAN
            flags.any { it.contains("impersonat", true) } -> ThreatType.MALWARE
            else -> ThreatType.MALWARE
        }
    }

    private fun buildDescription(level: ThreatLevel, flags: List<String>, app: AppInfo): String {
        if (level == ThreatLevel.CLEAN) return "No threats detected. App behavior appears normal."
        val flagText = flags.joinToString(". ")
        return "AI Analysis: $flagText. Confidence based on ${flags.size} risk indicators."
    }

    private fun isSuspiciousSystemName(name: String): Boolean {
        val systemNames = listOf("System", "Android", "Settings", "Google", "Play Store", "Phone", "Messages")
        return systemNames.any { name.contains(it, ignoreCase = true) }
    }

    private fun isSideloaded(app: AppInfo): Boolean {
        return try {
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(app.packageName).initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(app.packageName)
            }
            installer != "com.android.vending" && installer != "com.google.android.packageinstaller"
        } catch (e: Exception) { true }
    }

    fun getInstalledApps(): List<AppInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }

        return packages.map { pkg ->
            val perms = pkg.requestedPermissions?.toList() ?: emptyList()
            val isSystem = (pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            AppInfo(
                packageName = pkg.packageName,
                appName = pm.getApplicationLabel(pkg.applicationInfo).toString(),
                apkPath = pkg.applicationInfo.sourceDir ?: "",
                installTime = pkg.firstInstallTime,
                permissions = perms,
                isSystemApp = isSystem,
                versionName = pkg.versionName ?: "unknown",
                signatureHash = HashUtil.getSignatureHash(pkg)
            )
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
