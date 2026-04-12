package com.zeroday.antivirus.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.zeroday.antivirus.model.AppInfo
import com.zeroday.antivirus.model.ThreatLevel

data class PermissionReport(
    val appName: String,
    val packageName: String,
    val flaggedPermissions: List<FlaggedPermission>,
    val riskLevel: ThreatLevel
)

data class FlaggedPermission(
    val permission: String,
    val reason: String,
    val severity: ThreatLevel
)

class PermissionAuditor(private val context: Context) {

    private val pm = context.packageManager

    private val permissionDescriptions = mapOf(
        "android.permission.READ_SMS" to Pair("Can read all your SMS messages", ThreatLevel.HIGH),
        "android.permission.SEND_SMS" to Pair("Can send SMS without your knowledge", ThreatLevel.HIGH),
        "android.permission.RECORD_AUDIO" to Pair("Can record audio/calls at any time", ThreatLevel.HIGH),
        "android.permission.READ_CONTACTS" to Pair("Can access your entire contact list", ThreatLevel.MEDIUM),
        "android.permission.ACCESS_FINE_LOCATION" to Pair("Can track your precise GPS location", ThreatLevel.MEDIUM),
        "android.permission.CAMERA" to Pair("Can access camera at any time", ThreatLevel.MEDIUM),
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to Pair("Can read/control all screen content", ThreatLevel.CRITICAL),
        "android.permission.REQUEST_INSTALL_PACKAGES" to Pair("Can silently install other APKs", ThreatLevel.HIGH),
        "android.permission.READ_CALL_LOG" to Pair("Can access your call history", ThreatLevel.MEDIUM),
        "android.permission.PROCESS_OUTGOING_CALLS" to Pair("Can intercept and redirect calls", ThreatLevel.HIGH),
        "android.permission.BIND_DEVICE_ADMIN" to Pair("Can lock device or wipe data", ThreatLevel.CRITICAL),
        "android.permission.WRITE_SETTINGS" to Pair("Can modify system settings", ThreatLevel.LOW),
        "android.permission.READ_EXTERNAL_STORAGE" to Pair("Can read all files on your device", ThreatLevel.LOW),
    )

    fun auditAll(): List<PermissionReport> {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
        } else null

        val packages = if (flags != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(flags)
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        return packages.mapNotNull { pkg ->
            val perms = pkg.requestedPermissions?.toList() ?: return@mapNotNull null
            val flagged = perms.mapNotNull { perm ->
                permissionDescriptions[perm]?.let { (reason, severity) ->
                    FlaggedPermission(perm, reason, severity)
                }
            }
            if (flagged.isEmpty()) return@mapNotNull null

            val maxRisk = flagged.maxByOrNull { it.severity.ordinal }?.severity ?: ThreatLevel.LOW

            PermissionReport(
                appName = pm.getApplicationLabel(pkg.applicationInfo).toString(),
                packageName = pkg.packageName,
                flaggedPermissions = flagged,
                riskLevel = maxRisk
            )
        }.sortedByDescending { it.riskLevel.ordinal }
    }

    fun auditApp(packageName: String): PermissionReport? {
        return auditAll().find { it.packageName == packageName }
    }
}
