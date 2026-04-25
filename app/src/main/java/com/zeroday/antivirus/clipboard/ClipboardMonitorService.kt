package com.zeroday.antivirus.clipboard

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.zeroday.antivirus.R
import com.zeroday.antivirus.model.ZerodayDatabase
import com.zeroday.antivirus.ui.MainActivity
import kotlinx.coroutines.*

class ClipboardMonitorService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var clipboardManager: ClipboardManager
    private lateinit var db: ZerodayDatabase
    private var lastContentHash = ""

    companion object {
        const val CHANNEL_ID  = "zeroday_clipboard"
        const val NOTIF_ID    = 2001
        const val ALERT_ID    = 2002
        const val ACTION_STOP = "com.zeroday.antivirus.STOP_CLIPBOARD_MONITOR"

        fun start(context: Context) {
            try {
                context.startForegroundService(
                    Intent(context, ClipboardMonitorService::class.java)
                )
            } catch (e: Exception) {}
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ClipboardMonitorService::class.java))
        }
    }

    override fun onCreate() {
        super.onCreate()
        clipboardManager = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        db = ZerodayDatabase.getInstance(this)
        createNotificationChannels()
        startForeground(NOTIF_ID, buildForegroundNotif())
        startMonitoring()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    private fun startMonitoring() {
        // Primary: ClipboardManager listener (fires when clipboard changes)
        clipboardManager.addPrimaryClipChangedListener {
            scope.launch {
                handleClipboardChange()
            }
        }
    }

    private suspend fun handleClipboardChange() {
        try {
            val clip = clipboardManager.primaryClip ?: return
            if (clip.itemCount == 0) return

            val content = clip.getItemAt(0)?.coerceToText(this)?.toString() ?: return
            if (content.isBlank()) return

            // Deduplicate — don't log same content twice in a row
            val hash = com.zeroday.antivirus.util.HashUtil.sha256(content.trim())
            if (hash == lastContentHash) return
            lastContentHash = hash

            // Detect which app set the clipboard (best effort — Android limits this)
            val accessingPkg = getTopApp() ?: "unknown"
            val appName = getAppName(accessingPkg)

            // Analyze content
            val analysis = ClipboardAnalyzer.analyze(content, accessingPkg)

            // Build log entry
            val entry = ClipboardEntry(
                accessedByPackage = accessingPkg,
                accessedByAppName = appName,
                contentPreview    = analysis.maskedPreview,
                contentHash       = analysis.contentHash,
                dataType          = analysis.dataType,
                riskLevel         = analysis.riskLevel,
                riskReason        = analysis.riskReason,
                isMasked          = analysis.shouldMask,
                contentLength     = content.length,
                wasAlerted        = analysis.riskLevel != ClipboardRisk.SAFE
            )

            db.clipboardDao().insert(entry)

            // Alert for suspicious/critical
            if (analysis.riskLevel != ClipboardRisk.SAFE) {
                sendAlert(entry)
            }

            // Auto-purge logs older than 30 days
            val thirtyDaysAgo = System.currentTimeMillis() - (30L * 24 * 60 * 60 * 1000)
            db.clipboardDao().deleteOlderThan(thirtyDaysAgo)

        } catch (e: Exception) {
            // Never crash the service
        }
    }

    private fun getTopApp(): String? {
        return try {
            // On Android 10+ we can't get the foreground app without UsageStats permission
            // We use ActivityManager as a fallback
            val am = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
            @Suppress("DEPRECATION")
            am.getRunningTasks(1).firstOrNull()
                ?.topActivity?.packageName
        } catch (e: Exception) { null }
    }

    private fun getAppName(pkg: String): String {
        return try {
            val info = packageManager.getApplicationInfo(pkg, 0)
            packageManager.getApplicationLabel(info).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            pkg.substringAfterLast(".")
        }
    }

    private fun sendAlert(entry: ClipboardEntry) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                putExtra("open_tab", "clipboard")
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val icon = when (entry.riskLevel) {
            ClipboardRisk.CRITICAL   -> "🚨"
            ClipboardRisk.SUSPICIOUS -> "⚠️"
            ClipboardRisk.SAFE       -> "ℹ️"
        }

        nm.notify(ALERT_ID + entry.id, NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("$icon Clipboard Alert — ${entry.accessedByAppName}")
            .setContentText(entry.riskReason)
            .setStyle(NotificationCompat.BigTextStyle()
                .bigText("${entry.riskReason}\n\nData type: ${entry.dataType.name}\nContent preview: ${entry.contentPreview}"))
            .setPriority(
                if (entry.riskLevel == ClipboardRisk.CRITICAL)
                    NotificationCompat.PRIORITY_MAX
                else NotificationCompat.PRIORITY_HIGH
            )
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setColor(
                if (entry.riskLevel == ClipboardRisk.CRITICAL) 0xFFFF3B5C.toInt()
                else 0xFFFFAA00.toInt()
            )
            .build())
    }

    private fun buildForegroundNotif() = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_shield)
        .setContentTitle("Zeroday — Clipboard Guard")
        .setContentText("Monitoring clipboard for sensitive data")
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true)
        .build()

    private fun createNotificationChannels() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Clipboard Monitor",
                NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Alerts when sensitive data is detected in clipboard"
            })
    }
}
