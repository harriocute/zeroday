package com.zeroday.antivirus.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.zeroday.antivirus.R
import com.zeroday.antivirus.model.ThreatLevel
import com.zeroday.antivirus.model.ZerodayDatabase
import com.zeroday.antivirus.scanner.ZerodayScanner
import com.zeroday.antivirus.scanner.ScanProgress
import com.zeroday.antivirus.ui.MainActivity
import kotlinx.coroutines.*

class ProtectionService : Service() {

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private lateinit var scanner: ZerodayScanner
    private lateinit var db: ZerodayDatabase

    // Listen for new app installs
    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val packageName = intent.data?.schemeSpecificPart ?: return
            if (intent.action == Intent.ACTION_PACKAGE_ADDED) {
                scanNewApp(packageName)
            }
        }
    }

    companion object {
        const val CHANNEL_ID = "zeroday_protection"
        const val NOTIF_ID = 1001
        const val THREAT_NOTIF_ID = 1002

        fun start(context: Context) {
            val intent = Intent(context, ProtectionService::class.java)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ProtectionService::class.java))
        }
    }

    override fun onCreate() {
        super.onCreate()
        scanner = ZerodayScanner(this)
        db = ZerodayDatabase.getInstance(this)
        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification("Real-time protection active"))

        // Register package install listener
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addDataScheme("package")
        }
        registerReceiver(packageReceiver, filter)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        unregisterReceiver(packageReceiver)
    }

    private fun scanNewApp(packageName: String) {
        scope.launch {
            val apps = scanner.getInstalledApps()
            val app = apps.find { it.packageName == packageName } ?: return@launch
            val result = scanner.analyzeApp(app)

            db.threatDao().insertThreat(result)

            if (result.threatLevel == ThreatLevel.CRITICAL || result.threatLevel == ThreatLevel.HIGH) {
                notifyThreat(result.appName, result.description, result.threatLevel)
            }
        }
    }

    private fun notifyThreat(appName: String, description: String, level: ThreatLevel) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("⚠️ Threat Detected: $appName")
            .setContentText(description.take(100))
            .setStyle(NotificationCompat.BigTextStyle().bigText(description))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()

        nm.notify(THREAT_NOTIF_ID, notif)
    }

    private fun buildNotification(text: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_shield)
        .setContentTitle("Zeroday — Active")
        .setContentText(text)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true)
        .build()

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Zeroday Protection",
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Real-time threat protection" }
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(channel)
    }
}
