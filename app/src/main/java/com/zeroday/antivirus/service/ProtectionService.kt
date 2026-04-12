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
import com.zeroday.antivirus.ui.MainActivity
import kotlinx.coroutines.*

class ProtectionService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var scanner: ZerodayScanner
    private lateinit var db: ZerodayDatabase

    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val pkg = intent.data?.schemeSpecificPart ?: return
            if (intent.action == Intent.ACTION_PACKAGE_ADDED) scanNewApp(pkg)
        }
    }

    companion object {
        const val CHANNEL_ID = "zeroday_protection"
        const val NOTIF_ID   = 1001
        const val THREAT_ID  = 1002

        fun start(context: Context) {
            try {
                context.startForegroundService(Intent(context, ProtectionService::class.java))
            } catch (e: Exception) { /* ignore if already running */ }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ProtectionService::class.java))
        }
    }

    override fun onCreate() {
        super.onCreate()
        scanner = ZerodayScanner(this)
        db = ZerodayDatabase.getInstance(this)
        createChannel()
        startForeground(NOTIF_ID, buildNotif("Real-time protection active"))
        registerReceiver(packageReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addDataScheme("package")
        })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int) = START_STICKY
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        try { unregisterReceiver(packageReceiver) } catch (e: Exception) {}
    }

    private fun scanNewApp(packageName: String) {
        scope.launch {
            try {
                val apps = scanner.getInstalledApps()
                val app  = apps.find { it.packageName == packageName } ?: return@launch
                val result = scanner.analyzeApp(app)
                db.threatDao().insertThreat(result)
                if (result.threatLevel == ThreatLevel.CRITICAL || result.threatLevel == ThreatLevel.HIGH) {
                    notifyThreat(result.appName, result.description)
                }
            } catch (e: Exception) { /* don't crash the service */ }
        }
    }

    private fun notifyThreat(appName: String, desc: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        nm.notify(THREAT_ID, NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("⚠️ Threat Detected: $appName")
            .setContentText(desc.take(100))
            .setStyle(NotificationCompat.BigTextStyle().bigText(desc))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build())
    }

    private fun buildNotif(text: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_shield)
        .setContentTitle("Zeroday — Active")
        .setContentText(text)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true)
        .build()

    private fun createChannel() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Zeroday Protection",
                NotificationManager.IMPORTANCE_LOW).apply {
                description = "Real-time threat protection"
            })
    }
}
