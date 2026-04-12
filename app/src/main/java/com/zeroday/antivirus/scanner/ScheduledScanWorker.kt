package com.zeroday.antivirus.scanner

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.zeroday.antivirus.model.ThreatLevel
import com.zeroday.antivirus.model.ZerodayDatabase

class ScheduledScanWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return try {
            val scanner = ZerodayScanner(applicationContext)
            val db = ZerodayDatabase.getInstance(applicationContext)

            scanner.scanAllApps().collect { progress ->
                if (progress is ScanProgress.Complete) {
                    db.threatDao().clearAll()
                    db.threatDao().insertAll(progress.results)
                }
            }
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}
