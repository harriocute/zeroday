package com.zeroday.antivirus.model

import android.content.Context
import androidx.room.*
import com.zeroday.antivirus.clipboard.ClipboardDao
import com.zeroday.antivirus.clipboard.ClipboardEntry
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatDao {
    @Query("SELECT * FROM threats ORDER BY detectedAt DESC")
    fun getAllThreats(): Flow<List<ThreatResult>>

    @Query("SELECT * FROM threats WHERE threatLevel != 'CLEAN' ORDER BY detectedAt DESC")
    fun getNonCleanThreats(): Flow<List<ThreatResult>>

    @Query("SELECT * FROM threats WHERE isQuarantined = 0 AND threatLevel != 'CLEAN' ORDER BY detectedAt DESC")
    fun getActiveThreats(): Flow<List<ThreatResult>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreat(threat: ThreatResult)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(threats: List<ThreatResult>)

    @Query("UPDATE threats SET isQuarantined = 1 WHERE id = :id")
    suspend fun quarantine(id: Int)

    @Query("DELETE FROM threats WHERE id = :id")
    suspend fun delete(id: Int)

    @Query("DELETE FROM threats")
    suspend fun clearAll()

    @Query("SELECT COUNT(*) FROM threats WHERE threatLevel != 'CLEAN' AND isQuarantined = 0")
    fun getActiveThreatCount(): Flow<Int>
}

@Database(
    entities = [ThreatResult::class, ClipboardEntry::class],
    version = 2,
    exportSchema = false
)
abstract class ZerodayDatabase : RoomDatabase() {
    abstract fun threatDao(): ThreatDao
    abstract fun clipboardDao(): ClipboardDao

    companion object {
        @Volatile private var INSTANCE: ZerodayDatabase? = null

        fun getInstance(context: Context): ZerodayDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    ZerodayDatabase::class.java,
                    "zeroday_db"
                ).fallbackToDestructiveMigration()
                 .build()
                 .also { INSTANCE = it }
            }
    }
}
