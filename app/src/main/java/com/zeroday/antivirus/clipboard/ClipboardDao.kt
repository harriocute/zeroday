package com.zeroday.antivirus.clipboard

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface ClipboardDao {

    @Query("SELECT * FROM clipboard_log ORDER BY timestamp DESC")
    fun getAll(): Flow<List<ClipboardEntry>>

    @Query("SELECT * FROM clipboard_log WHERE riskLevel != 'SAFE' ORDER BY timestamp DESC")
    fun getSuspicious(): Flow<List<ClipboardEntry>>

    @Query("SELECT * FROM clipboard_log ORDER BY timestamp DESC LIMIT :limit")
    fun getRecent(limit: Int = 50): Flow<List<ClipboardEntry>>

    @Query("SELECT * FROM clipboard_log WHERE accessedByPackage = :pkg ORDER BY timestamp DESC")
    fun getByApp(pkg: String): Flow<List<ClipboardEntry>>

    @Query("SELECT COUNT(*) FROM clipboard_log WHERE riskLevel != 'SAFE'")
    fun getSuspiciousCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM clipboard_log WHERE timestamp > :since")
    suspend fun getCountSince(since: Long): Int

    @Query("""
        SELECT COUNT(*) FROM clipboard_log 
        WHERE accessedByPackage = :pkg AND timestamp > :since
    """)
    suspend fun getAccessCountByApp(pkg: String, since: Long): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: ClipboardEntry): Long

    @Query("DELETE FROM clipboard_log WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("DELETE FROM clipboard_log")
    suspend fun clearAll()

    @Query("SELECT * FROM clipboard_log WHERE id = :id")
    suspend fun getById(id: Int): ClipboardEntry?
}
