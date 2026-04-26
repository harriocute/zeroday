package com.zeroday.antivirus.dns

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface DnsDao {

    // ── Blocked Domains ──────────────────────────────────────────

    @Query("SELECT EXISTS(SELECT 1 FROM blocked_domains WHERE domain = :domain LIMIT 1)")
    suspend fun isDomainBlocked(domain: String): Boolean

    @Query("SELECT * FROM blocked_domains WHERE domain = :domain LIMIT 1")
    suspend fun getBlockedDomain(domain: String): BlockedDomain?

    @Query("SELECT COUNT(*) FROM blocked_domains")
    fun getBlocklistSize(): Flow<Int>

    @Query("SELECT COUNT(*) FROM blocked_domains")
    suspend fun getBlocklistSizeOnce(): Int

    @Query("SELECT * FROM blocked_domains WHERE isCustom = 1 ORDER BY addedAt DESC")
    fun getCustomRules(): Flow<List<BlockedDomain>>

    @Query("SELECT * FROM blocked_domains ORDER BY addedAt DESC LIMIT 100")
    fun getRecentBlocklist(): Flow<List<BlockedDomain>>

    @Query("SELECT * FROM blocked_domains WHERE category = :category ORDER BY domain ASC")
    fun getByCategory(category: BlockCategory): Flow<List<BlockedDomain>>

    @Query("SELECT COUNT(*) FROM blocked_domains WHERE category = :category")
    suspend fun countByCategory(category: BlockCategory): Int

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertDomain(domain: BlockedDomain): Long

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(domains: List<BlockedDomain>)

    @Query("DELETE FROM blocked_domains WHERE domain = :domain")
    suspend fun removeDomain(domain: String)

    @Query("DELETE FROM blocked_domains WHERE isCustom = 0")
    suspend fun clearBuiltinList()

    @Query("DELETE FROM blocked_domains")
    suspend fun clearAll()

    // ── DNS Log ───────────────────────────────────────────────────

    @Insert
    suspend fun logQuery(entry: DnsLogEntry)

    @Query("SELECT * FROM dns_log ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentLog(limit: Int = 200): Flow<List<DnsLogEntry>>

    @Query("SELECT * FROM dns_log WHERE action = 'BLOCKED' ORDER BY timestamp DESC LIMIT :limit")
    fun getBlockedLog(limit: Int = 200): Flow<List<DnsLogEntry>>

    @Query("SELECT COUNT(*) FROM dns_log")
    fun getTotalQueries(): Flow<Int>

    @Query("SELECT COUNT(*) FROM dns_log WHERE action = 'BLOCKED'")
    fun getTotalBlocked(): Flow<Int>

    @Query("SELECT COUNT(*) FROM dns_log WHERE action = 'ALLOWED'")
    fun getTotalAllowed(): Flow<Int>

    @Query("""
        SELECT domain, COUNT(*) as cnt FROM dns_log 
        WHERE action = 'BLOCKED' 
        GROUP BY domain 
        ORDER BY cnt DESC 
        LIMIT 1
    """)
    suspend fun getTopBlockedDomain(): String?

    @Query("SELECT COUNT(DISTINCT domain) FROM dns_log WHERE action = 'BLOCKED'")
    fun getUniqueBlockedDomains(): Flow<Int>

    @Query("DELETE FROM dns_log WHERE timestamp < :before")
    suspend fun purgeOldLogs(before: Long)

    @Query("DELETE FROM dns_log")
    suspend fun clearLog()
}
