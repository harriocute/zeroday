package com.zeroday.antivirus.dns

import android.content.Context
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * DnsBlocker — the core lookup engine.
 *
 * Uses a two-tier lookup:
 * 1. In-memory HashSet for O(1) speed (populated from DB on start)
 * 2. Room DB for persistence, stats, and custom rules
 *
 * Also supports wildcard subdomain blocking:
 * e.g. blocking "doubleclick.net" also blocks "ad.doubleclick.net"
 */
class DnsBlocker(private val context: Context) {

    private val db = ZerodayDnsDatabase.getInstance(context)

    // In-memory cache for ultra-fast lookups (avoids DB hit per query)
    private val blockedSet = HashSet<String>(50_000)
    private var cacheLoaded = false

    /** Load all blocked domains into memory — call once on service start */
    suspend fun loadCache() = withContext(Dispatchers.IO) {
        val domains = db.dnsDao().getAllBlockedDomains()
        blockedSet.clear()
        blockedSet.addAll(domains)
        cacheLoaded = true
    }

    /** Seed the database with the built-in blocklist */
    suspend fun seedBlocklist() = withContext(Dispatchers.IO) {
        val existing = db.dnsDao().getBlocklistSizeOnce()
        if (existing > 0) return@withContext  // already seeded

        val entries = BuiltinBlocklist.allDomains().map { (domain, category) ->
            BlockedDomain(
                domain   = domain,
                category = category,
                source   = "builtin"
            )
        }
        db.dnsDao().insertAll(entries)
        loadCache()
    }

    /**
     * Main lookup — returns the block decision for a DNS query.
     * Called for every DNS request intercepted by the VPN.
     */
    suspend fun checkDomain(domain: String): BlockResult = withContext(Dispatchers.Default) {
        if (!cacheLoaded) loadCache()

        val clean = domain.lowercase().trimEnd('.')

        // Exact match
        if (blockedSet.contains(clean)) {
            val entry = db.dnsDao().getBlockedDomain(clean)
            return@withContext BlockResult(
                domain   = clean,
                blocked  = true,
                category = entry?.category ?: BlockCategory.ADS,
                reason   = "Matched blocklist: ${entry?.source ?: "unknown"}"
            )
        }

        // Subdomain wildcard match
        // e.g. "tracker.ad.example.com" → check "ad.example.com" → "example.com"
        val parts = clean.split(".")
        for (i in 1 until parts.size - 1) {
            val parent = parts.drop(i).joinToString(".")
            if (blockedSet.contains(parent)) {
                val entry = db.dnsDao().getBlockedDomain(parent)
                return@withContext BlockResult(
                    domain   = clean,
                    blocked  = true,
                    category = entry?.category ?: BlockCategory.ADS,
                    reason   = "Subdomain of blocked: $parent"
                )
            }
        }

        BlockResult(domain = clean, blocked = false, category = null, reason = "Allowed")
    }

    suspend fun addCustomRule(domain: String) = withContext(Dispatchers.IO) {
        val entry = BlockedDomain(
            domain   = domain.lowercase().trim(),
            category = BlockCategory.CUSTOM,
            source   = "user",
            isCustom = true
        )
        db.dnsDao().insertDomain(entry)
        blockedSet.add(entry.domain)
    }

    suspend fun removeRule(domain: String) = withContext(Dispatchers.IO) {
        db.dnsDao().removeDomain(domain.lowercase().trim())
        blockedSet.remove(domain.lowercase().trim())
    }

    suspend fun logQuery(domain: String, app: String, result: BlockResult, responseMs: Long) =
        withContext(Dispatchers.IO) {
            db.dnsDao().logQuery(
                DnsLogEntry(
                    domain         = domain,
                    requestingApp  = app,
                    action         = if (result.blocked) BlockAction.BLOCKED else BlockAction.ALLOWED,
                    category       = result.category,
                    responseTimeMs = responseMs
                )
            )
        }

    fun getDao() = db.dnsDao()
}

data class BlockResult(
    val domain: String,
    val blocked: Boolean,
    val category: BlockCategory?,
    val reason: String
)
