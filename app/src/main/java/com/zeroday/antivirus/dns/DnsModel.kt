package com.zeroday.antivirus.dns

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

enum class BlockCategory {
    ADS, MALWARE, TRACKING, PHISHING, ADULT, CRYPTOMINING, RANSOMWARE, CUSTOM
}

enum class BlockAction { BLOCKED, ALLOWED, WHITELISTED }

@Entity(
    tableName = "blocked_domains",
    indices = [Index(value = ["domain"], unique = true)]
)
data class BlockedDomain(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val domain: String,
    val category: BlockCategory,
    val source: String = "zeroday",         // which blocklist it came from
    val addedAt: Long = System.currentTimeMillis(),
    val isCustom: Boolean = false            // user-added custom blocks
)

@Entity(tableName = "dns_log")
data class DnsLogEntry(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val domain: String,
    val requestingApp: String,
    val action: BlockAction,
    val category: BlockCategory?,
    val timestamp: Long = System.currentTimeMillis(),
    val responseTimeMs: Long = 0
)

data class DnsStats(
    val totalQueries: Int,
    val totalBlocked: Int,
    val totalAllowed: Int,
    val blockRate: Float,
    val uniqueDomainsBlocked: Int,
    val topBlockedDomain: String?,
    val blocklistSize: Int
)
