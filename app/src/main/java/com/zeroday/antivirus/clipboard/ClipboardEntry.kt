package com.zeroday.antivirus.clipboard

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class ClipboardRisk { SAFE, SUSPICIOUS, CRITICAL }
enum class ClipboardDataType {
    PLAIN_TEXT, PASSWORD, CREDIT_CARD, PHONE_NUMBER,
    EMAIL, URL, CRYPTO_ADDRESS, NATIONAL_ID, UNKNOWN
}

@Entity(tableName = "clipboard_log")
data class ClipboardEntry(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val accessedByPackage: String,      // which app read the clipboard
    val accessedByAppName: String,
    val contentPreview: String,         // first 40 chars, masked if sensitive
    val contentHash: String,            // SHA-256 of full content
    val dataType: ClipboardDataType,
    val riskLevel: ClipboardRisk,
    val riskReason: String,
    val isMasked: Boolean,              // true if content was sensitive
    val contentLength: Int,
    val timestamp: Long = System.currentTimeMillis(),
    val wasAlerted: Boolean = false
)
