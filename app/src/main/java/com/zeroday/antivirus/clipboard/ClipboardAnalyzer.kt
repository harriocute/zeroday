package com.zeroday.antivirus.clipboard

import com.zeroday.antivirus.util.HashUtil

/**
 * Analyzes clipboard content to detect sensitive data types
 * and assign a risk level. No content is stored raw — only
 * a masked preview and a hash.
 */
object ClipboardAnalyzer {

    // Regex patterns for sensitive data detection
    private val CREDIT_CARD   = Regex("""^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$""")
    private val PASSWORD_HINT = Regex("""(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}""")
    private val PHONE_NG      = Regex("""^(\+?234|0)[789][01]\d{8}$""")   // Nigerian numbers
    private val PHONE_INTL    = Regex("""^\+?[1-9]\d{7,14}$""")
    private val EMAIL         = Regex("""^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$""")
    private val URL           = Regex("""https?://[^\s/$.?#].[^\s]*""")
    private val BTC_ADDRESS   = Regex("""^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$""")
    private val ETH_ADDRESS   = Regex("""^0x[a-fA-F0-9]{40}$""")
    private val NIN_NG        = Regex("""^\d{11}$""")                      // Nigerian NIN
    private val BVN_NG        = Regex("""^\d{11}$""")                      // Nigerian BVN
    private val NUBAN_NG      = Regex("""^\d{10}$""")                      // Nigerian bank account
    private val PIN           = Regex("""^\d{4,6}$""")
    private val SECRET_KEY    = Regex("""[A-Za-z0-9+/]{32,}={0,2}""")    // base64-like secrets

    // Apps that legitimately read clipboard frequently
    private val TRUSTED_CLIPBOARD_APPS = setOf(
        "com.google.android.gms",
        "com.android.chrome",
        "com.google.android.inputmethod.latin",
        "com.samsung.android.honeyboard",
        "com.swiftkey.swiftkeyapp",
        "com.touchtype.swiftkey",
        "com.microsoft.swiftkey",
        "com.google.android.apps.docs",
        "com.microsoft.office.word",
        "com.microsoft.office.excel"
    )

    // Apps that should NEVER need clipboard access
    private val SUSPICIOUS_CLIPBOARD_APPS = setOf(
        // Games, flashlights, and utility apps with no legitimate clipboard need
        "com.flashlight",
        "com.battery.saver"
    )

    data class AnalysisResult(
        val dataType: ClipboardDataType,
        val riskLevel: ClipboardRisk,
        val riskReason: String,
        val maskedPreview: String,
        val shouldMask: Boolean,
        val contentHash: String
    )

    fun analyze(content: String, accessingPackage: String): AnalysisResult {
        val trimmed = content.trim()
        val hash = HashUtil.sha256(trimmed)

        // Detect data type
        val dataType = detectDataType(trimmed)

        // Mask sensitive content
        val (masked, shouldMask) = maskContent(trimmed, dataType)

        // Assess risk
        val (risk, reason) = assessRisk(trimmed, dataType, accessingPackage)

        return AnalysisResult(
            dataType     = dataType,
            riskLevel    = risk,
            riskReason   = reason,
            maskedPreview = masked,
            shouldMask   = shouldMask,
            contentHash  = hash
        )
    }

    private fun detectDataType(content: String): ClipboardDataType {
        val clean = content.replace(" ", "").replace("-", "")
        return when {
            CREDIT_CARD.matches(clean)        -> ClipboardDataType.CREDIT_CARD
            ETH_ADDRESS.matches(clean)        -> ClipboardDataType.CRYPTO_ADDRESS
            BTC_ADDRESS.matches(clean)        -> ClipboardDataType.CRYPTO_ADDRESS
            EMAIL.matches(clean)              -> ClipboardDataType.EMAIL
            URL.containsMatchIn(content)      -> ClipboardDataType.URL
            PHONE_NG.matches(clean)           -> ClipboardDataType.PHONE_NUMBER
            PHONE_INTL.matches(clean)         -> ClipboardDataType.PHONE_NUMBER
            NUBAN_NG.matches(clean)           -> ClipboardDataType.NATIONAL_ID
            NIN_NG.matches(clean) && clean.length == 11 -> ClipboardDataType.NATIONAL_ID
            PIN.matches(clean)                -> ClipboardDataType.PASSWORD
            PASSWORD_HINT.containsMatchIn(content) -> ClipboardDataType.PASSWORD
            SECRET_KEY.matches(clean) && clean.length >= 32 -> ClipboardDataType.PASSWORD
            else                              -> ClipboardDataType.PLAIN_TEXT
        }
    }

    private fun maskContent(content: String, type: ClipboardDataType): Pair<String, Boolean> {
        return when (type) {
            ClipboardDataType.CREDIT_CARD -> {
                val digits = content.replace(" ", "").replace("-", "")
                "****-****-****-${digits.takeLast(4)}" to true
            }
            ClipboardDataType.PASSWORD -> {
                "•".repeat(minOf(content.length, 12)) to true
            }
            ClipboardDataType.NATIONAL_ID -> {
                val visible = content.take(3)
                "$visible${"*".repeat(content.length - 3)}" to true
            }
            ClipboardDataType.CRYPTO_ADDRESS -> {
                "${content.take(8)}…${content.takeLast(6)}" to true
            }
            ClipboardDataType.PHONE_NUMBER -> {
                val last4 = content.takeLast(4)
                "****$last4" to true
            }
            ClipboardDataType.EMAIL -> {
                val parts = content.split("@")
                if (parts.size == 2) {
                    val user = parts[0]
                    val masked = if (user.length > 2)
                        "${user.take(2)}${"*".repeat(user.length - 2)}@${parts[1]}"
                    else "${user}***@${parts[1]}"
                    masked to false
                } else content.take(40) to false
            }
            else -> content.take(40) to false
        }
    }

    private fun assessRisk(
        content: String,
        type: ClipboardDataType,
        pkg: String
    ): Pair<ClipboardRisk, String> {

        // Intrinsically critical data types
        if (type == ClipboardDataType.CREDIT_CARD)
            return ClipboardRisk.CRITICAL to "Credit card number detected in clipboard"

        if (type == ClipboardDataType.NATIONAL_ID)
            return ClipboardRisk.CRITICAL to "National ID / BVN / account number in clipboard"

        if (type == ClipboardDataType.CRYPTO_ADDRESS)
            return ClipboardRisk.CRITICAL to "Crypto wallet address — clipboard hijacking risk"

        if (type == ClipboardDataType.PASSWORD)
            return ClipboardRisk.CRITICAL to "Password or secret key detected in clipboard"

        // Suspicious access patterns
        if (pkg in SUSPICIOUS_CLIPBOARD_APPS)
            return ClipboardRisk.CRITICAL to "$pkg has no legitimate reason to read clipboard"

        if (!TRUSTED_CLIPBOARD_APPS.any { pkg.startsWith(it) }) {
            if (type == ClipboardDataType.PHONE_NUMBER)
                return ClipboardRisk.SUSPICIOUS to "Phone number accessed by $pkg"
            if (type == ClipboardDataType.EMAIL)
                return ClipboardRisk.SUSPICIOUS to "Email address accessed by $pkg"
            if (content.length > 200)
                return ClipboardRisk.SUSPICIOUS to "Large clipboard content (${ content.length} chars) accessed by untrusted app"
        }

        return ClipboardRisk.SAFE to "Normal clipboard access"
    }

    fun isTrustedApp(pkg: String) = TRUSTED_CLIPBOARD_APPS.any { pkg.startsWith(it) }
}
