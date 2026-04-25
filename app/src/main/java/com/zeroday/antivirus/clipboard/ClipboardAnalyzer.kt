package com.zeroday.antivirus.clipboard

import com.zeroday.antivirus.util.HashUtil

object ClipboardAnalyzer {

    // ── Credit / Debit Cards ─────────────────────────────────────
    // Visa, Mastercard, Amex, Discover, UnionPay, JCB, Diners
    private val CREDIT_CARD = Regex(
        """^(?:4[0-9]{12}(?:[0-9]{3})?""" +
        """|5[1-5][0-9]{14}""" +
        """|2(?:2[2-9][1-9]|[3-6]\d{2}|7[01]\d|720)[0-9]{12}""" +
        """|3[47][0-9]{13}""" +
        """|3(?:0[0-5]|[68][0-9])[0-9]{11}""" +
        """|6(?:011|5[0-9]{2})[0-9]{12}""" +
        """|(?:2131|1800|35\d{3})\d{11}""" +
        """|62[0-9]{14,17})$"""
    )

    // ── IBAN ─────────────────────────────────────────────────────
    private val IBAN = Regex("""^[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}$""")

    // ── US Social Security Number ────────────────────────────────
    private val SSN_US = Regex("""^(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}$""")

    // ── Passwords & Secrets ──────────────────────────────────────
    private val PASSWORD_STRONG = Regex(
        """^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#${'$'}%^&+=!*\-_]).{8,}$"""
    )
    private val API_KEY       = Regex("""(?i)(api[_\-]?key|secret|token|bearer|password|passwd|pwd)\s*[:=]\s*\S{8,}""")
    private val BASE64_SECRET = Regex("""^[A-Za-z0-9+/]{32,}={0,2}$""")
    private val HEX_SECRET    = Regex("""^[0-9a-fA-F]{32,}$""")
    private val PEM_KEY       = Regex("""-----BEGIN .*(PRIVATE|SECRET).*KEY-----""")
    private val MNEMONIC_SEED = Regex("""^(\w+\s){11,23}\w+$""")

    // ── Phone Numbers ─────────────────────────────────────────────
    private val PHONE_E164          = Regex("""^\+[1-9]\d{7,14}$""")
    private val PHONE_US_CA         = Regex("""^(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}$""")
    private val PHONE_INTL_GENERIC  = Regex("""^\+?(?:[0-9][-.\s]?){8,14}[0-9]$""")

    // ── Email ────────────────────────────────────────────────────
    private val EMAIL = Regex("""^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$""")

    // ── URLs ─────────────────────────────────────────────────────
    private val URL = Regex("""https?://[^\s/$.?#].[^\s]*""")

    // ── Crypto Addresses ─────────────────────────────────────────
    private val BTC_LEGACY  = Regex("""^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$""")
    private val BTC_BECH32  = Regex("""^bc1[a-z0-9]{39,59}$""")
    private val ETH         = Regex("""^0x[a-fA-F0-9]{40}$""")
    private val SOLANA      = Regex("""^[1-9A-HJ-NP-Za-km-z]{32,44}$""")
    private val TRON        = Regex("""^T[a-zA-Z0-9]{33}$""")
    private val MONERO      = Regex("""^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$""")
    private val RIPPLE      = Regex("""^r[0-9a-zA-Z]{24,34}$""")
    private val LITECOIN    = Regex("""^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$""")

    // ── National / Government IDs ─────────────────────────────────
    // India
    private val AADHAAR_IN  = Regex("""^[2-9][0-9]{11}$""")       // 12-digit Aadhaar
    private val PAN_IN      = Regex("""^[A-Z]{5}[0-9]{4}[A-Z]$""")// PAN card
    // UK
    private val NIN_UK      = Regex("""^[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]$""")
    private val NHS_UK      = Regex("""^[0-9]{10}$""")
    // Canada
    private val SIN_CA      = Regex("""^[0-9]{9}$""")
    // Brazil
    private val CPF_BR      = Regex("""^[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}$""")
    private val CNPJ_BR     = Regex("""^[0-9]{2}\.[0-9]{3}\.[0-9]{3}/[0-9]{4}-[0-9]{2}$""")
    // Singapore
    private val NRIC_SG     = Regex("""^[STFGM][0-9]{7}[A-Z]$""")
    // South Africa
    private val ID_ZA       = Regex("""^[0-9]{13}$""")
    // Pakistan
    private val CNIC_PK     = Regex("""^[0-9]{5}-[0-9]{7}-[0-9]$""")
    // Indonesia
    private val KTP_ID      = Regex("""^[0-9]{16}$""")
    // Nigeria
    private val BVN_NG      = Regex("""^[0-9]{11}$""")
    private val NUBAN_NG    = Regex("""^[0-9]{10}$""")
    // Germany
    private val STEUER_DE   = Regex("""^[0-9]{11}$""")
    // France
    private val INSEE_FR    = Regex("""^[12][0-9]{2}[0-9]{2}[0-9]{5}[0-9]{3}[0-9]{2}$""")
    // Australia
    private val TFN_AU      = Regex("""^[0-9]{8,9}$""")
    // Generic passport (many countries)
    private val PASSPORT    = Regex("""^[A-Z]{1,2}[0-9]{6,9}$""")

    // ── Trusted apps with legitimate clipboard use ───────────────
    private val TRUSTED_APPS = setOf(
        "com.google.android.gms",
        "com.android.chrome",
        "com.google.android.inputmethod.latin",
        "com.samsung.android.honeyboard",
        "com.swiftkey.swiftkeyapp",
        "com.touchtype.swiftkey",
        "com.microsoft.swiftkey",
        "com.google.android.apps.docs",
        "com.microsoft.office.word",
        "com.microsoft.office.excel",
        "com.microsoft.office.outlook",
        "com.google.android.keep",
        "com.evernote",
        "com.notion.id",
        "com.1password",
        "com.lastpass.lpandroid",
        "com.dashlane",
        "com.bitwarden.mobile",
        "com.google.android.apps.translate",
        "com.grammarly.android.keyboard",
        "com.whatsapp",
        "org.telegram.messenger",
        "com.discord"
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
        val dataType = detectDataType(trimmed)
        val (masked, shouldMask) = maskContent(trimmed, dataType)
        val (risk, reason) = assessRisk(trimmed, dataType, accessingPackage)
        return AnalysisResult(dataType, risk, reason, masked, shouldMask, hash)
    }

    private fun detectDataType(content: String): ClipboardDataType {
        val clean = content.replace(Regex("[\\s\\-()./]"), "")
        val upper = clean.uppercase()

        return when {
            // Financial cards (highest priority)
            CREDIT_CARD.matches(clean)                              -> ClipboardDataType.CREDIT_CARD
            IBAN.matches(upper) && upper.length in 15..34           -> ClipboardDataType.NATIONAL_ID
            SSN_US.matches(content.trim())                          -> ClipboardDataType.NATIONAL_ID
            CPF_BR.matches(content.trim())                          -> ClipboardDataType.NATIONAL_ID
            CNPJ_BR.matches(content.trim())                         -> ClipboardDataType.NATIONAL_ID
            CNIC_PK.matches(content.trim())                         -> ClipboardDataType.NATIONAL_ID

            // Crypto (before generic numbers)
            ETH.matches(clean)                                      -> ClipboardDataType.CRYPTO_ADDRESS
            BTC_LEGACY.matches(clean)                               -> ClipboardDataType.CRYPTO_ADDRESS
            BTC_BECH32.matches(clean)                               -> ClipboardDataType.CRYPTO_ADDRESS
            TRON.matches(clean)                                     -> ClipboardDataType.CRYPTO_ADDRESS
            MONERO.matches(clean) && clean.length == 95             -> ClipboardDataType.CRYPTO_ADDRESS
            RIPPLE.matches(clean)                                   -> ClipboardDataType.CRYPTO_ADDRESS
            LITECOIN.matches(clean)                                 -> ClipboardDataType.CRYPTO_ADDRESS
            MNEMONIC_SEED.matches(content.trim()) &&
                content.trim().split(" ").size in listOf(12, 15, 18, 21, 24) -> ClipboardDataType.CRYPTO_ADDRESS

            // Private keys / secrets
            PEM_KEY.containsMatchIn(content)                        -> ClipboardDataType.PASSWORD
            API_KEY.containsMatchIn(content)                        -> ClipboardDataType.PASSWORD
            PASSWORD_STRONG.matches(content.trim())                 -> ClipboardDataType.PASSWORD
            BASE64_SECRET.matches(clean) && clean.length in 32..512 -> ClipboardDataType.PASSWORD
            HEX_SECRET.matches(clean) && clean.length in 32..64     -> ClipboardDataType.PASSWORD

            // Country-specific IDs
            PAN_IN.matches(upper)                                   -> ClipboardDataType.NATIONAL_ID
            NRIC_SG.matches(upper) && upper.length == 9             -> ClipboardDataType.NATIONAL_ID
            NIN_UK.matches(upper) && upper.length == 9              -> ClipboardDataType.NATIONAL_ID
            PASSPORT.matches(upper) && upper.length in 7..11        -> ClipboardDataType.NATIONAL_ID
            AADHAAR_IN.matches(clean) && clean.length == 12         -> ClipboardDataType.NATIONAL_ID
            INSEE_FR.matches(clean) && clean.length == 15           -> ClipboardDataType.NATIONAL_ID
            KTP_ID.matches(clean) && clean.length == 16             -> ClipboardDataType.NATIONAL_ID
            ID_ZA.matches(clean) && clean.length == 13              -> ClipboardDataType.NATIONAL_ID
            BVN_NG.matches(clean) && clean.length == 11             -> ClipboardDataType.NATIONAL_ID
            NUBAN_NG.matches(clean) && clean.length == 10           -> ClipboardDataType.NATIONAL_ID
            SIN_CA.matches(clean) && clean.length == 9              -> ClipboardDataType.NATIONAL_ID
            TFN_AU.matches(clean) && clean.length in 8..9           -> ClipboardDataType.NATIONAL_ID

            // Contact
            EMAIL.matches(clean)                                    -> ClipboardDataType.EMAIL
            PHONE_E164.matches(clean)                               -> ClipboardDataType.PHONE_NUMBER
            PHONE_US_CA.matches(content.trim())                     -> ClipboardDataType.PHONE_NUMBER
            PHONE_INTL_GENERIC.matches(content.trim()) &&
                clean.length in 8..15                               -> ClipboardDataType.PHONE_NUMBER

            // URLs
            URL.containsMatchIn(content)                            -> ClipboardDataType.URL

            else                                                    -> ClipboardDataType.PLAIN_TEXT
        }
    }

    private fun maskContent(content: String, type: ClipboardDataType): Pair<String, Boolean> {
        return when (type) {
            ClipboardDataType.CREDIT_CARD -> {
                val d = content.filter { it.isDigit() }
                "****-****-****-${d.takeLast(4)}" to true
            }
            ClipboardDataType.PASSWORD ->
                "${content.take(3)}${"•".repeat(minOf(content.length - 3, 20))}" to true
            ClipboardDataType.NATIONAL_ID -> {
                val c = content.filter { it.isLetterOrDigit() }
                "${c.take(3)}${"*".repeat((c.length - 3).coerceAtLeast(0))}" to true
            }
            ClipboardDataType.CRYPTO_ADDRESS ->
                "${content.take(8)}…${content.takeLast(6)}" to true
            ClipboardDataType.PHONE_NUMBER -> {
                val d = content.filter { it.isDigit() }
                "***-***-${d.takeLast(4)}" to true
            }
            ClipboardDataType.EMAIL -> {
                val parts = content.split("@")
                if (parts.size == 2) {
                    val u = parts[0]
                    "${u.take(2)}${"*".repeat((u.length - 3).coerceAtLeast(0))}${u.lastOrNull() ?: ""}@${parts[1]}" to false
                } else content.take(40) to false
            }
            else -> content.take(50) to false
        }
    }

    private fun assessRisk(
        content: String,
        type: ClipboardDataType,
        pkg: String
    ): Pair<ClipboardRisk, String> {
        val isTrusted = TRUSTED_APPS.any { pkg.startsWith(it) }

        return when (type) {
            ClipboardDataType.CREDIT_CARD    ->
                ClipboardRisk.CRITICAL to "Card number detected — clear clipboard immediately"
            ClipboardDataType.NATIONAL_ID    ->
                ClipboardRisk.CRITICAL to "Government ID / account number in clipboard"
            ClipboardDataType.CRYPTO_ADDRESS ->
                ClipboardRisk.CRITICAL to "Crypto address — verify before pasting (hijacking risk)"
            ClipboardDataType.PASSWORD       ->
                if (isTrusted) ClipboardRisk.SUSPICIOUS to "Credential copied from trusted app"
                else ClipboardRisk.CRITICAL to "Password or secret key exposed in clipboard"
            ClipboardDataType.PHONE_NUMBER   ->
                if (!isTrusted) ClipboardRisk.SUSPICIOUS to "Phone number read by $pkg"
                else ClipboardRisk.SAFE to "Normal clipboard access"
            ClipboardDataType.EMAIL          ->
                if (!isTrusted) ClipboardRisk.SUSPICIOUS to "Email address read by $pkg"
                else ClipboardRisk.SAFE to "Normal clipboard access"
            ClipboardDataType.URL            -> {
                val hasSensitiveParam = content.contains(
                    Regex("""(?i)(token|password|secret|key|auth|session)=""")
                )
                if (hasSensitiveParam)
                    ClipboardRisk.SUSPICIOUS to "URL contains sensitive parameters"
                else ClipboardRisk.SAFE to "Normal clipboard access"
            }
            else -> {
                if (!isTrusted && content.length > 500)
                    ClipboardRisk.SUSPICIOUS to "Large content (${content.length} chars) read by $pkg"
                else ClipboardRisk.SAFE to "Normal clipboard access"
            }
        }
    }

    fun isTrustedApp(pkg: String) = TRUSTED_APPS.any { pkg.startsWith(it) }
}
