package com.zeroday.antivirus.util

import android.content.pm.PackageInfo
import android.os.Build
import java.security.MessageDigest

object HashUtil {

    fun getSignatureHash(pkg: PackageInfo): String {
        return try {
            val sig = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkg.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                pkg.signatures?.firstOrNull()?.toByteArray()
            }
            sig?.let { sha256(it) } ?: "unknown"
        } catch (e: Exception) {
            "unknown"
        }
    }

    fun sha256(input: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input)
        return hash.joinToString("") { "%02x".format(it) }
    }

    fun sha256(input: String): String = sha256(input.toByteArray())

    fun md5(input: String): String {
        val digest = MessageDigest.getInstance("MD5")
        val hash = digest.digest(input.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }
}
