package com.zeroday.antivirus.dns

import android.content.Context
import androidx.room.*

@Database(
    entities = [BlockedDomain::class, DnsLogEntry::class],
    version = 1,
    exportSchema = false
)
abstract class ZerodayDnsDatabase : RoomDatabase() {
    abstract fun dnsDao(): DnsDao

    companion object {
        @Volatile private var INSTANCE: ZerodayDnsDatabase? = null

        fun getInstance(context: Context): ZerodayDnsDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    ZerodayDnsDatabase::class.java,
                    "zeroday_dns"
                ).fallbackToDestructiveMigration()
                 .build()
                 .also { INSTANCE = it }
            }
    }
}
