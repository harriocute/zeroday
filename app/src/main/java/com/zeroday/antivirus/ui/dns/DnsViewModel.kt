package com.zeroday.antivirus.ui.dns

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.zeroday.antivirus.dns.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class DnsUiState(
    val isEnabled: Boolean = false,
    val vpnPermissionNeeded: Boolean = false,
    val blocklistSize: Int = 0,
    val totalBlocked: Int = 0,
    val totalAllowed: Int = 0,
    val blockRate: Float = 0f,
    val uniqueBlocked: Int = 0,
    val recentLog: List<DnsLogEntry> = emptyList(),
    val categoryFilter: BlockAction? = null,
    val adsEnabled: Boolean = true,
    val trackingEnabled: Boolean = true,
    val malwareEnabled: Boolean = true,
    val cryptominingEnabled: Boolean = true,
    val phishingEnabled: Boolean = true
)

class DnsViewModel(application: Application) : AndroidViewModel(application) {

    private val db = ZerodayDnsDatabase.getInstance(application)
    private val dao = db.dnsDao()
    private val prefs = application.getSharedPreferences("zeroday_prefs",
        android.content.Context.MODE_PRIVATE)

    private val _isEnabled = MutableStateFlow(
        prefs.getBoolean("dns_blocker_enabled", false)
    )

    private val _filter = MutableStateFlow<BlockAction?>(null)

    val uiState: StateFlow<DnsUiState> = combine(
        _isEnabled,
        dao.getBlocklistSize(),
        dao.getTotalBlocked(),
        dao.getTotalAllowed(),
        dao.getUniqueBlockedDomains()
    ) { enabled, blocklistSize, blocked, allowed, unique ->
        val total = (blocked + allowed).toFloat()
        DnsUiState(
            isEnabled     = enabled,
            blocklistSize = blocklistSize,
            totalBlocked  = blocked,
            totalAllowed  = allowed,
            blockRate     = if (total > 0) blocked / total else 0f,
            uniqueBlocked = unique
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), DnsUiState())

    val recentLog: Flow<List<DnsLogEntry>> = _filter.flatMapLatest { filter ->
        when (filter) {
            BlockAction.BLOCKED  -> dao.getBlockedLog()
            else                 -> dao.getRecentLog()
        }
    }

    val customRules: Flow<List<BlockedDomain>> = dao.getCustomRules()

    fun setEnabled(enabled: Boolean) {
        _isEnabled.value = enabled
        prefs.edit().putBoolean("dns_blocker_enabled", enabled).apply()
    }

    fun setFilter(action: BlockAction?) {
        _filter.value = action
    }

    fun addCustomRule(domain: String) = viewModelScope.launch {
        val blocker = DnsBlocker(getApplication())
        blocker.addCustomRule(domain.trim().lowercase())
    }

    fun removeCustomRule(domain: String) = viewModelScope.launch {
        val blocker = DnsBlocker(getApplication())
        blocker.removeRule(domain)
    }

    fun clearLog() = viewModelScope.launch {
        dao.clearLog()
    }

    fun purgeOldLogs() = viewModelScope.launch {
        val sevenDaysAgo = System.currentTimeMillis() - (7L * 24 * 60 * 60 * 1000)
        dao.purgeOldLogs(sevenDaysAgo)
    }
}
