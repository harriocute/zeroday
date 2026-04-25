package com.zeroday.antivirus.ui.clipboard

import android.app.Application
import android.content.SharedPreferences
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.zeroday.antivirus.clipboard.ClipboardEntry
import com.zeroday.antivirus.clipboard.ClipboardRisk
import com.zeroday.antivirus.model.ZerodayDatabase
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class ClipboardUiState(
    val isMonitoring: Boolean = false,
    val entries: List<ClipboardEntry> = emptyList(),
    val totalAccess: Int = 0,
    val suspiciousCount: Int = 0,
    val criticalCount: Int = 0,
    val uniqueApps: Int = 0,
    val showSuspiciousOnly: Boolean = false
)

class ClipboardViewModel(application: Application) : AndroidViewModel(application) {

    private val db = ZerodayDatabase.getInstance(application)
    private val prefs: SharedPreferences =
        application.getSharedPreferences("zeroday_prefs", android.content.Context.MODE_PRIVATE)

    private val _filterSuspicious = MutableStateFlow(false)
    private val _isMonitoring = MutableStateFlow(
        prefs.getBoolean("clipboard_monitor_enabled", false)
    )

    val uiState: StateFlow<ClipboardUiState> = combine(
        _isMonitoring,
        _filterSuspicious,
        db.clipboardDao().getAll()
    ) { monitoring, filterSuspicious, allEntries ->

        val filtered = if (filterSuspicious)
            allEntries.filter { it.riskLevel != ClipboardRisk.SAFE }
        else allEntries

        ClipboardUiState(
            isMonitoring     = monitoring,
            entries          = filtered,
            totalAccess      = allEntries.size,
            suspiciousCount  = allEntries.count { it.riskLevel == ClipboardRisk.SUSPICIOUS },
            criticalCount    = allEntries.count { it.riskLevel == ClipboardRisk.CRITICAL },
            uniqueApps       = allEntries.map { it.accessedByPackage }.distinct().size,
            showSuspiciousOnly = filterSuspicious
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), ClipboardUiState())

    fun setMonitorEnabled(enabled: Boolean) {
        _isMonitoring.value = enabled
        prefs.edit().putBoolean("clipboard_monitor_enabled", enabled).apply()
    }

    fun setFilter(suspiciousOnly: Boolean) {
        _filterSuspicious.value = suspiciousOnly
    }

    fun clearLog() = viewModelScope.launch {
        db.clipboardDao().clearAll()
    }
}
