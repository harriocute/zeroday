package com.zeroday.antivirus.ui.home

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.zeroday.antivirus.model.ThreatLevel
import com.zeroday.antivirus.model.ZerodayDatabase
import com.zeroday.antivirus.scanner.WifiScanner
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class HomeUiState(
    val threatCount: Int = 0,
    val atRiskCount: Int = 0,
    val cleanCount: Int = 0,
    val lastScanTime: Long = 0L,
    val overallRisk: ThreatLevel = ThreatLevel.CLEAN,
    val wifiRisk: ThreatLevel = ThreatLevel.CLEAN,
    val realTimeProtection: Boolean = true
)

class HomeViewModel(application: Application) : AndroidViewModel(application) {

    private val db = ZerodayDatabase.getInstance(application)
    private val wifiScanner = WifiScanner(application)

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    init {
        observeThreats()
        checkWifi()
    }

    private fun observeThreats() {
        viewModelScope.launch {
            db.threatDao().getAllThreats().collect { threats ->
                val active = threats.filter { !it.isQuarantined }
                _uiState.update {
                    it.copy(
                        threatCount = active.count { t ->
                            t.threatLevel == ThreatLevel.CRITICAL || t.threatLevel == ThreatLevel.HIGH
                        },
                        atRiskCount = active.count { t ->
                            t.threatLevel == ThreatLevel.MEDIUM || t.threatLevel == ThreatLevel.LOW
                        },
                        cleanCount = active.count { t -> t.threatLevel == ThreatLevel.CLEAN },
                        overallRisk = when {
                            active.any { t -> t.threatLevel == ThreatLevel.CRITICAL } -> ThreatLevel.CRITICAL
                            active.any { t -> t.threatLevel == ThreatLevel.HIGH } -> ThreatLevel.HIGH
                            active.any { t -> t.threatLevel == ThreatLevel.MEDIUM } -> ThreatLevel.MEDIUM
                            else -> ThreatLevel.CLEAN
                        }
                    )
                }
            }
        }
    }

    private fun checkWifi() {
        viewModelScope.launch {
            val risk = wifiScanner.getCurrentNetworkRisk()
            _uiState.update { it.copy(wifiRisk = risk) }
        }
    }

    fun toggleRealTimeProtection() {
        _uiState.update { it.copy(realTimeProtection = !it.realTimeProtection) }
    }
}
