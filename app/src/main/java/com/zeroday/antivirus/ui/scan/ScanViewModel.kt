package com.zeroday.antivirus.ui.scan

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.zeroday.antivirus.model.ScanStats
import com.zeroday.antivirus.model.ThreatResult
import com.zeroday.antivirus.model.ZerodayDatabase
import com.zeroday.antivirus.scanner.ScanProgress
import com.zeroday.antivirus.scanner.ZerodayScanner
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class ScanUiState(
    val isScanning: Boolean = false,
    val progress: Float = 0f,
    val currentApp: String = "",
    val currentIndex: Int = 0,
    val totalApps: Int = 0,
    val results: List<ThreatResult> = emptyList(),
    val stats: ScanStats? = null,
    val error: String? = null
)

class ScanViewModel(application: Application) : AndroidViewModel(application) {

    private val scanner = ZerodayScanner(application)
    private val db = ZerodayDatabase.getInstance(application)

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    val allThreats = db.threatDao().getAllThreats()
    val activeThreatCount = db.threatDao().getActiveThreatCount()

    fun startScan() {
        if (_uiState.value.isScanning) return

        viewModelScope.launch {
            _uiState.update { it.copy(isScanning = true, error = null, results = emptyList()) }

            scanner.scanAllApps().collect { progress ->
                when (progress) {
                    is ScanProgress.Started -> {
                        _uiState.update { it.copy(totalApps = progress.total) }
                    }
                    is ScanProgress.Scanning -> {
                        val pct = progress.current.toFloat() / progress.total.toFloat()
                        _uiState.update {
                            it.copy(
                                progress = pct,
                                currentApp = progress.appName,
                                currentIndex = progress.current
                            )
                        }
                    }
                    is ScanProgress.Complete -> {
                        db.threatDao().clearAll()
                        db.threatDao().insertAll(progress.results)
                        _uiState.update {
                            it.copy(
                                isScanning = false,
                                progress = 1f,
                                results = progress.results,
                                stats = progress.stats
                            )
                        }
                    }
                    is ScanProgress.Error -> {
                        _uiState.update { it.copy(isScanning = false, error = progress.message) }
                    }
                }
            }
        }
    }

    fun quarantine(threatId: Int) {
        viewModelScope.launch {
            db.threatDao().quarantine(threatId)
        }
    }

    fun deleteThreat(threatId: Int) {
        viewModelScope.launch {
            db.threatDao().delete(threatId)
        }
    }
}
