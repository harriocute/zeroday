package com.zeroday.antivirus.ui.home

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.zeroday.antivirus.R
import com.zeroday.antivirus.databinding.FragmentHomeBinding
import com.zeroday.antivirus.model.ThreatLevel
import kotlinx.coroutines.launch

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!
    private val viewModel: HomeViewModel by viewModels()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnScan.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_scan)
        }

        binding.cardWifi.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_threats)
        }

        binding.switchRealtime.setOnCheckedChangeListener { _, _ ->
            viewModel.toggleRealTimeProtection()
        }

        lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                updateUI(state)
            }
        }
    }

    private fun updateUI(state: HomeUiState) {
        binding.tvThreatCount.text = state.threatCount.toString()
        binding.tvAtRisk.text = state.atRiskCount.toString()
        binding.tvClean.text = state.cleanCount.toString()
        binding.switchRealtime.isChecked = state.realTimeProtection

        val (statusText, statusColor) = when (state.overallRisk) {
            ThreatLevel.CRITICAL -> Pair("CRITICAL THREAT", R.color.danger)
            ThreatLevel.HIGH -> Pair("HIGH RISK", R.color.danger)
            ThreatLevel.MEDIUM -> Pair("MEDIUM RISK", R.color.warning)
            ThreatLevel.LOW -> Pair("LOW RISK", R.color.warning)
            ThreatLevel.CLEAN -> Pair("PROTECTED", R.color.accent_green)
        }

        binding.tvStatus.text = statusText
        binding.tvStatus.setTextColor(requireContext().getColor(statusColor))

        binding.tvWifiRisk.text = when (state.wifiRisk) {
            ThreatLevel.CLEAN -> "WiFi: SECURE"
            ThreatLevel.LOW, ThreatLevel.MEDIUM -> "WiFi: AT RISK"
            else -> "WiFi: THREAT DETECTED"
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
