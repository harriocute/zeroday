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

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnScan.setOnClickListener {
            findNavController().navigate(R.id.scanFragment)
        }
        binding.cardWifi.setOnClickListener {
            findNavController().navigate(R.id.threatsFragment)
        }
        binding.switchRealtime.setOnCheckedChangeListener { _, _ ->
            viewModel.toggleRealTimeProtection()
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.uiState.collect { state -> updateUI(state) }
        }
    }

    private fun updateUI(state: HomeUiState) {
        binding.tvThreatCount.text = state.threatCount.toString()
        binding.tvAtRisk.text = state.atRiskCount.toString()
        binding.tvClean.text = state.cleanCount.toString()
        binding.switchRealtime.isChecked = state.realTimeProtection

        val (statusText, colorRes) = when (state.overallRisk) {
            ThreatLevel.CRITICAL -> "CRITICAL" to R.color.danger
            ThreatLevel.HIGH     -> "HIGH RISK" to R.color.danger
            ThreatLevel.MEDIUM   -> "MEDIUM RISK" to R.color.warning
            ThreatLevel.LOW      -> "LOW RISK" to R.color.warning
            ThreatLevel.CLEAN    -> "PROTECTED" to R.color.accent_green
        }
        binding.tvStatus.text = statusText
        binding.tvStatus.setTextColor(requireContext().getColor(colorRes))

        binding.tvWifiRisk.text = when (state.wifiRisk) {
            ThreatLevel.CLEAN                     -> "WiFi: SECURE"
            ThreatLevel.LOW, ThreatLevel.MEDIUM   -> "WiFi: AT RISK"
            else                                   -> "WiFi: THREAT"
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
