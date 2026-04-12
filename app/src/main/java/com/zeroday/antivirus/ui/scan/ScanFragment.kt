package com.zeroday.antivirus.ui.scan

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.zeroday.antivirus.databinding.FragmentScanBinding
import kotlinx.coroutines.launch

class ScanFragment : Fragment() {

    private var _binding: FragmentScanBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ScanViewModel by viewModels()
    private lateinit var adapter: ThreatAdapter

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentScanBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = ThreatAdapter(
            onQuarantine = { threat -> viewModel.quarantine(threat.id) },
            onDelete = { threat -> viewModel.deleteThreat(threat.id) }
        )

        binding.rvThreats.layoutManager = LinearLayoutManager(requireContext())
        binding.rvThreats.adapter = adapter

        binding.btnStartScan.setOnClickListener {
            viewModel.startScan()
        }

        lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                updateUI(state)
            }
        }

        lifecycleScope.launch {
            viewModel.allThreats.collect { threats ->
                adapter.submitList(threats)
            }
        }
    }

    private fun updateUI(state: ScanUiState) {
        with(binding) {
            progressBar.progress = (state.progress * 100).toInt()
            tvProgress.text = "${(state.progress * 100).toInt()}%"
            tvCurrentApp.text = if (state.isScanning) "Scanning: ${state.currentApp}" else ""
            tvScanCount.text = if (state.isScanning) "${state.currentIndex}/${state.totalApps} apps" else ""

            btnStartScan.isEnabled = !state.isScanning
            btnStartScan.text = if (state.isScanning) "Scanning..." else "Start AI Scan"

            progressGroup.visibility = if (state.isScanning) View.VISIBLE else View.GONE

            state.stats?.let { stats ->
                tvScanResult.visibility = View.VISIBLE
                tvScanResult.text = buildString {
                    append("Scan complete — ")
                    append("${stats.threatsFound} threats, ")
                    append("${stats.atRisk} at risk, ")
                    append("${stats.cleanApps} clean")
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
