package com.zeroday.antivirus.ui.scan

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.snackbar.Snackbar
import com.zeroday.antivirus.databinding.FragmentScanBinding
import kotlinx.coroutines.launch

class ScanFragment : Fragment() {

    private var _binding: FragmentScanBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ScanViewModel by viewModels()
    private lateinit var adapter: ThreatAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentScanBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = ThreatAdapter(
            onQuarantine = { threat -> viewModel.quarantine(threat.id) },
            onDelete     = { threat -> viewModel.deleteThreat(threat.id) }
        )
        binding.rvThreats.layoutManager = LinearLayoutManager(requireContext())
        binding.rvThreats.adapter = adapter

        binding.btnStartScan.setOnClickListener { viewModel.startScan() }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.uiState.collect { state -> updateUI(state) }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.allThreats.collect { threats -> adapter.submitList(threats) }
        }
    }

    private fun updateUI(state: ScanUiState) {
        with(binding) {
            // Scan button
            btnStartScan.isEnabled = !state.isScanning
            btnStartScan.text = if (state.isScanning) "Scanning…" else "START AI SCAN"

            // Progress
            progressGroup.visibility = if (state.isScanning) View.VISIBLE else View.GONE
            progressBar.progress = (state.progress * 100).toInt()
            tvProgress.text = "${(state.progress * 100).toInt()}%"
            tvCurrentApp.text = if (state.isScanning) state.currentApp else ""
            tvScanCount.text = if (state.isScanning)
                "${state.currentIndex} / ${state.totalApps} apps" else ""

            // Result summary
            state.stats?.let { stats ->
                tvScanResult.visibility = View.VISIBLE
                tvScanResult.text =
                    "✓ Scan complete — ${stats.threatsFound} threats, " +
                    "${stats.atRisk} at risk, ${stats.cleanApps} clean " +
                    "(${stats.totalScanned} apps in ${stats.scanDurationMs / 1000}s)"
            } ?: run { tvScanResult.visibility = View.GONE }

            // Error
            state.error?.let { err ->
                Snackbar.make(root, err, Snackbar.LENGTH_LONG).show()
                viewModel.clearError()
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
