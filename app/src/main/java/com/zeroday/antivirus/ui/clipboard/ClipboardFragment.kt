package com.zeroday.antivirus.ui.clipboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.tabs.TabLayout
import com.zeroday.antivirus.clipboard.ClipboardMonitorService
import com.zeroday.antivirus.clipboard.ClipboardRisk
import com.zeroday.antivirus.databinding.FragmentClipboardBinding
import kotlinx.coroutines.launch

class ClipboardFragment : Fragment() {

    private var _binding: FragmentClipboardBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ClipboardViewModel by viewModels()
    private lateinit var adapter: ClipboardAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentClipboardBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = ClipboardAdapter { entry ->
            // Show detail bottom sheet on tap
            ClipboardDetailSheet.newInstance(entry.id)
                .show(childFragmentManager, "detail")
        }

        binding.rvClipboard.layoutManager = LinearLayoutManager(requireContext())
        binding.rvClipboard.adapter = adapter

        // Toggle monitor
        binding.switchMonitor.setOnCheckedChangeListener { _, isChecked ->
            viewModel.setMonitorEnabled(isChecked)
            if (isChecked) ClipboardMonitorService.start(requireContext())
            else ClipboardMonitorService.stop(requireContext())
            updateMonitorStatus(isChecked)
        }

        // Tab filter: All / Suspicious
        binding.tabFilter.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                viewModel.setFilter(tab.position == 1)
            }
            override fun onTabUnselected(tab: TabLayout.Tab?) {}
            override fun onTabReselected(tab: TabLayout.Tab?) {}
        })

        binding.btnClearLog.setOnClickListener {
            viewModel.clearLog()
        }

        observeData()
    }

    private fun observeData() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                binding.switchMonitor.isChecked = state.isMonitoring
                updateMonitorStatus(state.isMonitoring)

                // Stats cards
                binding.tvTotalAccess.text  = state.totalAccess.toString()
                binding.tvSuspicious.text   = state.suspiciousCount.toString()
                binding.tvCritical.text     = state.criticalCount.toString()
                binding.tvAppsMonitored.text = state.uniqueApps.toString()

                // Risk color on suspicious count
                val suspColor = if (state.suspiciousCount > 0)
                    requireContext().getColor(com.zeroday.antivirus.R.color.danger)
                else requireContext().getColor(com.zeroday.antivirus.R.color.accent_green)
                binding.tvSuspicious.setTextColor(suspColor)

                // List
                adapter.submitList(state.entries)
                binding.tvEmpty.visibility =
                    if (state.entries.isEmpty()) View.VISIBLE else View.GONE
            }
        }
    }

    private fun updateMonitorStatus(active: Boolean) {
        binding.tvMonitorStatus.text = if (active) "ACTIVE" else "INACTIVE"
        val color = if (active)
            requireContext().getColor(com.zeroday.antivirus.R.color.accent_green)
        else
            requireContext().getColor(com.zeroday.antivirus.R.color.text_muted)
        binding.tvMonitorStatus.setTextColor(color)
        binding.ivStatusDot.setColorFilter(color)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
