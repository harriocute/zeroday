package com.zeroday.antivirus.ui.dns

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.snackbar.Snackbar
import com.zeroday.antivirus.dns.BlockAction
import com.zeroday.antivirus.dns.DnsVpnService
import com.zeroday.antivirus.databinding.FragmentDnsBinding
import kotlinx.coroutines.launch

class DnsFragment : Fragment() {

    private var _binding: FragmentDnsBinding? = null
    private val binding get() = _binding!!
    private val viewModel: DnsViewModel by viewModels()
    private lateinit var logAdapter: DnsLogAdapter

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            enableDns()
        } else {
            binding.switchDns.isChecked = false
            Snackbar.make(binding.root, "VPN permission required for DNS blocking", Snackbar.LENGTH_LONG).show()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentDnsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        logAdapter = DnsLogAdapter()
        binding.rvDnsLog.layoutManager = LinearLayoutManager(requireContext())
        binding.rvDnsLog.adapter = logAdapter

        // Toggle DNS blocker
        binding.switchDns.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                val prepareIntent = VpnService.prepare(requireContext())
                if (prepareIntent != null) {
                    vpnPermissionLauncher.launch(prepareIntent)
                } else {
                    enableDns()
                }
            } else {
                disableDns()
            }
        }

        // Tab filter
        binding.chipAll.setOnClickListener { viewModel.setFilter(null) }
        binding.chipBlocked.setOnClickListener { viewModel.setFilter(BlockAction.BLOCKED) }
        binding.chipAllowed.setOnClickListener { viewModel.setFilter(BlockAction.ALLOWED) }

        // Add custom rule
        binding.btnAddRule.setOnClickListener { showAddRuleDialog() }

        // Clear log
        binding.btnClearLog.setOnClickListener { viewModel.clearLog() }

        observeState()
    }

    private fun observeState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                binding.switchDns.isChecked = state.isEnabled
                updateStatusIndicator(state.isEnabled)

                binding.tvBlocklistSize.text = "${state.blocklistSize.formatCount()} domains"
                binding.tvTotalBlocked.text  = state.totalBlocked.formatCount()
                binding.tvTotalAllowed.text  = state.totalAllowed.formatCount()
                binding.tvBlockRate.text     = "${(state.blockRate * 100).toInt()}%"
                binding.tvUniqueBlocked.text = state.uniqueBlocked.formatCount()

                // Animate block rate bar
                binding.progressBlockRate.progress = (state.blockRate * 100).toInt()
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.recentLog.collect { log ->
                logAdapter.submitList(log)
                binding.tvEmpty.visibility = if (log.isEmpty()) View.VISIBLE else View.GONE
            }
        }
    }

    private fun enableDns() {
        viewModel.setEnabled(true)
        DnsVpnService.start(requireContext())
        Snackbar.make(binding.root, "✓ DNS Blocker activated", Snackbar.LENGTH_SHORT).show()
    }

    private fun disableDns() {
        viewModel.setEnabled(false)
        DnsVpnService.stop(requireContext())
        updateStatusIndicator(false)
    }

    private fun showAddRuleDialog() {
        val input = EditText(requireContext()).apply {
            hint = "e.g. ads.example.com"
            setPadding(48, 32, 48, 32)
        }
        AlertDialog.Builder(requireContext())
            .setTitle("Block Custom Domain")
            .setMessage("Enter a domain to block. Subdomains are blocked automatically.")
            .setView(input)
            .setPositiveButton("Block") { _, _ ->
                val domain = input.text.toString().trim()
                if (domain.isNotEmpty()) {
                    viewModel.addCustomRule(domain)
                    Snackbar.make(binding.root, "✓ $domain added to blocklist",
                        Snackbar.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun updateStatusIndicator(active: Boolean) {
        binding.tvDnsStatus.text = if (active) "ACTIVE" else "INACTIVE"
        val color = if (active)
            requireContext().getColor(com.zeroday.antivirus.R.color.accent_green)
        else
            requireContext().getColor(com.zeroday.antivirus.R.color.text_muted)
        binding.tvDnsStatus.setTextColor(color)
        binding.ivStatusDot.setColorFilter(color)
    }

    private fun Int.formatCount(): String = when {
        this >= 1_000_000 -> "${this / 1_000_000}M"
        this >= 1_000     -> "${this / 1_000}K"
        else              -> toString()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
