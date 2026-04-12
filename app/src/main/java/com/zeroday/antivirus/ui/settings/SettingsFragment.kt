package com.zeroday.antivirus.ui.settings

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.work.*
import com.zeroday.antivirus.databinding.FragmentSettingsBinding
import com.zeroday.antivirus.service.ProtectionService
import com.zeroday.antivirus.scanner.ScheduledScanWorker
import java.util.concurrent.TimeUnit

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.switchRealtime.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) ProtectionService.start(requireContext())
            else ProtectionService.stop(requireContext())
        }

        binding.switchAutoScan.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) scheduleAutoScan() else cancelAutoScan()
        }

        binding.switchRealtime.isChecked = true
        binding.switchAutoScan.isChecked = true
    }

    private fun scheduleAutoScan() {
        val request = PeriodicWorkRequestBuilder<ScheduledScanWorker>(24, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .build()
        WorkManager.getInstance(requireContext())
            .enqueueUniquePeriodicWork("zeroday_scan", ExistingPeriodicWorkPolicy.KEEP, request)
    }

    private fun cancelAutoScan() {
        WorkManager.getInstance(requireContext()).cancelUniqueWork("zeroday_scan")
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
