package com.zeroday.antivirus.ui.threats

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.zeroday.antivirus.databinding.FragmentThreatsBinding
import com.zeroday.antivirus.model.ZerodayDatabase
import com.zeroday.antivirus.ui.scan.ThreatAdapter
import kotlinx.coroutines.launch

class ThreatsFragment : Fragment() {

    private var _binding: FragmentThreatsBinding? = null
    private val binding get() = _binding!!
    private lateinit var adapter: ThreatAdapter

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentThreatsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val db = ZerodayDatabase.getInstance(requireContext())

        adapter = ThreatAdapter(
            onQuarantine = { threat ->
                lifecycleScope.launch { db.threatDao().quarantine(threat.id) }
            },
            onDelete = { threat ->
                lifecycleScope.launch { db.threatDao().delete(threat.id) }
            }
        )

        binding.rvThreats.layoutManager = LinearLayoutManager(requireContext())
        binding.rvThreats.adapter = adapter

        lifecycleScope.launch {
            db.threatDao().getNonCleanThreats().collect { threats ->
                adapter.submitList(threats)
                binding.tvEmpty.visibility = if (threats.isEmpty()) View.VISIBLE else View.GONE
                binding.tvThreatCount.text = "${threats.size} threats found"
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
