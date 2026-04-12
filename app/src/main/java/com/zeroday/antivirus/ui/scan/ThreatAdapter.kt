package com.zeroday.antivirus.ui.scan

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.zeroday.antivirus.R
import com.zeroday.antivirus.databinding.ItemThreatBinding
import com.zeroday.antivirus.model.ThreatLevel
import com.zeroday.antivirus.model.ThreatResult

class ThreatAdapter(
    private val onQuarantine: (ThreatResult) -> Unit,
    private val onDelete: (ThreatResult) -> Unit
) : ListAdapter<ThreatResult, ThreatAdapter.ThreatViewHolder>(DiffCallback) {

    companion object DiffCallback : DiffUtil.ItemCallback<ThreatResult>() {
        override fun areItemsTheSame(a: ThreatResult, b: ThreatResult) = a.id == b.id
        override fun areContentsTheSame(a: ThreatResult, b: ThreatResult) = a == b
    }

    inner class ThreatViewHolder(private val binding: ItemThreatBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(threat: ThreatResult) {
            binding.tvAppName.text = threat.appName
            binding.tvPackage.text = threat.packageName
            binding.tvDescription.text = threat.description
            binding.tvConfidence.text = "AI: ${(threat.aiConfidence * 100).toInt()}%"

            val (label, colorRes) = when (threat.threatLevel) {
                ThreatLevel.CRITICAL -> Pair("CRITICAL", R.color.danger)
                ThreatLevel.HIGH -> Pair("HIGH", R.color.danger)
                ThreatLevel.MEDIUM -> Pair("MEDIUM", R.color.warning)
                ThreatLevel.LOW -> Pair("LOW", R.color.warning)
                ThreatLevel.CLEAN -> Pair("CLEAN", R.color.accent_green)
            }

            binding.tvThreatLevel.text = label
            binding.tvThreatLevel.setTextColor(
                ContextCompat.getColor(binding.root.context, colorRes)
            )

            binding.btnQuarantine.visibility = if (threat.isQuarantined || threat.threatLevel == ThreatLevel.CLEAN)
                android.view.View.GONE else android.view.View.VISIBLE

            binding.btnQuarantine.setOnClickListener { onQuarantine(threat) }
            binding.btnDelete.setOnClickListener { onDelete(threat) }

            if (threat.isQuarantined) {
                binding.tvQuarantined.visibility = android.view.View.VISIBLE
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ThreatViewHolder {
        val binding = ItemThreatBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ThreatViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ThreatViewHolder, position: Int) {
        holder.bind(getItem(position))
    }
}
