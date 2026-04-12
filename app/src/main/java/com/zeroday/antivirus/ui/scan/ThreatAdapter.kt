package com.zeroday.antivirus.ui.scan

import android.view.LayoutInflater
import android.view.View
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
) : ListAdapter<ThreatResult, ThreatAdapter.VH>(Diff) {

    companion object Diff : DiffUtil.ItemCallback<ThreatResult>() {
        override fun areItemsTheSame(a: ThreatResult, b: ThreatResult) = a.id == b.id
        override fun areContentsTheSame(a: ThreatResult, b: ThreatResult) = a == b
    }

    inner class VH(private val b: ItemThreatBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(t: ThreatResult) {
            b.tvAppName.text = t.appName
            b.tvPackage.text = t.packageName
            b.tvDescription.text = t.description
            b.tvConfidence.text = "AI Confidence: ${(t.aiConfidence * 100).toInt()}%"

            val (label, color) = when (t.threatLevel) {
                ThreatLevel.CRITICAL -> "CRITICAL" to R.color.danger
                ThreatLevel.HIGH     -> "HIGH"     to R.color.danger
                ThreatLevel.MEDIUM   -> "MEDIUM"   to R.color.warning
                ThreatLevel.LOW      -> "LOW"      to R.color.warning
                ThreatLevel.CLEAN    -> "CLEAN"    to R.color.accent_green
            }
            b.tvThreatLevel.text = label
            b.tvThreatLevel.setTextColor(ContextCompat.getColor(b.root.context, color))

            b.btnQuarantine.visibility =
                if (t.isQuarantined || t.threatLevel == ThreatLevel.CLEAN) View.GONE
                else View.VISIBLE
            b.tvQuarantined.visibility = if (t.isQuarantined) View.VISIBLE else View.GONE

            b.btnQuarantine.setOnClickListener { onQuarantine(t) }
            b.btnDelete.setOnClickListener { onDelete(t) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(ItemThreatBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))
}
