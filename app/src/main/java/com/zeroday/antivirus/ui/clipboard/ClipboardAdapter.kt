package com.zeroday.antivirus.ui.clipboard

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.zeroday.antivirus.R
import com.zeroday.antivirus.clipboard.ClipboardEntry
import com.zeroday.antivirus.clipboard.ClipboardRisk
import com.zeroday.antivirus.clipboard.ClipboardDataType
import com.zeroday.antivirus.databinding.ItemClipboardBinding
import java.text.SimpleDateFormat
import java.util.*

class ClipboardAdapter(
    private val onClick: (ClipboardEntry) -> Unit
) : ListAdapter<ClipboardEntry, ClipboardAdapter.VH>(Diff) {

    companion object Diff : DiffUtil.ItemCallback<ClipboardEntry>() {
        override fun areItemsTheSame(a: ClipboardEntry, b: ClipboardEntry) = a.id == b.id
        override fun areContentsTheSame(a: ClipboardEntry, b: ClipboardEntry) = a == b
    }

    private val timeFormat = SimpleDateFormat("MMM d, h:mm a", Locale.getDefault())

    inner class VH(private val b: ItemClipboardBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(entry: ClipboardEntry) {
            b.tvAppName.text     = entry.accessedByAppName
            b.tvPackage.text     = entry.accessedByPackage
            b.tvPreview.text     = if (entry.isMasked) "🔒 ${entry.contentPreview}"
                                   else entry.contentPreview
            b.tvTime.text        = timeFormat.format(Date(entry.timestamp))
            b.tvDataType.text    = formatDataType(entry.dataType)
            b.tvRiskReason.text  = entry.riskReason

            val (riskLabel, riskColor, bgDrawable) = when (entry.riskLevel) {
                ClipboardRisk.CRITICAL   ->
                    Triple("CRITICAL", R.color.danger, R.drawable.bg_badge_danger)
                ClipboardRisk.SUSPICIOUS ->
                    Triple("SUSPICIOUS", R.color.warning, R.drawable.bg_badge_warning)
                ClipboardRisk.SAFE       ->
                    Triple("SAFE", R.color.accent_green, R.drawable.bg_badge_green)
            }

            b.tvRiskBadge.text = riskLabel
            b.tvRiskBadge.setTextColor(ContextCompat.getColor(b.root.context, riskColor))
            b.tvRiskBadge.setBackgroundResource(bgDrawable)

            // Left accent bar color
            b.viewAccent.setBackgroundColor(
                ContextCompat.getColor(b.root.context, riskColor)
            )

            b.tvDataTypeIcon.text = dataTypeIcon(entry.dataType)

            b.root.setOnClickListener { onClick(entry) }
        }
    }

    private fun formatDataType(type: ClipboardDataType) = when (type) {
        ClipboardDataType.CREDIT_CARD    -> "Credit Card"
        ClipboardDataType.PASSWORD       -> "Password / Secret"
        ClipboardDataType.PHONE_NUMBER   -> "Phone Number"
        ClipboardDataType.EMAIL          -> "Email Address"
        ClipboardDataType.URL            -> "URL / Link"
        ClipboardDataType.CRYPTO_ADDRESS -> "Crypto Address"
        ClipboardDataType.NATIONAL_ID    -> "National ID / BVN"
        ClipboardDataType.PLAIN_TEXT     -> "Plain Text"
        ClipboardDataType.UNKNOWN        -> "Unknown"
    }

    private fun dataTypeIcon(type: ClipboardDataType) = when (type) {
        ClipboardDataType.CREDIT_CARD    -> "💳"
        ClipboardDataType.PASSWORD       -> "🔑"
        ClipboardDataType.PHONE_NUMBER   -> "📞"
        ClipboardDataType.EMAIL          -> "📧"
        ClipboardDataType.URL            -> "🌐"
        ClipboardDataType.CRYPTO_ADDRESS -> "₿"
        ClipboardDataType.NATIONAL_ID    -> "🪪"
        ClipboardDataType.PLAIN_TEXT     -> "📋"
        ClipboardDataType.UNKNOWN        -> "❓"
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(ItemClipboardBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) =
        holder.bind(getItem(position))
}
