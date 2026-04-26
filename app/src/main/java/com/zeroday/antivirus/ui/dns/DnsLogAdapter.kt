package com.zeroday.antivirus.ui.dns

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.zeroday.antivirus.R
import com.zeroday.antivirus.databinding.ItemDnsLogBinding
import com.zeroday.antivirus.dns.BlockAction
import com.zeroday.antivirus.dns.BlockCategory
import com.zeroday.antivirus.dns.DnsLogEntry
import java.text.SimpleDateFormat
import java.util.*

class DnsLogAdapter : ListAdapter<DnsLogEntry, DnsLogAdapter.VH>(Diff) {

    companion object Diff : DiffUtil.ItemCallback<DnsLogEntry>() {
        override fun areItemsTheSame(a: DnsLogEntry, b: DnsLogEntry) = a.id == b.id
        override fun areContentsTheSame(a: DnsLogEntry, b: DnsLogEntry) = a == b
    }

    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    inner class VH(private val b: ItemDnsLogBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(e: DnsLogEntry) {
            b.tvDomain.text   = e.domain
            b.tvTime.text     = timeFmt.format(Date(e.timestamp))
            b.tvCategory.text = e.category?.let { categoryLabel(it) } ?: ""

            val (actionLabel, actionColor, icon) = when (e.action) {
                BlockAction.BLOCKED    -> Triple("BLOCKED", R.color.danger, "🚫")
                BlockAction.ALLOWED    -> Triple("ALLOWED", R.color.accent_green, "✓")
                BlockAction.WHITELISTED -> Triple("WHITELISTED", R.color.accent_cyan, "✓")
            }
            b.tvAction.text = "$icon $actionLabel"
            b.tvAction.setTextColor(ContextCompat.getColor(b.root.context, actionColor))

            // Left accent
            b.viewAccent.setBackgroundColor(
                ContextCompat.getColor(b.root.context,
                    if (e.action == BlockAction.BLOCKED) R.color.danger else R.color.accent_green)
            )

            if (e.responseTimeMs > 0) {
                b.tvResponseTime.text = "${e.responseTimeMs}ms"
            } else {
                b.tvResponseTime.text = ""
            }
        }
    }

    private fun categoryLabel(cat: BlockCategory) = when (cat) {
        BlockCategory.ADS         -> "Ads"
        BlockCategory.TRACKING    -> "Tracking"
        BlockCategory.MALWARE     -> "Malware"
        BlockCategory.PHISHING    -> "Phishing"
        BlockCategory.CRYPTOMINING -> "Cryptomining"
        BlockCategory.RANSOMWARE  -> "Ransomware"
        BlockCategory.ADULT       -> "Adult"
        BlockCategory.CUSTOM      -> "Custom Rule"
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(ItemDnsLogBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))
}
