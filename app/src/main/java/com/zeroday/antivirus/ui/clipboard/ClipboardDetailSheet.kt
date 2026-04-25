package com.zeroday.antivirus.ui.clipboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.zeroday.antivirus.R
import com.zeroday.antivirus.clipboard.ClipboardRisk
import com.zeroday.antivirus.databinding.SheetClipboardDetailBinding
import com.zeroday.antivirus.model.ZerodayDatabase
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

class ClipboardDetailSheet : BottomSheetDialogFragment() {

    private var _binding: SheetClipboardDetailBinding? = null
    private val binding get() = _binding!!

    companion object {
        private const val ARG_ID = "entry_id"
        fun newInstance(id: Int) = ClipboardDetailSheet().apply {
            arguments = Bundle().apply { putInt(ARG_ID, id) }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = SheetClipboardDetailBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val id = arguments?.getInt(ARG_ID) ?: return

        viewLifecycleOwner.lifecycleScope.launch {
            val db = ZerodayDatabase.getInstance(requireContext())
            val entry = db.clipboardDao().getById(id) ?: return@launch
            val fmt = SimpleDateFormat("MMMM d, yyyy 'at' h:mm:ss a", Locale.getDefault())

            binding.tvDetailAppName.text  = entry.accessedByAppName
            binding.tvDetailPackage.text  = entry.accessedByPackage
            binding.tvDetailTime.text     = fmt.format(Date(entry.timestamp))
            binding.tvDetailDataType.text = entry.dataType.name.replace("_", " ")
            binding.tvDetailLength.text   = "${entry.contentLength} characters"
            binding.tvDetailPreview.text  = if (entry.isMasked)
                "🔒 ${entry.contentPreview}\n(Content masked for privacy)"
            else entry.contentPreview
            binding.tvDetailReason.text   = entry.riskReason
            binding.tvDetailHash.text     = entry.contentHash.take(16) + "…"

            val (label, color) = when (entry.riskLevel) {
                ClipboardRisk.CRITICAL   -> "CRITICAL" to R.color.danger
                ClipboardRisk.SUSPICIOUS -> "SUSPICIOUS" to R.color.warning
                ClipboardRisk.SAFE       -> "SAFE" to R.color.accent_green
            }
            binding.tvDetailRisk.text = label
            binding.tvDetailRisk.setTextColor(
                ContextCompat.getColor(requireContext(), color)
            )

            binding.btnClose.setOnClickListener { dismiss() }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
