import React, { useState, useMemo } from 'react';
import {
  Copy,
  Check,
  Table2,
  FileSpreadsheet,
  Plus,
  Trash2,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Eye,
  Layers,
  Terminal,
  ArrowUpRight,
} from 'lucide-react';
import {
  EaseModeForensicBreakdown,
  StructuredSolanaAlertReport,
  WhitelistClassification,
} from '../services/knowledgeGraphService';

interface StructuredAlertReportViewProps {
  breakdown: EaseModeForensicBreakdown;
  onSelectAddress: (address: string) => void;
  onInvestigateSignature: (signature: string) => void;
}

export interface BatchTransactionRow {
  tokenSymbol: string;
  tokenMintAddress: string;
  txnSignature: string;
  fromResponderSubLabel: string;
  fromResponderAddress: string;
  fromResponderWhitelist: WhitelistClassification;
  toAccountSubLabel: string;
  toAccountAddress: string;
  toAccountWhitelist: WhitelistClassification;
  valueNumberFormatted: string;
  valueTokenSymbol: string;
  eventsTriggeredPrimary: string;
  eventsTriggeredActual: string;
}

const REFERENCE_TWO_TX_BATCH: BatchTransactionRow[] = [
  {
    tokenSymbol: 'JLTXX',
    tokenMintAddress: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    txnSignature:
      'TCdFYA2znTKFBqYG2THR1akPjU7F4kNwsknXmk1MEU3vHoNackgsp4paLFAz9zW2P5hEm83ZPMAoZ4deTdQv6cF',
    fromResponderSubLabel: '(Mint authority)',
    fromResponderAddress: '32E9ipXM6Yoc7n12auPtXL4Z1STBposTmVuvt3btMdmT',
    fromResponderWhitelist: 'INSTITUTIONAL_WHITELISTED',
    toAccountSubLabel: '(Account)',
    toAccountAddress: '6AbAo9hjR9M77923jRUDPbjMeAVciB6ycQHJRvukdMy7',
    toAccountWhitelist: 'INSTITUTIONAL_WHITELISTED',
    valueNumberFormatted: '46,391.53',
    valueTokenSymbol: 'JLTXX',
    eventsTriggeredPrimary: 'Mint',
    eventsTriggeredActual: 'Mint To',
  },
  {
    tokenSymbol: 'JLTXX',
    tokenMintAddress: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    txnSignature:
      '2BDaRNdXFPu3cLnhzXtmA1eACekE9MPW8X8wvyPdQNuGqGHLy25R4nJqxyJAXS7WeCT7ctiYsqqqmD9j5oC2YLY2d',
    fromResponderSubLabel: '(Mint authority)',
    fromResponderAddress: '32E9ipXM6Yoc7n12auPtXL4Z1STBposTmVuvt3btMdmT',
    fromResponderWhitelist: 'INSTITUTIONAL_WHITELISTED',
    toAccountSubLabel: '(Account)',
    toAccountAddress: 'DwWsjJsCic4xF7MPgqSxT7WZGancjGtumbmVVYFK1zXR',
    toAccountWhitelist: 'INSTITUTIONAL_WHITELISTED',
    valueNumberFormatted: '0.01',
    valueTokenSymbol: 'JLTXX',
    eventsTriggeredPrimary: 'Mint',
    eventsTriggeredActual: 'Mint To',
  },
];

function renderCompactProvenanceBadge(
  status: WhitelistClassification,
  isLightTable: boolean
) {
  if (status === 'INSTITUTIONAL_WHITELISTED') {
    return (
      <span
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
          isLightTable
            ? 'bg-emerald-100 text-emerald-900 border border-emerald-300'
            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
        }`}
      >
        <ShieldCheck className="w-3 h-3 shrink-0" />
        WHITELISTED
      </span>
    );
  }
  if (status === 'CORE_PROTOCOL_WHITELISTED') {
    return (
      <span
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
          isLightTable
            ? 'bg-cyan-100 text-cyan-900 border border-cyan-300'
            : 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
        }`}
      >
        <CheckCircle2 className="w-3 h-3 shrink-0" />
        CORE PROTOCOL
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
        isLightTable
          ? 'bg-rose-100 text-rose-900 border border-rose-300'
          : 'bg-rose-500/15 text-rose-300 border border-rose-500/40'
      }`}
    >
      <AlertTriangle className="w-3 h-3 shrink-0" />
      NOT WHITELISTED
    </span>
  );
}

export const StructuredAlertReportView: React.FC<StructuredAlertReportViewProps> = ({
  breakdown,
  onSelectAddress,
  onInvestigateSignature,
}) => {
  const report: StructuredSolanaAlertReport = breakdown.structuredAlertReport;

  // Allow switching between Classic Light-Blue Header Report Table (matching screenshot) and Dark Forensic Table
  const [tableStyleMode, setTableStyleMode] = useState<'classic-report' | 'dark-forensic'>(
    'classic-report'
  );

  // Analyst overrides for Classification, Amount Involved status, and Event Tag prefix
  const [classificationOverride, setClassificationOverride] = useState<
    'Info' | 'Warning' | 'Critical' | null
  >(null);
  const [amountStatusOverride, setAmountStatusOverride] = useState<
    'Normal' | 'High Value' | 'Anomalous' | null
  >(null);
  const [eventProviderTag, setEventProviderTag] = useState<'Hexagate' | 'SOL-MATE' | 'Alert'>(
    'Hexagate'
  );

  // Batch queue of transactions for multi-row "Transactions Detail :" reports
  const [customBatchRows, setCustomBatchRows] = useState<BatchTransactionRow[] | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const activeClassification = classificationOverride || report.classificationLabel;
  const activeAmountStatus = amountStatusOverride || report.amountInvolvedStatusLabel;

  const displayedRows: BatchTransactionRow[] = useMemo(() => {
    if (customBatchRows && customBatchRows.length > 0) {
      return customBatchRows;
    }
    return [report.transactionDetailRow];
  }, [customBatchRows, report.transactionDetailRow]);

  const txCount = displayedRows.length;
  const headerSubjectText = `Alert Notification ${report.networkLabel.toUpperCase()} (${activeClassification.toUpperCase()}) - ${report.dateShortIST} ${report.timeRangeShortIST}`;
  const greetingSummaryText = `Hello Team, We received ${txCount} ${eventProviderTag} alert notification${
    txCount > 1 ? 's' : ''
  } today at ${report.timeRangeShortIST}, for ${txCount} transaction${
    txCount > 1 ? 's' : ''
  }. Please find all alerts attached for your review & kindly acknowledge them as per the mentioned details.`;

  const triggerCopiedFeedback = (key: string) => {
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey((prev) => (prev === key ? null : prev));
    }, 2000);
  };

  const copyRichHtmlAndPlainText = async (
    htmlContent: string,
    plainTextContent: string,
    feedbackKey: string
  ) => {
    try {
      if (typeof ClipboardItem !== 'undefined' && navigator.clipboard?.write) {
        const htmlBlob = new Blob([htmlContent], { type: 'text/html' });
        const textBlob = new Blob([plainTextContent], { type: 'text/plain' });
        await navigator.clipboard.write([
          new ClipboardItem({
            'text/html': htmlBlob,
            'text/plain': textBlob,
          }),
        ]);
        triggerCopiedFeedback(feedbackKey);
        return;
      }
    } catch {
      // Fallback to writeText below
    }
    try {
      await navigator.clipboard.writeText(plainTextContent);
      triggerCopiedFeedback(feedbackKey);
    } catch {
      // Ignore clipboard permission errors
    }
  };

  const handleCopySingleValue = async (val: string, key: string) => {
    try {
      await navigator.clipboard.writeText(val);
      triggerCopiedFeedback(key);
    } catch {
      // Ignore
    }
  };

  // Build HTML + Plain Text for Table 1: Info / Details
  const buildInfoDetailsHtml = () => {
    const rows = [
      ['Classification', activeClassification],
      ['Time Range', report.timeRangeShortIST],
      ['Transaction status', report.transactionStatusLabel],
      ['Alert Type', report.alertTypeLabel],
      ['Network', report.networkLabel],
      ['Tokens Involved', displayedRows[0]?.tokenSymbol || report.tokensInvolvedLabel],
      ['Amount involved', activeAmountStatus],
    ];
    const trs = rows
      .map(
        ([k, v]) => `
        <tr>
          <td style="border:1px solid #1e293b;padding:8px 14px;text-align:center;font-family:Arial,sans-serif;font-size:13px;color:#0f172a;">${k}</td>
          <td style="border:1px solid #1e293b;padding:8px 14px;font-family:Arial,sans-serif;font-size:13px;color:#0f172a;${
            k === 'Time Range' ? 'font-weight:bold;' : ''
          }">${v}</td>
        </tr>`
      )
      .join('');

    return `
      <table style="border-collapse:collapse;width:440px;border:1px solid #1e293b;font-family:Arial,sans-serif;">
        <thead>
          <tr style="background-color:#d9e2f3;">
            <th style="border:1px solid #1e293b;padding:8px 14px;text-align:center;font-size:13px;font-weight:bold;color:#0f172a;">Info</th>
            <th style="border:1px solid #1e293b;padding:8px 14px;text-align:left;font-size:13px;font-weight:bold;color:#0f172a;">Details</th>
          </tr>
        </thead>
        <tbody>${trs}</tbody>
      </table>
    `;
  };

  const buildInfoDetailsPlainText = () => {
    return [
      `Info\tDetails`,
      `Classification\t${activeClassification}`,
      `Time Range\t${report.timeRangeShortIST}`,
      `Transaction status\t${report.transactionStatusLabel}`,
      `Alert Type\t${report.alertTypeLabel}`,
      `Network\t${report.networkLabel}`,
      `Tokens Involved\t${displayedRows[0]?.tokenSymbol || report.tokensInvolvedLabel}`,
      `Amount involved\t${activeAmountStatus}`,
    ].join('\n');
  };

  // Build HTML + Plain Text for Table 2: Transactions Detail
  const buildTransactionsDetailHtml = () => {
    const trs = displayedRows
      .map(
        (r) => `
        <tr>
          <td style="border:1px solid #1e293b;padding:12px 10px;text-align:center;font-family:Arial,sans-serif;font-size:12px;color:#0f172a;">
            <div style="font-weight:bold;margin-bottom:2px;">${r.tokenSymbol}</div>
            <div style="word-break:break-all;">(${r.tokenMintAddress})</div>
          </td>
          <td style="border:1px solid #1e293b;padding:12px 10px;text-align:center;font-family:Arial,sans-serif;font-size:12px;color:#0f172a;word-break:break-all;">
            ${r.txnSignature}
          </td>
          <td style="border:1px solid #1e293b;padding:12px 10px;text-align:center;font-family:Arial,sans-serif;font-size:12px;color:#0f172a;word-break:break-all;">
            ${r.fromResponderAddress}
          </td>
          <td style="border:1px solid #1e293b;padding:12px 10px;text-align:center;font-family:Arial,sans-serif;font-size:12px;color:#0f172a;word-break:break-all;">
            ${r.toAccountAddress}
          </td>
          <td style="border:1px solid #1e293b;padding:12px 10px;text-align:center;font-family:Arial,sans-serif;font-size:12px;color:#0f172a;">
            <div style="font-weight:bold;">${r.valueNumberFormatted}</div>
            <div>${r.valueTokenSymbol}</div>
          </td>
          <td style="border:1px solid #1e293b;padding:12px 10px;text-align:center;font-family:Arial,sans-serif;font-size:12px;color:#0f172a;">
            <div style="font-weight:bold;">[${eventProviderTag}]</div>
            <div style="margin-bottom:6px;">${r.eventsTriggeredPrimary}</div>
            <div style="font-weight:bold;">[Actual]</div>
            <div>${r.eventsTriggeredActual}</div>
          </td>
        </tr>`
      )
      .join('');

    return `
      <table style="border-collapse:collapse;width:100%;max-width:980px;border:1px solid #1e293b;font-family:Arial,sans-serif;">
        <thead>
          <tr style="background-color:#d9e2f3;">
            <th style="border:1px solid #1e293b;padding:10px;text-align:center;font-size:12px;font-weight:bold;color:#0f172a;">Tokens</th>
            <th style="border:1px solid #1e293b;padding:10px;text-align:center;font-size:12px;font-weight:bold;color:#0f172a;">Txn Signature</th>
            <th style="border:1px solid #1e293b;padding:10px;text-align:center;font-size:12px;font-weight:bold;color:#0f172a;">From responder<br/>${
              displayedRows[0]?.fromResponderSubLabel || '(Mint authority)'
            }</th>
            <th style="border:1px solid #1e293b;padding:10px;text-align:center;font-size:12px;font-weight:bold;color:#0f172a;">TO<br/>(Account)</th>
            <th style="border:1px solid #1e293b;padding:10px;text-align:center;font-size:12px;font-weight:bold;color:#0f172a;">Value</th>
            <th style="border:1px solid #1e293b;padding:10px;text-align:center;font-size:12px;font-weight:bold;color:#0f172a;">Events<br/>Triggered</th>
          </tr>
        </thead>
        <tbody>${trs}</tbody>
      </table>
    `;
  };

  const buildTransactionsDetailPlainText = () => {
    const header = `Tokens\tTxn Signature\tFrom responder ${
      displayedRows[0]?.fromResponderSubLabel || '(Mint authority)'
    }\tTO (Account)\tValue\tEvents Triggered`;
    const lines = displayedRows.map(
      (r) =>
        `${r.tokenSymbol} (${r.tokenMintAddress})\t${r.txnSignature}\t${r.fromResponderAddress}\t${r.toAccountAddress}\t${r.valueNumberFormatted} ${r.valueTokenSymbol}\t[${eventProviderTag}] ${r.eventsTriggeredPrimary} / [Actual] ${r.eventsTriggeredActual}`
    );
    return [header, ...lines].join('\n');
  };

  const handleCopyFullReport = () => {
    const fullHtml = `
      <div style="font-family:Arial,sans-serif;color:#0f172a;">
        <h3 style="margin:0 0 8px 0;font-size:16px;">${headerSubjectText}</h3>
        <p style="margin:0 0 12px 0;font-size:13px;">${greetingSummaryText}</p>
        ${buildInfoDetailsHtml()}
        <p style="margin:16px 0 8px 0;font-size:13px;font-weight:bold;">Transactions Detail :</p>
        ${buildTransactionsDetailHtml()}
      </div>
    `;
    const fullPlain = [
      headerSubjectText,
      '',
      greetingSummaryText,
      '',
      buildInfoDetailsPlainText(),
      '',
      'Transactions Detail :',
      buildTransactionsDetailPlainText(),
    ].join('\n');

    copyRichHtmlAndPlainText(fullHtml, fullPlain, 'full-report');
  };

  const handleAddActiveTxToBatch = () => {
    const currentRow = report.transactionDetailRow;
    setCustomBatchRows((prev) => {
      const base = prev && prev.length > 0 ? prev : [];
      if (base.some((r) => r.txnSignature === currentRow.txnSignature)) {
        return base;
      }
      return [...base, currentRow];
    });
  };

  const isLightTable = tableStyleMode === 'classic-report';

  return (
    <section className="bg-[#0c121e] border border-cyan-500/40 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-5">
      {/* Top Control Bar: Title & 1-Click Copy Actions */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyan-400">
            <Table2 className="w-4 h-4 text-cyan-400" />
            <span>
              EASE MODE • STRUCTURED SOLANA ALERT NOTIFICATION & COPY-READY TABLE REPORT
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-extrabold text-white mt-0.5">
            {headerSubjectText}
          </h2>
          <p className="text-xs text-slate-300 mt-1">{greetingSummaryText}</p>
        </div>

        {/* Primary Copy & Batch Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleCopyFullReport}
            className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-xs flex items-center gap-1.5 shadow-lg shadow-cyan-500/20 transition cursor-pointer"
          >
            {copiedKey === 'full-report' ? (
              <>
                <Check className="w-3.5 h-3.5" />
                <span>Copied Full Report (Rich Table)!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Full Alert Report (Tables + Header)</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() =>
              copyRichHtmlAndPlainText(
                buildInfoDetailsHtml(),
                buildInfoDetailsPlainText(),
                'info-table'
              )
            }
            className="px-3 py-2 rounded-xl bg-[#080c14] hover:bg-slate-800 border border-slate-700 text-slate-200 font-bold text-xs flex items-center gap-1.5 transition cursor-pointer"
          >
            {copiedKey === 'info-table' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-300">Copied Info Table</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-cyan-400" />
                <span>Copy Info/Details Table</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() =>
              copyRichHtmlAndPlainText(
                buildTransactionsDetailHtml(),
                buildTransactionsDetailPlainText(),
                'tx-table'
              )
            }
            className="px-3 py-2 rounded-xl bg-[#080c14] hover:bg-slate-800 border border-slate-700 text-slate-200 font-bold text-xs flex items-center gap-1.5 transition cursor-pointer"
          >
            {copiedKey === 'tx-table' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-300">Copied Tx Detail Table</span>
              </>
            ) : (
              <>
                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                <span>Copy Transactions Detail Table</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Interactive Report Customization & Multi-Tx Batch Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-[#080c14] border border-slate-800 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          {/* Table Visual Style Toggle */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-400">Table View:</span>
            <div className="inline-flex rounded-lg bg-[#0c121e] p-0.5 border border-slate-800">
              <button
                type="button"
                onClick={() => setTableStyleMode('classic-report')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition cursor-pointer ${
                  isLightTable
                    ? 'bg-cyan-500 text-slate-950'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Classic Report Table (Light Blue Header)
              </button>
              <button
                type="button"
                onClick={() => setTableStyleMode('dark-forensic')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition cursor-pointer ${
                  !isLightTable
                    ? 'bg-cyan-500 text-slate-950'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Dark Forensic Table
              </button>
            </div>
          </div>

          {/* Classification Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-400">Classification:</span>
            {(['Info', 'Warning', 'Critical'] as const).map((cls) => (
              <button
                key={cls}
                type="button"
                onClick={() => setClassificationOverride(cls)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold transition cursor-pointer ${
                  activeClassification === cls
                    ? 'bg-emerald-500 text-slate-950'
                    : 'bg-[#0c121e] border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                {cls}
              </button>
            ))}
          </div>

          {/* Event Tag Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-400">Event Tag:</span>
            {(['Hexagate', 'SOL-MATE', 'Alert'] as const).map((tag) => (
              <button
                key={tag}
                type="button"
                onClick={() => setEventProviderTag(tag)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold transition cursor-pointer ${
                  eventProviderTag === tag
                    ? 'bg-cyan-500 text-slate-950'
                    : 'bg-[#0c121e] border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                [{tag}]
              </button>
            ))}
          </div>
        </div>

        {/* Multi-Transaction Batch Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleAddActiveTxToBatch}
            className="px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-300 font-mono text-[11px] font-bold flex items-center gap-1 cursor-pointer"
          >
            <Plus className="w-3 h-3" />
            <span>Add Active Tx to Batch ({displayedRows.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setCustomBatchRows(REFERENCE_TWO_TX_BATCH)}
            className="px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-emerald-300 font-mono text-[11px] font-bold flex items-center gap-1 cursor-pointer"
          >
            <Layers className="w-3 h-3" />
            <span>Load 2-Tx Batch Sample (46,391.53 + 0.01)</span>
          </button>

          {customBatchRows && (
            <button
              type="button"
              onClick={() => setCustomBatchRows(null)}
              className="px-2 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 font-mono text-[11px] font-bold flex items-center gap-1 cursor-pointer"
            >
              <Trash2 className="w-3 h-3" />
              <span>Reset to Active Tx</span>
            </button>
          )}
        </div>
      </div>

      {/* =====================================================================
          REPORT CONTAINER (CLASSIC LIGHT-BLUE REPORT STYLE OR DARK FORENSIC)
         ===================================================================== */}
      <div
        className={`rounded-2xl p-5 sm:p-6 border transition space-y-6 ${
          isLightTable
            ? 'bg-white text-slate-900 border-slate-300 shadow-inner'
            : 'bg-[#080c14] text-slate-100 border-slate-800'
        }`}
      >
        {/* Top Greeting Line inside the copy-ready sheet */}
        <div className="space-y-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3
              className={`text-base sm:text-lg font-bold ${
                isLightTable ? 'text-slate-900' : 'text-white'
              }`}
            >
              {headerSubjectText}
            </h3>
            <button
              type="button"
              onClick={() =>
                handleCopySingleValue(
                  `${headerSubjectText}\n\n${greetingSummaryText}`,
                  'copy-greeting'
                )
              }
              className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold flex items-center gap-1 cursor-pointer ${
                isLightTable
                  ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                  : 'bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700'
              }`}
            >
              {copiedKey === 'copy-greeting' ? (
                <>
                  <Check className="w-3 h-3 text-emerald-600" />
                  <span>Copied Header</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy Subject & Intro</span>
                </>
              )}
            </button>
          </div>
          <p className={`text-xs sm:text-sm ${isLightTable ? 'text-slate-800' : 'text-slate-300'}`}>
            Hello Team, We received <strong>{txCount}</strong> {eventProviderTag} alert notification
            {txCount > 1 ? 's' : ''} today at <strong>{report.timeRangeShortIST}</strong>, for{' '}
            <strong>{txCount}</strong> transaction{txCount > 1 ? 's' : ''}. Please find all alerts
            attached for your review &amp; kindly acknowledge them as per the mentioned details
          </p>
        </div>

        {/* ===================================================================
            TABLE 1: INFO / DETAILS SUMMARY TABLE (EXACT SEQUENCE FROM SCREENSHOT)
           =================================================================== */}
        <div className="overflow-x-auto">
          <table
            className={`w-full max-w-md border-collapse text-xs sm:text-sm border ${
              isLightTable ? 'border-slate-800' : 'border-slate-700'
            }`}
          >
            <thead>
              <tr
                className={
                  isLightTable
                    ? 'bg-[#d9e2f3] text-slate-900 font-bold'
                    : 'bg-[#162238] text-cyan-300 font-bold'
                }
              >
                <th
                  className={`py-2 px-4 text-center border w-44 ${
                    isLightTable ? 'border-slate-800' : 'border-slate-700'
                  }`}
                >
                  Info
                </th>
                <th
                  className={`py-2 px-4 text-left border ${
                    isLightTable ? 'border-slate-800' : 'border-slate-700'
                  }`}
                >
                  Details
                </th>
              </tr>
            </thead>
            <tbody>
              {[
                { label: 'Classification', value: activeClassification, bold: false },
                { label: 'Time Range', value: report.timeRangeShortIST, bold: true },
                { label: 'Transaction status', value: report.transactionStatusLabel, bold: false },
                { label: 'Alert Type', value: report.alertTypeLabel, bold: false },
                { label: 'Network', value: report.networkLabel, bold: false },
                {
                  label: 'Tokens Involved',
                  value: displayedRows[0]?.tokenSymbol || report.tokensInvolvedLabel,
                  bold: false,
                },
                { label: 'Amount involved', value: activeAmountStatus, bold: false },
              ].map((row) => (
                <tr
                  key={row.label}
                  onClick={() =>
                    handleCopySingleValue(`${row.label}: ${row.value}`, `info-${row.label}`)
                  }
                  title="Click row to copy"
                  className={`cursor-pointer transition ${
                    isLightTable ? 'hover:bg-slate-100' : 'hover:bg-slate-900/80'
                  }`}
                >
                  <td
                    className={`py-2 px-4 text-center border ${
                      isLightTable
                        ? 'border-slate-800 text-slate-900'
                        : 'border-slate-700 text-slate-300'
                    }`}
                  >
                    {row.label}
                  </td>
                  <td
                    className={`py-2 px-4 text-left border ${
                      row.bold ? 'font-extrabold' : 'font-normal'
                    } ${
                      isLightTable
                        ? 'border-slate-800 text-slate-900'
                        : 'border-slate-700 text-white'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span>{row.value}</span>
                      {copiedKey === `info-${row.label}` && (
                        <span className="text-[10px] font-mono text-emerald-500 font-bold">
                          Copied!
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ===================================================================
            TABLE 2: TRANSACTIONS DETAIL 6-COLUMN TABLE (EXACT SEQUENCE)
           =================================================================== */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div
              className={`text-xs sm:text-sm font-bold ${
                isLightTable ? 'text-slate-900' : 'text-white'
              }`}
            >
              Transactions Detail :
            </div>
            <span
              className={`text-[11px] font-mono ${
                isLightTable ? 'text-slate-500' : 'text-slate-400'
              }`}
            >
              Click any address or signature cell to copy or inspect
            </span>
          </div>

          <div className="overflow-x-auto">
            <table
              className={`w-full border-collapse text-xs border ${
                isLightTable ? 'border-slate-800' : 'border-slate-700'
              }`}
            >
              <thead>
                <tr
                  className={
                    isLightTable
                      ? 'bg-[#d9e2f3] text-slate-900 font-bold'
                      : 'bg-[#162238] text-cyan-300 font-bold'
                  }
                >
                  <th
                    className={`py-2.5 px-3 text-center border w-[18%] ${
                      isLightTable ? 'border-slate-800' : 'border-slate-700'
                    }`}
                  >
                    Tokens
                  </th>
                  <th
                    className={`py-2.5 px-3 text-center border w-[23%] ${
                      isLightTable ? 'border-slate-800' : 'border-slate-700'
                    }`}
                  >
                    Txn Signature
                  </th>
                  <th
                    className={`py-2.5 px-3 text-center border w-[20%] ${
                      isLightTable ? 'border-slate-800' : 'border-slate-700'
                    }`}
                  >
                    <div>From responder</div>
                    <div className="text-[11px] font-semibold">
                      {displayedRows[0]?.fromResponderSubLabel || '(Mint authority)'}
                    </div>
                  </th>
                  <th
                    className={`py-2.5 px-3 text-center border w-[20%] ${
                      isLightTable ? 'border-slate-800' : 'border-slate-700'
                    }`}
                  >
                    <div>TO</div>
                    <div className="text-[11px] font-semibold">(Account)</div>
                  </th>
                  <th
                    className={`py-2.5 px-3 text-center border w-[9%] ${
                      isLightTable ? 'border-slate-800' : 'border-slate-700'
                    }`}
                  >
                    Value
                  </th>
                  <th
                    className={`py-2.5 px-3 text-center border w-[10%] ${
                      isLightTable ? 'border-slate-800' : 'border-slate-700'
                    }`}
                  >
                    <div>Events</div>
                    <div>Triggered</div>
                  </th>
                </tr>
              </thead>
              <tbody>
                {displayedRows.map((row, idx) => (
                  <tr
                    key={`${row.txnSignature}-${idx}`}
                    className={
                      isLightTable ? 'hover:bg-slate-50/90' : 'hover:bg-slate-900/60'
                    }
                  >
                    {/* Column 1: Tokens (Symbol + Mint Address) */}
                    <td
                      className={`py-4 px-3 text-center align-middle border ${
                        isLightTable
                          ? 'border-slate-800 text-slate-900'
                          : 'border-slate-700 text-slate-100'
                      }`}
                    >
                      <div className="font-extrabold text-xs sm:text-sm">{row.tokenSymbol}</div>
                      <button
                        type="button"
                        onClick={() => onSelectAddress(row.tokenMintAddress)}
                        className={`font-mono text-[11px] break-all mt-0.5 hover:underline cursor-pointer ${
                          isLightTable ? 'text-slate-800' : 'text-cyan-300'
                        }`}
                        title="Click to inspect Token Mint in drawer"
                      >
                        ({row.tokenMintAddress})
                      </button>
                      <div className="mt-2 flex items-center justify-center gap-1.5">
                        <button
                          type="button"
                          onClick={() =>
                            handleCopySingleValue(
                              `${row.tokenSymbol} (${row.tokenMintAddress})`,
                              `tok-${idx}`
                            )
                          }
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono cursor-pointer ${
                            isLightTable
                              ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                          }`}
                        >
                          {copiedKey === `tok-${idx}` ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </td>

                    {/* Column 2: Txn Signature */}
                    <td
                      className={`py-4 px-3 text-center align-middle border ${
                        isLightTable
                          ? 'border-slate-800 text-slate-900'
                          : 'border-slate-700 text-slate-100'
                      }`}
                    >
                      <div className="font-mono text-[11px] sm:text-xs break-all leading-relaxed">
                        {row.txnSignature}
                      </div>
                      <div className="mt-2 flex items-center justify-center gap-1.5">
                        <button
                          type="button"
                          onClick={() =>
                            handleCopySingleValue(row.txnSignature, `sig-${idx}`)
                          }
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold cursor-pointer ${
                            isLightTable
                              ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                              : 'bg-slate-800 hover:bg-slate-700 text-cyan-300'
                          }`}
                        >
                          {copiedKey === `sig-${idx}` ? 'Copied!' : 'Copy Sig'}
                        </button>
                        {row.txnSignature !== breakdown.signature && (
                          <button
                            type="button"
                            onClick={() => onInvestigateSignature(row.txnSignature)}
                            className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500 text-slate-950 hover:bg-cyan-400 cursor-pointer flex items-center gap-0.5"
                          >
                            <span>Load Tx</span>
                            <ArrowUpRight className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    </td>

                    {/* Column 3: From responder (Mint authority) */}
                    <td
                      className={`py-4 px-3 text-center align-middle border ${
                        isLightTable
                          ? 'border-slate-800 text-slate-900'
                          : 'border-slate-700 text-slate-100'
                      }`}
                    >
                      <button
                        type="button"
                        onClick={() => onSelectAddress(row.fromResponderAddress)}
                        className="font-mono text-[11px] sm:text-xs break-all leading-relaxed hover:underline cursor-pointer"
                        title="Click to inspect authority address"
                      >
                        {row.fromResponderAddress}
                      </button>
                      <div className="mt-2 flex flex-wrap items-center justify-center gap-1.5">
                        {renderCompactProvenanceBadge(row.fromResponderWhitelist, isLightTable)}
                        <button
                          type="button"
                          onClick={() =>
                            handleCopySingleValue(row.fromResponderAddress, `from-${idx}`)
                          }
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono cursor-pointer ${
                            isLightTable
                              ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                          }`}
                        >
                          {copiedKey === `from-${idx}` ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </td>

                    {/* Column 4: TO (Account) */}
                    <td
                      className={`py-4 px-3 text-center align-middle border ${
                        isLightTable
                          ? 'border-slate-800 text-slate-900'
                          : 'border-slate-700 text-slate-100'
                      }`}
                    >
                      <button
                        type="button"
                        onClick={() => onSelectAddress(row.toAccountAddress)}
                        className="font-mono text-[11px] sm:text-xs break-all leading-relaxed hover:underline cursor-pointer"
                        title="Click to inspect recipient account"
                      >
                        {row.toAccountAddress}
                      </button>
                      <div className="mt-2 flex flex-wrap items-center justify-center gap-1.5">
                        {renderCompactProvenanceBadge(row.toAccountWhitelist, isLightTable)}
                        <button
                          type="button"
                          onClick={() =>
                            handleCopySingleValue(row.toAccountAddress, `to-${idx}`)
                          }
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono cursor-pointer ${
                            isLightTable
                              ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                          }`}
                        >
                          {copiedKey === `to-${idx}` ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </td>

                    {/* Column 5: Value */}
                    <td
                      className={`py-4 px-3 text-center align-middle border ${
                        isLightTable
                          ? 'border-slate-800 text-slate-900'
                          : 'border-slate-700 text-white'
                      }`}
                    >
                      <div className="font-extrabold text-xs sm:text-sm font-mono">
                        {row.valueNumberFormatted}
                      </div>
                      <div className="text-xs mt-0.5">{row.valueTokenSymbol}</div>
                    </td>

                    {/* Column 6: Events Triggered */}
                    <td
                      className={`py-4 px-3 text-center align-middle border ${
                        isLightTable
                          ? 'border-slate-800 text-slate-900'
                          : 'border-slate-700 text-slate-100'
                      }`}
                    >
                      <div className="font-extrabold text-[11px]">[{eventProviderTag}]</div>
                      <div className="text-xs mb-2">{row.eventsTriggeredPrimary}</div>
                      <div className="font-extrabold text-[11px]">[Actual]</div>
                      <div className="text-xs">{row.eventsTriggeredActual}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ===================================================================
            ATTACHED FORENSIC EVIDENCE / INSTRUCTION & CPI PROOF CARDS
            (Matches the bottom "Attached Screenshots :" section in the image)
           =================================================================== */}
        <div className="space-y-2.5 pt-2">
          <div
            className={`text-xs sm:text-sm font-bold flex items-center gap-2 ${
              isLightTable ? 'text-slate-900' : 'text-white'
            }`}
          >
            <Terminal className="w-4 h-4 text-cyan-500" />
            <span>Attached On-Chain Instruction &amp; CPI Forensic Evidence :</span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Left Evidence Card: Action, Interact With, Instruction Data (Account, Amount, Mint, Mint Authority) */}
            <div
              className={`rounded-xl p-4 border text-xs space-y-2.5 ${
                isLightTable
                  ? 'bg-slate-50 border-slate-300 text-slate-800'
                  : 'bg-[#0b101b] border-slate-800 text-slate-200'
              }`}
            >
              <div className="flex items-center justify-between pb-1.5 border-b border-slate-300/40">
                <span className="font-mono text-[10px] font-bold uppercase text-cyan-600">
                  EVIDENCE PANEL 1 • TOKEN-2022 ACTION &amp; MINT AUTHORITY PROOF
                </span>
                <button
                  type="button"
                  onClick={() =>
                    handleCopySingleValue(
                      `Action: ${report.attachedForensicEvidence.actionLine}\nInteract With: ${report.attachedForensicEvidence.interactWithProgramName} - ${report.attachedForensicEvidence.interactWithProgramId}\nAccount: ${report.attachedForensicEvidence.instructionAccountAddress}\nAmount: ${report.attachedForensicEvidence.instructionAmountText}\nMint: ${report.attachedForensicEvidence.instructionMintSymbol} (${report.attachedForensicEvidence.instructionMintAddress})\n${report.attachedForensicEvidence.instructionAuthorityLabel}: ${report.attachedForensicEvidence.instructionAuthorityAddress}`,
                      'ev-panel-1'
                    )
                  }
                  className="text-[10px] font-mono text-cyan-600 hover:underline cursor-pointer"
                >
                  {copiedKey === 'ev-panel-1' ? 'Copied Evidence!' : 'Copy Evidence'}
                </button>
              </div>

              <div className="grid grid-cols-12 gap-2 items-center">
                <span className="col-span-3 text-[11px] text-slate-500 font-medium">Action</span>
                <div className="col-span-9 font-medium break-all">
                  <span className="font-bold">
                    {report.transactionDetailRow.eventsTriggeredPrimary}
                  </span>{' '}
                  to{' '}
                  <button
                    type="button"
                    onClick={() =>
                      onSelectAddress(report.transactionDetailRow.toAccountAddress)
                    }
                    className="text-blue-600 hover:underline font-mono cursor-pointer"
                  >
                    {report.transactionDetailRow.toAccountAddress}
                  </button>{' '}
                  for{' '}
                  <span className="font-bold">
                    {report.transactionDetailRow.valueNumberFormatted}
                  </span>{' '}
                  <button
                    type="button"
                    onClick={() =>
                      onSelectAddress(report.transactionDetailRow.tokenMintAddress)
                    }
                    className="text-blue-600 hover:underline font-bold cursor-pointer"
                  >
                    {report.transactionDetailRow.tokenSymbol}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-12 gap-2 items-center">
                <span className="col-span-3 text-[11px] text-slate-500 font-medium">
                  Interact With
                </span>
                <div className="col-span-9 font-mono text-[11px] break-all">
                  <span>{report.attachedForensicEvidence.interactWithProgramName} - </span>
                  <button
                    type="button"
                    onClick={() =>
                      onSelectAddress(report.attachedForensicEvidence.interactWithProgramId)
                    }
                    className="text-blue-600 hover:underline cursor-pointer"
                  >
                    {report.attachedForensicEvidence.interactWithProgramId}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-12 gap-2 items-start pt-1 border-t border-slate-300/30">
                <span className="col-span-3 text-[11px] text-slate-500 font-medium">
                  Instruction Data
                </span>
                <div className="col-span-9 space-y-1.5 font-mono text-[11px]">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-slate-500 font-sans">Account:</span>
                    <button
                      type="button"
                      onClick={() =>
                        onSelectAddress(
                          report.attachedForensicEvidence.instructionAccountAddress
                        )
                      }
                      className="text-blue-600 hover:underline break-all cursor-pointer"
                    >
                      {report.attachedForensicEvidence.instructionAccountAddress}
                    </button>
                    <span className="px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-600 text-[9px] font-bold">
                      WRITABLE
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-slate-500 font-sans">Amount:</span>
                    <span className="font-bold">
                      {report.attachedForensicEvidence.instructionAmountText}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-slate-500 font-sans">Mint:</span>
                    <button
                      type="button"
                      onClick={() =>
                        onSelectAddress(report.attachedForensicEvidence.instructionMintAddress)
                      }
                      className="text-blue-600 hover:underline font-bold cursor-pointer"
                    >
                      {report.attachedForensicEvidence.instructionMintSymbol}
                    </button>
                    <span className="px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-600 text-[9px] font-bold">
                      WRITABLE
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-slate-500 font-sans">
                      {report.attachedForensicEvidence.instructionAuthorityLabel}:
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        onSelectAddress(
                          report.attachedForensicEvidence.instructionAuthorityAddress
                        )
                      }
                      className="text-blue-600 hover:underline break-all cursor-pointer"
                    >
                      {report.attachedForensicEvidence.instructionAuthorityAddress}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Evidence Card: Outer Controller Program, Raw Hex Instruction Data & Inner CPI MintTo */}
            <div
              className={`rounded-xl p-4 border text-xs space-y-2.5 flex flex-col justify-between ${
                isLightTable
                  ? 'bg-slate-50 border-slate-300 text-slate-800'
                  : 'bg-[#0b101b] border-slate-800 text-slate-200'
              }`}
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between pb-1.5 border-b border-slate-300/40">
                  <span className="font-mono text-[10px] font-bold uppercase text-emerald-600">
                    EVIDENCE PANEL 2 • OUTER CONTROLLER &amp; INNER CPI TRACE
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      handleCopySingleValue(
                        `${report.attachedForensicEvidence.outerInstructionIndexLabel}: ${report.attachedForensicEvidence.outerProgramId} (PROGRAM)\nInstruction Data: ${report.attachedForensicEvidence.outerInstructionDataHex}\nInner Instructions: ${report.attachedForensicEvidence.innerInstructionSummary}`,
                        'ev-panel-2'
                      )
                    }
                    className="text-[10px] font-mono text-emerald-600 hover:underline cursor-pointer"
                  >
                    {copiedKey === 'ev-panel-2' ? 'Copied CPI Trace!' : 'Copy CPI Trace'}
                  </button>
                </div>

                <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                  <span className="font-bold">
                    {report.attachedForensicEvidence.outerInstructionIndexLabel}:
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      onSelectAddress(report.attachedForensicEvidence.outerProgramId)
                    }
                    className="text-blue-600 hover:underline break-all cursor-pointer"
                  >
                    {report.attachedForensicEvidence.outerProgramId}
                  </button>
                  <span className="px-1.5 py-0.5 rounded bg-violet-500/15 border border-violet-500/30 text-violet-600 text-[9px] font-bold">
                    PROGRAM
                  </span>
                </div>

                <div className="grid grid-cols-12 gap-2 items-start">
                  <span className="col-span-3 text-[11px] text-slate-500 font-medium">
                    Instruction Data
                  </span>
                  <div
                    className={`col-span-9 p-2 rounded font-mono text-[11px] break-all border ${
                      isLightTable
                        ? 'bg-emerald-50/70 border-emerald-200 text-slate-800'
                        : 'bg-[#070a10] border-slate-800 text-emerald-300'
                    }`}
                  >
                    {report.attachedForensicEvidence.outerInstructionDataHex}
                  </div>
                </div>

                <div className="grid grid-cols-12 gap-2 items-center pt-1">
                  <span className="col-span-3 text-[11px] text-slate-500 font-medium">
                    Inner Instructions
                  </span>
                  <div
                    className={`col-span-9 p-2 rounded font-mono text-[11px] font-bold border ${
                      isLightTable
                        ? 'bg-white border-slate-200 text-slate-900'
                        : 'bg-[#070a10] border-slate-800 text-cyan-300'
                    }`}
                  >
                    {report.attachedForensicEvidence.innerInstructionSummary}
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-300/30 flex items-center justify-between text-[10px] font-mono text-slate-500">
                <span>Slot #{breakdown.slot.toLocaleString()}</span>
                <span className="flex items-center gap-1">
                  <Eye className="w-3 h-3" /> All cells 1-click copyable for email / Excel / audit
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
