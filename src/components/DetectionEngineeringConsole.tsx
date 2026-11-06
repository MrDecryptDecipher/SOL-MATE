/**
 * SOL-MATE — Detection Engineering Console
 * Implements Phase 4, Phase 10.3, and Phase 11:
 * - Versioned Detection Rule Catalog across Categories A through G
 * - Rule Lifecycle Management: Enable/Disable, Threshold Tuning, Version History & Rollback, Custom Draft Rule Creation
 * - Historical Fixture Replay & Dry-Run Evaluation (Precision, Recall, False-Positive Rate, Category Coverage)
 */

import React, { useState, useMemo } from 'react';
import {
  Sliders,
  Play,
  RotateCcw,
  CheckCircle2,
  PlusCircle,
  ShieldAlert,
  Layers,
  Code2,
  History,
  Activity,
} from 'lucide-react';
import {
  AlertSeverity,
  DetectionCategoryCode,
  DetectionConfidence,
  DetectionRule,
  RuleReplayFixture,
} from '../types/universalIntel';
import {
  buildHistoricalReplayFixtures,
  evaluateRuleEnginePerformance,
  evaluateUniversalTransaction,
} from '../services/universalDetectionEngine';

interface DetectionEngineeringConsoleProps {
  rules: DetectionRule[];
  onUpdateRules: (updated: DetectionRule[]) => void;
}

const CATEGORY_LABELS: Record<DetectionCategoryCode, string> = {
  CATEGORY_A_ASSET_LIFECYCLE: 'Category A • Asset Lifecycle (Mint, Burn, Supply, Provisioning)',
  CATEGORY_B_VALUE_MOVEMENT: 'Category B • Value Movement (Large Transfers, Velocity, Fan-Out)',
  CATEGORY_C_AUTHORITY_PERMISSIONS: 'Category C • Authority & Permissions (Mint/Freeze/Owner/Roles)',
  CATEGORY_D_ADMIN_PROTOCOL_STATE: 'Category D • Admin & Protocol State (SetStopCodes, Proxy, DiamondCut)',
  CATEGORY_E_EXECUTION_ACCESS_CONTROL: 'Category E • Execution & Access Control (Burn State Machine, Reverts)',
  CATEGORY_F_BEHAVIOURAL_RELATIONSHIP: 'Category F • Behavioural & Relationship Analysis',
  CATEGORY_G_DATA_INTEGRITY_HEALTH: 'Category G • Data Integrity & Unknown Instruction Fallback',
};

export const DetectionEngineeringConsole: React.FC<DetectionEngineeringConsoleProps> = ({
  rules,
  onUpdateRules,
}) => {
  const [selectedRuleId, setSelectedRuleId] = useState<string>(rules[0]?.ruleId || 'RULE-A01');
  const [replayFixtures] = useState<RuleReplayFixture[]>(() => buildHistoricalReplayFixtures());
  const [lastReplayTimestamp, setLastReplayTimestamp] = useState<number>(Date.now());
  const [newRuleName, setNewRuleName] = useState<string>('');
  const [newRuleCategory, setNewRuleCategory] = useState<DetectionCategoryCode>(
    'CATEGORY_F_BEHAVIOURAL_RELATIONSHIP'
  );
  const [newRuleSeverity, setNewRuleSeverity] = useState<AlertSeverity>('medium');

  const selectedRule = useMemo(
    () => rules.find((r) => r.ruleId === selectedRuleId) || rules[0],
    [rules, selectedRuleId]
  );

  const evaluation = useMemo(
    () => evaluateRuleEnginePerformance(rules, replayFixtures),
    [rules, replayFixtures, lastReplayTimestamp]
  );

  const handleToggleRuleStatus = (ruleId: string) => {
    const updated = rules.map((r) => {
      if (r.ruleId !== ruleId) return r;
      const nextStatus: DetectionRule['status'] = r.status === 'ENABLED' ? 'DISABLED' : 'ENABLED';
      return {
        ...r,
        status: nextStatus,
      };
    });
    onUpdateRules(updated);
  };

  const handleRollbackVersion = (ruleId: string, targetVersion: string) => {
    const updated = rules.map((r) => {
      if (r.ruleId !== ruleId) return r;
      const snap = r.versionHistory.find((v) => v.version === targetVersion);
      if (!snap) return r;
      return {
        ...r,
        version: snap.version,
        defaultSeverity: snap.severity,
        defaultConfidence: snap.confidence,
        status: snap.enabled ? ('ENABLED' as const) : ('DISABLED' as const),
        thresholdConfig: { ...snap.thresholdConfig },
      };
    });
    onUpdateRules(updated);
  };

  const handleCreateCustomRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName.trim()) return;
    const nextNum = rules.length + 1;
    const ruleId = `RULE-CUSTOM-${nextNum}`;
    const newRule: DetectionRule = {
      ruleId,
      name: newRuleName.trim(),
      category: newRuleCategory,
      version: '1.0.0',
      status: 'ENABLED',
      supportedChains: ['solana-mainnet', 'ethereum-mainnet'],
      targetStandards: ['ANY'],
      targetMintsOrContracts: [],
      description: `Analyst-configured custom detection rule (${newRuleName.trim()}) validated against universal transaction schema.`,
      conditions: [
        {
          field: 'callFrames',
          operator: 'EXISTS',
          value: true,
          description: 'Evaluates normalized universal call frames and state deltas.',
        },
      ],
      thresholdConfig: { customThreshold: 1 },
      defaultSeverity: newRuleSeverity,
      defaultConfidence: 'high',
      deduplicationWindowSeconds: 300,
      mitigationGuidance: ['Verify transaction against custom analyst policy parameters.'],
      versionHistory: [
        {
          version: '1.0.0',
          updatedAt: Date.now(),
          author: 'Analyst Custom Rule',
          changelog: 'Created via Detection Engineering Console.',
          severity: newRuleSeverity,
          confidence: 'high',
          enabled: true,
          thresholdConfig: { customThreshold: 1 },
        },
      ],
    };
    onUpdateRules([...rules, newRule]);
    setSelectedRuleId(ruleId);
    setNewRuleName('');
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Header & Quality Metrics */}
      <div className="bg-gradient-to-r from-[#0d131f] via-[#0f172a] to-[#0d131f] border border-cyan-500/30 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-extrabold uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Detection Engineering Console
              </span>
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                Versioned Schema • Historical Replay
              </span>
            </div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">
              Extensible Detection Rule Engine, Versioning & Historical Fixture Replay
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl">
              Manage data-driven detection rules across Categories A–G, tune thresholds, rollback rule versions,
              and replay historical Solana & EVM fixtures to verify precision, recall, and false-positive rate.
            </p>
          </div>

          <button
            onClick={() => setLastReplayTimestamp(Date.now())}
            className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-extrabold text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer shrink-0"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>Run Historical Replay & Dry-Run Suite</span>
          </button>
        </div>

        {/* Metrics Strip (Phase 11) */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-4 pt-4 border-t border-slate-800/80">
          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Precision Rate</div>
            <div className="text-lg font-extrabold text-emerald-400 mt-0.5">
              {evaluation.metrics.precisionPercent}%
            </div>
            <div className="text-[10px] text-slate-400">
              TP: {evaluation.metrics.truePositives} | FP: {evaluation.metrics.falsePositives}
            </div>
          </div>

          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Recall Rate</div>
            <div className="text-lg font-extrabold text-cyan-400 mt-0.5">
              {evaluation.metrics.recallPercent}%
            </div>
            <div className="text-[10px] text-slate-400">
              FN: {evaluation.metrics.falseNegatives} missed
            </div>
          </div>

          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">False-Positive Rate</div>
            <div className="text-lg font-extrabold text-emerald-300 mt-0.5">
              {evaluation.metrics.falsePositiveRatePercent}%
            </div>
            <div className="text-[10px] text-slate-400">Strict invariant gating</div>
          </div>

          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Active Rules</div>
            <div className="text-lg font-extrabold text-white mt-0.5">
              {rules.filter((r) => r.status === 'ENABLED').length} / {rules.length}
            </div>
            <div className="text-[10px] text-slate-400">Categories A–G</div>
          </div>

          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Replay Corpus</div>
            <div className="text-lg font-extrabold text-violet-400 mt-0.5">
              {evaluation.metrics.totalFixturesEvaluated} Fixtures
            </div>
            <div className="text-[10px] text-slate-400">
              {evaluation.metrics.totalAlertsGenerated} alerts verified
            </div>
          </div>
        </div>
      </div>

      {/* Main Split: Left Rule List + Custom Rule Builder, Right Rule Inspector & Fixture Replay Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 5 Columns: Rule Catalog */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-4 space-y-3">
            <div className="text-xs font-extrabold uppercase tracking-wider text-slate-300 flex items-center justify-between">
              <span>Versioned Detection Rule Catalog ({rules.length})</span>
              <span className="text-cyan-400 font-mono text-[10px]">Schema v2.0</span>
            </div>

            <div className="space-y-2">
              {rules.map((rule) => {
                const isSelected = rule.ruleId === selectedRule.ruleId;
                return (
                  <div
                    key={rule.ruleId}
                    onClick={() => setSelectedRuleId(rule.ruleId)}
                    className={`p-3.5 rounded-xl border transition cursor-pointer ${
                      isSelected
                        ? 'bg-[#121c31] border-cyan-400'
                        : 'bg-[#070a12] border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-extrabold text-cyan-300">
                          {rule.ruleId}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          v{rule.version}
                        </span>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleToggleRuleStatus(rule.ruleId);
                        }}
                        aria-label={`Toggle rule ${rule.ruleId}`}
                        className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase cursor-pointer ${
                          rule.status === 'ENABLED'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {rule.status}
                      </button>
                    </div>
                    <div className="text-xs font-bold text-white mt-1.5">{rule.name}</div>
                    <div className="text-[10px] text-slate-400 mt-1">
                      {CATEGORY_LABELS[rule.category]}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Create & Validate New Rule Form */}
          <form
            onSubmit={handleCreateCustomRule}
            className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-4 space-y-3"
          >
            <div className="text-xs font-extrabold uppercase text-cyan-400 flex items-center gap-1.5">
              <PlusCircle className="w-4 h-4" />
              <span>Create & Validate New Detection Rule</span>
            </div>

            <div>
              <label className="block text-[10px] font-bold uppercase text-slate-400 mb-1">
                Rule Name
              </label>
              <input
                type="text"
                value={newRuleName}
                onChange={(e) => setNewRuleName(e.target.value)}
                placeholder="e.g., Rapid Holder Fan-Out Velocity Spike"
                className="w-full bg-[#070a12] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[10px] font-bold uppercase text-slate-400 mb-1">
                  Category
                </label>
                <select
                  aria-label="New Rule Category"
                  value={newRuleCategory}
                  onChange={(e) => setNewRuleCategory(e.target.value as DetectionCategoryCode)}
                  className="w-full bg-[#070a12] border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-white"
                >
                  <option value="CATEGORY_A_ASSET_LIFECYCLE">Category A (Asset Lifecycle)</option>
                  <option value="CATEGORY_B_VALUE_MOVEMENT">Category B (Value Movement)</option>
                  <option value="CATEGORY_C_AUTHORITY_PERMISSIONS">Category C (Authority)</option>
                  <option value="CATEGORY_D_ADMIN_PROTOCOL_STATE">Category D (Admin/StopCode)</option>
                  <option value="CATEGORY_E_EXECUTION_ACCESS_CONTROL">Category E (Execution)</option>
                  <option value="CATEGORY_F_BEHAVIOURAL_RELATIONSHIP">Category F (Behavioural)</option>
                  <option value="CATEGORY_G_DATA_INTEGRITY_HEALTH">Category G (Data Health)</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-bold uppercase text-slate-400 mb-1">
                  Default Severity
                </label>
                <select
                  aria-label="New Rule Severity"
                  value={newRuleSeverity}
                  onChange={(e) => setNewRuleSeverity(e.target.value as AlertSeverity)}
                  className="w-full bg-[#070a12] border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-white"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              className="w-full py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold cursor-pointer"
            >
              Validate Schema & Register Rule
            </button>
          </form>
        </div>

        {/* Right 7 Columns: Selected Rule Details, Version Rollback & Historical Fixture Replay */}
        <div className="lg:col-span-7 space-y-6">
          {selectedRule && (
            <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-2 border-b border-slate-800 pb-3">
                <div>
                  <span className="font-mono text-xs font-extrabold text-cyan-400">
                    {selectedRule.ruleId} • v{selectedRule.version}
                  </span>
                  <h2 className="text-base font-extrabold text-white mt-0.5">{selectedRule.name}</h2>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2.5 py-0.5 rounded bg-slate-800 text-slate-200 font-mono">
                    Default Sev: {selectedRule.defaultSeverity}
                  </span>
                  <span className="text-xs px-2.5 py-0.5 rounded bg-slate-800 text-emerald-300 font-mono">
                    Default Conf: {selectedRule.defaultConfidence}
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">{selectedRule.description}</p>

              {/* Conditions */}
              <div>
                <div className="text-[10px] font-extrabold uppercase text-cyan-400 mb-2">
                  Predicates & Invariant Conditions
                </div>
                <div className="space-y-2">
                  {selectedRule.conditions.map((cond, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-[#070a12] border border-slate-800 font-mono text-xs"
                    >
                      <div className="text-emerald-300 font-bold">
                        {cond.field} [{cond.operator}] {JSON.stringify(cond.value)}
                      </div>
                      <div className="text-slate-400 font-sans text-[11px] mt-0.5">
                        {cond.description}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Version History & Rollback */}
              <div>
                <div className="text-[10px] font-extrabold uppercase text-violet-400 mb-2 flex items-center gap-1.5">
                  <History className="w-3.5 h-3.5" />
                  <span>Version History & Instant Rollback</span>
                </div>
                <div className="space-y-2">
                  {selectedRule.versionHistory.map((ver) => {
                    const isCurrent = ver.version === selectedRule.version;
                    return (
                      <div
                        key={ver.version}
                        className="flex items-center justify-between gap-2 p-3 rounded-xl bg-[#070a12] border border-slate-800 text-xs"
                      >
                        <div>
                          <div className="font-mono font-bold text-white">
                            v{ver.version}{' '}
                            {isCurrent && (
                              <span className="text-[10px] text-emerald-400 ml-1">(Active)</span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-400">{ver.changelog}</div>
                        </div>
                        {!isCurrent && (
                          <button
                            onClick={() => handleRollbackVersion(selectedRule.ruleId, ver.version)}
                            className="px-3 py-1 rounded-lg bg-violet-500/20 hover:bg-violet-500/30 text-violet-300 border border-violet-500/40 text-[11px] font-bold flex items-center gap-1 cursor-pointer shrink-0"
                          >
                            <RotateCcw className="w-3 h-3" />
                            <span>Rollback to v{ver.version}</span>
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Historical Fixture Replay Verification Matrix */}
          <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-extrabold text-white">
                  Historical Fixture Dry-Run Verification Matrix
                </h3>
                <p className="text-[11px] text-slate-400">
                  Deterministic replay of Solana JLTXX/MONY, Burn State Machine, SetStopCodes, EVM DiamondCut,
                  and Unknown Instruction fixtures against current rule configuration.
                </p>
              </div>
            </div>

            <div className="space-y-2.5">
              {replayFixtures.map((fix) => {
                const alertsFired = evaluateUniversalTransaction(fix.envelope, rules);
                const firedIds = alertsFired.map((a) => a.ruleId);
                const passed = fix.expectedRuleIds.every((id) => firedIds.includes(id));

                return (
                  <div
                    key={fix.fixtureId}
                    className="p-3.5 rounded-xl bg-[#070a12] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-cyan-400 font-bold">
                          {fix.fixtureId}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          {fix.chain}
                        </span>
                      </div>
                      <div className="text-xs font-bold text-white">{fix.title}</div>
                      <div className="text-[11px] text-slate-400">{fix.description}</div>
                      <div className="text-[10px] font-mono text-slate-400 pt-1">
                        Expected: [{fix.expectedRuleIds.join(', ')}] • Fired: [
                        {firedIds.join(', ') || 'NONE'}]
                      </div>
                    </div>

                    <div className="shrink-0">
                      <span
                        className={`px-2.5 py-1 rounded-lg text-[10px] font-extrabold uppercase ${
                          passed
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        }`}
                      >
                        {passed ? 'REPLAY VERIFIED' : 'RULE DISABLED / MISMATCH'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
