import type { ReactNode } from 'react';
import {
  BarChart3,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  HardDrive,
  Info,
  MemoryStick,
  Monitor,
  Play,
  Power,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Thermometer,
  Wrench,
  XCircle,
} from 'lucide-react';
import type {
  AppInfo,
  ApplyOutcome,
  CheckStatus,
  Comparison,
  JournalEntry,
  PreviewAction,
  Preset,
  ScanReport,
  Score,
  ToolDefinition,
  ToolRunResult,
} from '../types';
import type { Lang } from '../i18n';
import { formatBytes, formatDate } from '../lib/api';
import { FindingList } from './Findings';

type T = (key: string) => string;

function PageHeader({ title, subtitle, action }: { title: string; subtitle: string; action?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      {action}
    </header>
  );
}

function scoreTone(status: Score['status']): string {
  if (status === 'excellent') return 'excellent';
  if (status === 'good') return 'good';
  if (status === 'attention') return 'attention';
  return 'poor';
}

function MetricCard({
  icon,
  label,
  value,
  hint,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="metric-card">
      <div className="metric-icon">{icon}</div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {hint && <div className="metric-hint">{hint}</div>}
    </div>
  );
}

export function ScorePanel({ score, t }: { score: Score; t: T }) {
  return (
    <section className={`score-panel ${scoreTone(score.status)}`}>
      <div className="score-value">
        <span>{score.value}</span>
        <small>/ 100</small>
      </div>
      <div className="score-info">
        <div className="score-label">{t('score.title')}</div>
        <div className="score-status">{t(`score.${score.status}`)}</div>
        <div className="score-note">{t('score.note')}</div>
        <div className="score-note">
          {t('score.breakdown')}: {score.breakdown.length}
        </div>
      </div>
      <div className="score-bars">
        {score.breakdown.slice(0, 6).map((item) => (
          <div className="score-bar-row" key={item.category}>
            <span>{t(`categories.${item.category}`)}</span>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${Math.min(100, item.applied * 8)}%` }} />
            </div>
            <strong>−{item.applied}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

export function ChecksPanel({ checks, t }: { checks: CheckStatus[]; t: T }) {
  if (!checks.length) return null;

  return (
    <section className="panel checks-panel">
      <h2>{t('checks.title')}</h2>
      <p className="muted">{t('checks.subtitle')}</p>
      <div className="checks-list">
        {checks.map((item) => {
          const localized = t(`check.${item.id}`);
          const title = localized === `check.${item.id}` ? item.title : localized;
          const badgeClass = item.status === 'ok' ? 'safe' : item.status === 'issue' ? 'warn' : 'subtle';

          return (
            <article className={`check-row ${item.status}`} key={item.id}>
              <div className="check-icon">
                {item.status === 'ok' ? (
                  <CheckCircle2 size={15} />
                ) : item.status === 'issue' ? (
                  <AlertTriangle size={15} />
                ) : (
                  <Info size={15} />
                )}
              </div>
              <div className="check-content">
                <div className="check-head">
                  <h3>{title}</h3>
                  <span className={`badge ${badgeClass}`}>{t(`checks.${item.status}`)}</span>
                </div>
                <p className="check-summary">{item.summary}</p>
                <p className="check-result">
                  <strong>{t('checks.result')}:</strong> {item.result}
                </p>
                {item.evidence.length > 0 && <p className="check-evidence">{item.evidence.join(' · ')}</p>}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

interface OverviewProps {
  report: ScanReport | null;
  appInfo: AppInfo | null;
  t: T;
}

export function OverviewView({ report, appInfo, t }: OverviewProps) {
  if (!report) {
    return (
      <div className="page">
        <PageHeader title={t('overview.title')} subtitle={t('overview.subtitle')} />
        <div className="empty-state large">
          <Monitor size={34} />
          <h3>{t('overview.noReport')}</h3>
        </div>
      </div>
    );
  }

  const { system, metrics } = report;

  return (
    <div className="page">
      <PageHeader title={t('overview.title')} subtitle={t('overview.subtitle')} />
      <ScorePanel score={report.score} t={t} />

      <div className="metric-grid">
        <MetricCard
          icon={<Cpu size={18} />}
          label={t('overview.cpu')}
          value={system.cpu}
          hint={`${system.cpuCores} ${t('common.of')} ${system.arch}`}
        />
        <MetricCard
          icon={<MemoryStick size={18} />}
          label={t('overview.ram')}
          value={`${system.ramUsedGb} / ${system.ramTotalGb} ГБ`}
          hint={`${system.ramUsedPercent}% · ${system.ram}`}
        />
        <MetricCard icon={<Monitor size={18} />} label={t('overview.gpu')} value={system.gpu} />
        <MetricCard
          icon={<HardDrive size={18} />}
          label={t('overview.disk')}
          value={`${system.disk.free} / ${system.disk.total} ГБ`}
          hint={`${metrics.diskType || '—'} · ${system.disk.freePercent}% free`}
        />
        <MetricCard icon={<Monitor size={18} />} label={t('overview.os')} value={system.os} hint={system.hostname} />
        <MetricCard
          icon={<Clock size={18} />}
          label={t('overview.uptime')}
          value={system.uptime.text}
          hint={system.bootSeconds ? `${t('overview.boot')}: ${system.bootSeconds} с` : undefined}
        />
        <MetricCard
          icon={<Thermometer size={18} />}
          label={t('overview.temp')}
          value={system.temperatureC !== null ? `${system.temperatureC} °C` : '—'}
          hint={metrics.rebootPending ? t('categories.updates') : undefined}
        />
        <MetricCard
          icon={<ShieldCheck size={18} />}
          label={t('overview.admin')}
          value={appInfo?.isAdmin || system.isAdmin ? t('common.admin') : t('common.user')}
          hint={`${t('overview.findings')}: ${report.findings.length}`}
        />
      </div>
    </div>
  );
}

interface ScanViewProps {
  report: ScanReport | null;
  busy: boolean;
  selected: Set<string>;
  onToggle: (id: string) => void;
  onScan: () => void;
  lang: Lang;
  t: T;
}

export function ScanView({ report, busy, selected, onToggle, onScan, lang, t }: ScanViewProps) {
  return (
    <div className="page">
      <PageHeader
        title={t('scan.title')}
        subtitle={t('scan.subtitle')}
        action={
          <button type="button" className="button primary" onClick={onScan} disabled={busy}>
            {busy ? <RefreshCw size={16} className="spin" /> : <Play size={16} />}
            {busy ? t('scan.running') : t('scan.run')}
          </button>
        }
      />

      {report && (
        <div className="scan-meta">
          <span>{formatDate(report.scannedAt, lang)}</span>
          <span>
            {t('scan.duration')}: {(report.durationMs / 1000).toFixed(1)} с
          </span>
          <span>
            {t('overview.findings')}: {report.findings.length}
          </span>
        </div>
      )}

      {report?.warnings?.length ? (
        <div className="notice warn">
          <AlertTriangle size={16} />
          <div>
            <strong>{t('scan.warnings')}</strong>
            <ul>
              {report.warnings.map((warning, index) => (
                <li key={`warning-${index}`}>{warning}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      {report && (
        <div className="notice warn" role="note">
          <AlertTriangle size={16} />
          <span>{t('security.noAntivirus')}</span>
        </div>
      )}

      {report ? (
        <>
          <ChecksPanel checks={report.checks || []} t={t} />
          <FindingList
            findings={report.findings}
            selected={selected}
            onToggle={onToggle}
            lang={lang}
            selectable
            t={t}
          />
        </>
      ) : (
        <div className="empty-state large">
          <Play size={30} />
          <h3>{t('scan.title')}</h3>
          <p>{t('scan.subtitle')}</p>
        </div>
      )}
    </div>
  );
}

interface PlanViewProps {
  report: ScanReport | null;
  presets: Preset[];
  activePreset: string;
  selected: Set<string>;
  preview: PreviewAction[];
  outcome: ApplyOutcome | null;
  applying: boolean;
  onPreset: (id: string) => void;
  onToggle: (id: string) => void;
  onApply: () => void;
  onRestartAdmin: () => void;
  lang: Lang;
  t: T;
}

export function PlanView({
  report,
  presets,
  activePreset,
  selected,
  preview,
  outcome,
  applying,
  onPreset,
  onToggle,
  onApply,
  onRestartAdmin,
  lang,
  t,
}: PlanViewProps) {
  const actionable = report?.findings.filter((finding) => finding.action) || [];
  const preset = presets.find((item) => item.id === activePreset);

  return (
    <div className="page">
      <PageHeader title={t('plan.title')} subtitle={t('plan.subtitle')} />

      {!report ? (
        <div className="empty-state large">
          <Play size={30} />
          <p>{t('overview.noReport')}</p>
        </div>
      ) : (
        <>
          <section className="panel">
            <h2>{t('plan.preset')}</h2>
            <div className="preset-row">
              {presets.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  className="preset-button"
                  onClick={() => onPreset(preset.id)}
                  title={preset.description}
                >
                  {preset.title}
                </button>
              ))}
              <button type="button" className="preset-button" onClick={() => onPreset('none')}>
                {t('common.none')}
              </button>
            </div>
            <div className="selection-count">
              {t('common.selected')}: {selected.size} {t('common.of')} {actionable.length}
            </div>
            {preset && (
              <div className="selection-count">
                <strong>{preset.title}:</strong> {preset.description} {t('plan.presetHint')}
              </div>
            )}
          </section>

          {outcome?.needsAdmin && (
            <div className="notice warn">
              <AlertTriangle size={16} />
              <div>
                <strong>{t('plan.needsAdmin')}</strong>
                <button type="button" className="button small" onClick={onRestartAdmin}>
                  {t('plan.restartAdmin')}
                </button>
              </div>
            </div>
          )}

          {outcome?.restorePoint && (
            <div className={`notice ${outcome.restorePoint.success ? 'ok' : 'warn'}`}>
              {outcome.restorePoint.success ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
              {outcome.restorePoint.success ? t('plan.restoreOk') : t('plan.restoreFail')}
            </div>
          )}

          {outcome && !outcome.needsAdmin && (
            <section className="panel">
              <h2>{t('report.title')}</h2>
              <div className="result-list">
                {outcome.results.map((result) => (
                  <div key={result.id} className={`result-row ${result.success ? 'ok' : 'fail'}`}>
                    {result.success ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                    <span>{result.title}</span>
                    <small>{result.success ? result.message : result.error}</small>
                  </div>
                ))}
              </div>
            </section>
          )}

          <section className="panel sticky-actions">
            <div>
              <h2>{t('plan.preview')}</h2>
              <p className="muted">
                {preview.length} {t('common.of')} {selected.size}
              </p>
            </div>
            <button type="button" className="button primary" onClick={onApply} disabled={applying || !selected.size}>
              {applying ? <RefreshCw size={16} className="spin" /> : <CheckCircle2 size={16} />}
              {applying ? t('common.loading') : t('plan.apply')}
            </button>
          </section>

          <FindingList
            findings={actionable}
            selected={selected}
            onToggle={onToggle}
            lang={lang}
            selectable
            t={t}
          />
        </>
      )}
    </div>
  );
}

interface ToolsViewProps {
  tools: ToolDefinition[];
  report: ScanReport | null;
  isAdmin: boolean;
  busyId: string | null;
  lastResult: { id: string; result: ToolRunResult } | null;
  onRun: (id: string) => void;
  onRestartAdmin: () => void;
  t: T;
}

function toolHint(tool: ToolDefinition, report: ScanReport | null, t: T): string | null {
  if (tool.requiresSelection) return t('tools.noSelection');
  if (tool.diskType === 'any') return null;
  if (!report) return t('tools.needScan');

  const detected = String(report.metrics.diskType || '').toLowerCase();
  if (!detected.includes(tool.diskType)) return t('tools.wrongDisk');
  return null;
}

export function ToolsView({
  tools,
  report,
  isAdmin,
  busyId,
  lastResult,
  onRun,
  onRestartAdmin,
  t,
}: ToolsViewProps) {
  return (
    <div className="page">
      <PageHeader title={t('tools.title')} subtitle={t('tools.subtitle')} />

      {lastResult?.result.needsAdmin && (
        <div className="notice warn">
          <AlertTriangle size={16} />
          <div>
            <strong>{t('tools.needAdmin')}</strong>
            <button type="button" className="button small" onClick={onRestartAdmin}>
              {t('tools.restartAdmin')}
            </button>
          </div>
        </div>
      )}

      {lastResult?.result.restorePoint && (
        <div className={`notice ${lastResult.result.restorePoint.success ? 'ok' : 'warn'}`}>
          {lastResult.result.restorePoint.success ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          {lastResult.result.restorePoint.success ? t('tools.restoreOk') : t('tools.restoreFail')}
        </div>
      )}

      {lastResult?.result.success && (
        <div className="notice ok">
          <CheckCircle2 size={16} />
          <div>
            <strong>{t('tools.success')}</strong>
            {lastResult.result.data?.nothingFound === true && (
              <div className="tool-result-detail">{t('tools.nothingFound')}</div>
            )}
            {lastResult.result.data?.freedBytes !== undefined && !lastResult.result.data?.nothingFound && (
              <div className="tool-result-detail">
                {t('tools.result')}: {formatBytes(Number(lastResult.result.data.freedBytes) || 0)}
                {lastResult.result.data.filesRemoved !== undefined &&
                  ` · ${Number(lastResult.result.data.filesRemoved)} ${t('overview.findings').toLowerCase()}`}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="tool-grid">
        {tools.map((tool) => {
          const localized = t(`tool.${tool.id}`);
          const title = localized === `tool.${tool.id}` ? tool.title : localized;
          const hint = toolHint(tool, report, t);
          const busy = busyId === tool.id;

          return (
            <article className="tool-card" key={tool.id}>
              <div className="tool-head">
                <div className="tool-icon">
                  <Wrench size={17} />
                </div>
                <h3>{title}</h3>
              </div>
              <p className="tool-description">{tool.description}</p>
              <div className="tool-tags">
                <span className={`badge ${tool.risk === 'high' ? 'danger' : tool.risk === 'medium' ? 'warn' : 'safe'}`}>
                  {t(`risk.${tool.risk}`)}
                </span>
                {tool.reversible && <span className="badge subtle">{t('common.rollback')}</span>}
                {tool.requiresAdmin && <span className="badge subtle">{t('tools.adminHint')}</span>}
              </div>
              {hint && <p className="tool-hint">{hint}</p>}
              <button
                type="button"
                className="button small"
                onClick={() => onRun(tool.id)}
                disabled={busy || Boolean(hint)}
              >
                {busy ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
                {busy ? t('tools.running') : t('tools.run')}
              </button>
            </article>
          );
        })}
      </div>

      {!isAdmin && <p className="muted tool-admin-note">{t('tools.needAdmin')}</p>}
    </div>
  );
}

interface ReportViewProps {
  comparison: Comparison | null;
  lang: Lang;
  t: T;
}

function DiffRow({
  label,
  before,
  after,
  better,
}: {
  label: string;
  before: string;
  after: string;
  better: boolean | null;
}) {
  return (
    <div className="diff-row">
      <span className="diff-label">{label}</span>
      <span className="diff-before">{before}</span>
      <span className="diff-arrow">→</span>
      <span className={`diff-after ${better === null ? '' : better ? 'better' : 'worse'}`}>{after}</span>
    </div>
  );
}

export function ReportView({ comparison, lang, t }: ReportViewProps) {
  if (!comparison) {
    return (
      <div className="page">
        <PageHeader title={t('report.title')} subtitle={t('report.subtitle')} />
        <div className="empty-state large">
          <BarChart3Icon />
          <p>{t('overview.noReport')}</p>
        </div>
      </div>
    );
  }

  const { before, after, results } = comparison;

  return (
    <div className="page">
      <PageHeader title={t('report.title')} subtitle={t('report.subtitle')} />
      <div className="notice ok">
        <CheckCircle2 size={16} />
        {t('report.rescan')}
      </div>

      <section className="panel">
        <h2>{t('score.title')}</h2>
        <DiffRow
          label={t('score.title')}
          before={`${before.score.value} / 100`}
          after={`${after.score.value} / 100`}
          better={after.score.value >= before.score.value}
        />
        <DiffRow
          label={t('overview.findings')}
          before={String(before.findings.length)}
          after={String(after.findings.length)}
          better={after.findings.length <= before.findings.length}
        />
        <DiffRow
          label={t('overview.disk')}
          before={`${before.system.disk.freePercent}%`}
          after={`${after.system.disk.freePercent}%`}
          better={after.system.disk.freePercent >= before.system.disk.freePercent}
        />
        <DiffRow
          label={t('categories.startup')}
          before={String(before.metrics.startupTotal ?? 0)}
          after={String(after.metrics.startupTotal ?? 0)}
          better={(after.metrics.startupTotal ?? 0) <= (before.metrics.startupTotal ?? 0)}
        />
        <DiffRow
          label={t('overview.ram')}
          before={`${before.system.ramUsedPercent}%`}
          after={`${after.system.ramUsedPercent}%`}
          better={after.system.ramUsedPercent <= before.system.ramUsedPercent}
        />
        <DiffRow
          label={t('categories.storage')}
          before={formatBytes(before.metrics.tempOldBytes || 0)}
          after={formatBytes(after.metrics.tempOldBytes || 0)}
          better={(after.metrics.tempOldBytes || 0) <= (before.metrics.tempOldBytes || 0)}
        />
        <DiffRow
          label={t('categories.power')}
          before={before.metrics.powerPlan || '—'}
          after={after.metrics.powerPlan || '—'}
          better={null}
        />
        {before.system.bootSeconds && after.system.bootSeconds ? (
          <DiffRow
            label={t('overview.boot')}
            before={`${before.system.bootSeconds} с`}
            after={`${after.system.bootSeconds} с`}
            better={after.system.bootSeconds <= before.system.bootSeconds}
          />
        ) : null}
      </section>

      <section className="panel">
        <h2>{t('plan.apply')}</h2>
        <div className="result-list">
          {results.map((result) => (
            <div key={result.id} className={`result-row ${result.success ? 'ok' : 'fail'}`}>
              {result.success ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
              <span>{result.title}</span>
              <small>{result.success ? result.message : result.error}</small>
            </div>
          ))}
        </div>
      </section>
      <p className="muted">{formatDate(after.scannedAt, lang)}</p>
    </div>
  );
}

function BarChart3Icon() {
  return <BarChart3 size={30} />;
}

interface JournalViewProps {
  entries: JournalEntry[];
  onRollback: (id: string) => void;
  lang: Lang;
  t: T;
}

export function JournalView({ entries, onRollback, lang, t }: JournalViewProps) {
  if (!entries.length) {
    return (
      <div className="page">
        <PageHeader title={t('journal.title')} subtitle={t('journal.subtitle')} />
        <div className="empty-state large">
          <RotateCcw size={30} />
          <p>{t('journal.empty')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader title={t('journal.title')} subtitle={t('journal.subtitle')} />
      <div className="journal-list">
        {entries.map((entry) => (
          <article className="journal-card" key={entry.id}>
            <div className="journal-head">
              <div>
                <h3>{entry.title}</h3>
                <p className="muted">
                  {t('journal.time')}: {formatDate(entry.createdAt, lang)}
                </p>
              </div>
              <span className={`badge ${entry.risk === 'high' ? 'danger' : entry.risk === 'medium' ? 'warn' : 'safe'}`}>
                {t(`risk.${entry.risk}`)}
              </span>
            </div>
            <div className="journal-actions">
              {entry.reversible ? (
                <button
                  type="button"
                  className="button small"
                  onClick={() => onRollback(entry.id)}
                  disabled={Boolean(entry.rolledBackAt)}
                >
                  <RotateCcw size={14} />
                  {entry.rolledBackAt ? t('journal.rolledBack') : t('common.rollback')}
                </button>
              ) : (
                <span className="muted">{t('common.none')}</span>
              )}
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

export function ConfirmDialog({
  title,
  body,
  onConfirm,
  onCancel,
  t,
}: {
  title: string;
  body: string;
  onConfirm: () => void;
  onCancel: () => void;
  t: T;
}) {
  return (
    <div className="modal-backdrop" role="presentation" onClick={onCancel}>
      <div className="modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
        <h2>{title}</h2>
        <p>{body}</p>
        <div className="modal-actions">
          <button type="button" className="button" onClick={onCancel}>
            {t('common.cancel')}
          </button>
          <button type="button" className="button danger" onClick={onConfirm}>
            <Power size={15} />
            {t('common.reboot')}
          </button>
        </div>
      </div>
    </div>
  );
}
