import { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  ChevronDown,
  Copy,
  FolderOpen,
  Info,
  ShieldAlert,
} from 'lucide-react';
import { api } from '../lib/api';
import type { Finding } from '../types';
import type { Lang } from '../i18n';

type T = (key: string) => string;

interface FindingListProps {
  findings: Finding[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  lang: Lang;
  selectable: boolean;
  t: T;
}

function RiskBadge({ finding, t }: { finding: Finding; t: T }) {
  const tone = finding.risk === 'high' ? 'danger' : finding.risk === 'medium' ? 'warn' : 'safe';
  return (
    <span className={`badge ${tone}`}>
      {finding.risk === 'low' ? <Check size={12} /> : <AlertTriangle size={12} />}
      {t(`risk.${finding.risk}`)}
    </span>
  );
}

function securityPath(finding: Finding): string | null {
  const prefixes = ['Путь:', 'Команда:', 'Действие:'];
  for (const line of finding.evidence) {
    for (const prefix of prefixes) {
      if (!line.startsWith(prefix)) continue;
      const value = line.slice(prefix.length).trim();
      if (!value || value === '—') return null;
      const quoted = value.match(/^"([^"]+)"/);
      const path = quoted ? quoted[1] : value.split(/\s+/)[0];
      return path.length > 2 ? path : null;
    }
  }
  return null;
}

function SecurityActions({ finding, t }: { finding: Finding; t: T }) {
  const [busy, setBusy] = useState<'reveal' | 'copy' | 'tasks' | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const target = useMemo(() => securityPath(finding), [finding]);
  const payload = finding.evidence.join('\n');

  async function run(kind: 'reveal' | 'copy' | 'tasks') {
    setBusy(kind);
    setMessage(null);
    try {
      if (kind === 'reveal' && target) await api().revealPath(target);
      else if (kind === 'copy') await api().copyText(payload);
      else await api().openTaskManager();
      setMessage(t('security.status.done'));
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="security-actions">
      <div className="security-disclaimer">
        <Info size={14} />
        <span>{t('security.disclaimer')}</span>
      </div>
      <div className="detail-block">
        <div className="detail-title">
          <Activity size={14} />
          {t('security.actions.title')}
        </div>
        <p className="security-advice">{t(`security.action.${finding.confidence}`)}</p>
        <div className="security-button-row">
          {target && (
            <button
              type="button"
              className="button small"
              disabled={busy !== null}
              onClick={() => void run('reveal')}
            >
              <FolderOpen size={14} />
              {t('security.button.reveal')}
            </button>
          )}
          <button
            type="button"
            className="button small"
            disabled={busy !== null}
            onClick={() => void run('copy')}
          >
            <Copy size={14} />
            {t('security.button.copy')}
          </button>
          <button
            type="button"
            className="button small"
            disabled={busy !== null}
            onClick={() => void run('tasks')}
          >
            <Activity size={14} />
            {t('security.button.taskManager')}
          </button>
        </div>
        {!target && <p className="security-hint">{t('security.noPath')}</p>}
        {message && (
          <p className="security-status" role="status">
            {message}
          </p>
        )}
      </div>
    </div>
  );
}

function FindingCard({
  finding,
  checked,
  onToggle,
  selectable,
  t,
}: {
  finding: Finding;
  checked: boolean;
  onToggle: (id: string) => void;
  selectable: boolean;
  t: T;
}) {
  const [expanded, setExpanded] = useState(false);
  const isSecurity = finding.category === 'security';

  return (
    <article className={`finding-card ${checked ? 'selected' : ''}`}>
      <div className="finding-head">
        {selectable && finding.action ? (
          <label className="checkbox-wrap">
            <input
              type="checkbox"
              checked={checked}
              onChange={() => onToggle(finding.id)}
              aria-label={finding.title}
            />
            <span className="checkbox-box" />
          </label>
        ) : (
          <span className="finding-dot" />
        )}

        <div className="finding-main">
          <div className="finding-title-row">
            <h3>{finding.title}</h3>
            {isSecurity ? (
              <>
                <span className="badge subtle">{t('security.indicator')}</span>
                <span className="badge subtle">{t(`security.confidence.${finding.confidence}`)}</span>
              </>
            ) : (
              <>
                <RiskBadge finding={finding} t={t} />
                {finding.recommended && <span className="badge subtle">{t('common.recommended')}</span>}
                {!finding.action && <span className="badge subtle">{t('common.optional')}</span>}
              </>
            )}
          </div>
          <p className="finding-summary">{finding.summary}</p>
          <div className="finding-tags">
            <span>{t(`categories.${finding.category}`)}</span>
            {isSecurity ? (
              <span>{t(`severity.${finding.severity}`)}</span>
            ) : (
              <>
                <span>{t(`severity.${finding.severity}`)}</span>
                <span>{finding.reversible ? t('common.rollback') : t('common.none')}</span>
              </>
            )}
          </div>
        </div>

        <button
          type="button"
          className="expand-button"
          onClick={() => setExpanded((value) => !value)}
          aria-expanded={expanded}
        >
          <ChevronDown size={18} className={expanded ? 'rotated' : ''} />
        </button>
      </div>

      {expanded && (
        <div className="finding-body">
          {isSecurity && <SecurityActions finding={finding} t={t} />}

          <div className="detail-block">
            <div className="detail-title">
              <Info size={14} />
              {t('common.why')}
            </div>
            <ul>
              {finding.details.map((line, index) => (
                <li key={`${finding.id}-detail-${index}`}>{line}</li>
              ))}
            </ul>
          </div>

          {finding.evidence.length > 0 && (
            <div className="detail-block">
              <div className="detail-title">
                <ShieldAlert size={14} />
                {t('common.evidence')}
              </div>
              <ul className="evidence-list">
                {finding.evidence.map((line, index) => (
                  <li key={`${finding.id}-evidence-${index}`}>{line}</li>
                ))}
              </ul>
            </div>
          )}

          {finding.action && (
            <div className="action-note">
              <strong>{t('plan.preview')}:</strong> {finding.action.description || finding.summary}
              {finding.action.rollback && (
                <>
                  {' '}
                  <strong>{t('common.rollback')}:</strong> {finding.action.rollback}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </article>
  );
}

export function FindingList({ findings, selected, onToggle, lang, selectable, t }: FindingListProps) {
  void lang;
  if (!findings.length) {
    return (
      <div className="empty-state">
        <Check size={28} />
        <h3>{t('scan.noFindings')}</h3>
        <p>{t('scan.allGood')}</p>
      </div>
    );
  }

  return (
    <div className="finding-list">
      {findings.map((finding) => (
        <FindingCard
          key={finding.id}
          finding={finding}
          checked={selected.has(finding.id)}
          onToggle={onToggle}
          selectable={selectable}
          t={t}
        />
      ))}
    </div>
  );
}
