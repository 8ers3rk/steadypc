import { useState } from 'react';
import { AlertTriangle, Check, ChevronDown, Info, ShieldAlert } from 'lucide-react';
import type { Finding } from '../types';
import type { Lang } from '../i18n';

interface FindingListProps {
  findings: Finding[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  lang: Lang;
  selectable: boolean;
  t: (key: string) => string;
}

function RiskBadge({ finding, t }: { finding: Finding; t: (key: string) => string }) {
  const tone = finding.risk === 'high' ? 'danger' : finding.risk === 'medium' ? 'warn' : 'safe';
  return (
    <span className={`badge ${tone}`}>
      {finding.risk === 'low' ? <Check size={12} /> : <AlertTriangle size={12} />}
      {t(`risk.${finding.risk}`)}
    </span>
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
  t: (key: string) => string;
}) {
  const [expanded, setExpanded] = useState(false);

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
            <RiskBadge finding={finding} t={t} />
            {finding.recommended && <span className="badge subtle">{t('common.recommended')}</span>}
            {!finding.action && <span className="badge subtle">{t('common.optional')}</span>}
          </div>
          <p className="finding-summary">{finding.summary}</p>
          <div className="finding-tags">
            <span>{t(`categories.${finding.category}`)}</span>
            <span>{t(`severity.${finding.severity}`)}</span>
            <span>
              {finding.reversible ? t('common.rollback') : t('common.none')}
            </span>
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
