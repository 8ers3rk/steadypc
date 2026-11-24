'use strict';

const SEVERITY_WEIGHT = Object.freeze({ low: 3, medium: 7, high: 14 });

const CATEGORY_CAP = Object.freeze({
  startup: 12,
  storage: 18,
  power: 10,
  disk: 14,
  processes: 8,
  network: 6,
  visual: 4,
  privacy: 2,
  updates: 8,
});

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function scoreFindings(findings) {
  const perCategory = new Map();

  for (const finding of findings) {
    const weight = SEVERITY_WEIGHT[finding.severity] || 0;
    const current = perCategory.get(finding.category) || 0;
    perCategory.set(finding.category, current + weight);
  }

  const breakdown = [...perCategory.entries()]
    .map(([category, raw]) => ({
      category,
      raw,
      applied: Math.min(raw, CATEGORY_CAP[category] || 10),
      capped: raw > (CATEGORY_CAP[category] || 10),
    }))
    .sort((a, b) => b.applied - a.applied);

  const penalty = Math.min(90, breakdown.reduce((sum, item) => sum + item.applied, 0));
  const value = clamp(100 - penalty, 10, 100);

  let status = 'good';
  if (value >= 90) status = 'excellent';
  else if (value >= 75) status = 'good';
  else if (value >= 55) status = 'attention';
  else status = 'poor';

  return { value, status, penalty, breakdown };
}

function scoreReportFindings(findings) {
  return scoreFindings(findings.filter((item) => item.category !== 'security'));
}

module.exports = { scoreFindings, scoreReportFindings, SEVERITY_WEIGHT, CATEGORY_CAP };
