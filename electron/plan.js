'use strict';

const PRESETS = Object.freeze([
  {
    id: 'balanced',
    title: 'Баланс',
    description: 'Умеренные изменения без заметного влияния на внешний вид и поведение системы.',
  },
  {
    id: 'performance',
    title: 'Производительность',
    description: 'Меньше фоновой нагрузки и визуальных эффектов, более активный план питания.',
  },
  {
    id: 'gaming',
    title: 'Игры',
    description: 'Минимум отвлекающих процессов и эффектов во время игры.',
  },
  {
    id: 'saver',
    title: 'Энергосбережение',
    description: 'Приоритет автономности и низкого энергопотребления.',
  },
  {
    id: 'advanced',
    title: 'Расширенные',
    description: 'Изменения с повышенным риском. Применяйте только понимая последствия.',
  },
]);

function actionableFindings(findings) {
  return findings.filter((finding) => finding.action && finding.action.commandId);
}

function selectedForPreset(findings, presetId) {
  if (presetId === 'all') return actionableFindings(findings).map((finding) => finding.id);
  if (presetId === 'none') return [];
  return actionableFindings(findings)
    .filter((finding) => Array.isArray(finding.presets) && finding.presets.includes(presetId))
    .map((finding) => finding.id);
}

function buildPreview(findings, ids) {
  const wanted = new Set(ids);
  return actionableFindings(findings)
    .filter((finding) => wanted.has(finding.id))
    .map((finding) => ({
      id: finding.id,
      title: finding.title,
      category: finding.category,
      risk: finding.risk,
      reversible: finding.reversible,
      requiresAdmin: Boolean(finding.action.requiresAdmin),
      commandId: finding.action.commandId,
      params: finding.action.params || {},
      description: finding.action.description || finding.summary,
      rollback: finding.action.rollback || null,
    }));
}

module.exports = { PRESETS, selectedForPreset, buildPreview, actionableFindings };
