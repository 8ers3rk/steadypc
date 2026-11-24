'use strict';

function finding(config) {
  return {
    id: config.id,
    category: config.category,
    title: config.title,
    summary: config.summary,
    details: config.details || [],
    evidence: config.evidence || [],
    severity: config.severity || 'low',
    risk: config.risk || 'low',
    confidence: config.confidence || 'high',
    reversible: Boolean(config.reversible),
    recommended: Boolean(config.recommended),
    presets: config.presets || [],
    action: config.action || null,
  };
}

function check(config) {
  return {
    id: config.id,
    category: config.category,
    title: config.title,
    status: config.status || 'ok',
    summary: config.summary || '',
    result: config.result || '',
    evidence: config.evidence || [],
  };
}

module.exports = { finding, check };
