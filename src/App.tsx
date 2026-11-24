import { useCallback, useEffect, useState } from 'react';
import { AlertCircle } from 'lucide-react';
import { Layout } from './components/Layout';
import { FaqDialog } from './components/FaqDialog';
import {
  ConfirmDialog,
  JournalView,
  OverviewView,
  PlanView,
  ReportView,
  ScanView,
  ToolsView,
} from './components/Views';
import { api } from './lib/api';
import { translate, type Lang } from './i18n';
import type {
  AppInfo,
  ApplyOutcome,
  Comparison,
  JournalEntry,
  PreviewAction,
  Preset,
  ScanReport,
  Tab,
  ToolDefinition,
  ToolRunResult,
} from './types';

function storedLang(): Lang {
  try {
    return localStorage.getItem('steadypc.lang') === 'en' ? 'en' : 'ru';
  } catch (error) {
    return 'ru';
  }
}

function storedTheme(): 'light' | 'dark' {
  try {
    return localStorage.getItem('steadypc.theme') === 'light' ? 'light' : 'dark';
  } catch (error) {
    return 'dark';
  }
}

function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export default function App() {
  const [lang, setLang] = useState<Lang>(storedLang);
  const [theme, setTheme] = useState<'light' | 'dark'>(storedTheme);
  const [tab, setTab] = useState<Tab>('overview');
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<PreviewAction[]>([]);
  const [outcome, setOutcome] = useState<ApplyOutcome | null>(null);
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [journal, setJournal] = useState<JournalEntry[]>([]);
  const [tools, setTools] = useState<ToolDefinition[]>([]);
  const [busyTool, setBusyTool] = useState<string | null>(null);
  const [toolResult, setToolResult] = useState<{ id: string; result: ToolRunResult } | null>(null);
  const [busy, setBusy] = useState(false);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmReboot, setConfirmReboot] = useState(false);
  const [faqOpen, setFaqOpen] = useState(false);

  const t = useCallback((key: string) => translate(lang, key), [lang]);
  const closeFaq = useCallback(() => setFaqOpen(false), []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem('steadypc.theme', theme);
    } catch (caught) {
      void caught;
    }
  }, [theme]);

  useEffect(() => {
    try {
      localStorage.setItem('steadypc.lang', lang);
    } catch (caught) {
      void caught;
    }
  }, [lang]);

  useEffect(() => {
    let active = true;
    Promise.all([api().getAppInfo(), api().getPresets(), api().getJournal(), api().listTools()])
      .then(([info, presetList, entries, toolList]) => {
        if (!active) return;
        setAppInfo(info);
        setPresets(presetList);
        setJournal(entries);
        setTools(toolList);
      })
      .catch((caught) => {
        if (active) setError(messageOf(caught));
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!report) return;
    let active = true;
    api()
      .previewPlan([...selected])
      .then((items) => {
        if (active) setPreview(items);
      })
      .catch(() => {
        if (active) setPreview([]);
      });
    return () => {
      active = false;
    };
  }, [report, selected]);

  const toggleFinding = useCallback((id: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const runScan = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const next = await api().runScan();
      setReport(next);
      const ids = await api().selectPreset('balanced');
      setSelected(new Set(ids));
      setOutcome(null);
      setComparison(null);
    } catch (caught) {
      setError(messageOf(caught));
    } finally {
      setBusy(false);
    }
  }, []);

  const handlePreset = useCallback(async (presetId: string) => {
    try {
      const ids = await api().selectPreset(presetId);
      setSelected(new Set(ids));
    } catch (caught) {
      setError(messageOf(caught));
    }
  }, []);

  const handleApply = useCallback(async () => {
    if (!report) return;
    if (!selected.size) {
      setError(t('plan.noSelection'));
      return;
    }

    setApplying(true);
    setError(null);
    try {
      const before = report;
      const result = await api().applyPlan([...selected]);
      setOutcome(result);

      if (result.needsAdmin) return;

      const after = await api().runScan();
      setReport(after);
      setComparison({ before, after, results: result.results, restorePoint: result.restorePoint });
      setJournal(await api().getJournal());
      const ids = await api().selectPreset('balanced');
      setSelected(new Set(ids));
      setTab('report');
    } catch (caught) {
      setError(messageOf(caught));
    } finally {
      setApplying(false);
    }
  }, [report, selected, t]);

  const runTool = useCallback(async (id: string) => {
    setBusyTool(id);
    setError(null);
    setToolResult(null);
    try {
      const result = await api().runTool(id);
      setToolResult({ id, result });
      if (!result.needsAdmin && result.success) {
        setJournal(await api().getJournal());
      }
    } catch (caught) {
      setError(messageOf(caught));
    } finally {
      setBusyTool(null);
    }
  }, []);

  const handleRollback = useCallback(async (entryId: string) => {
    setError(null);
    try {
      await api().rollback(entryId);
      setJournal(await api().getJournal());
      const next = await api().runScan();
      setReport(next);
    } catch (caught) {
      setError(messageOf(caught));
    }
  }, []);

  const handleReboot = useCallback(async () => {
    setConfirmReboot(false);
    try {
      await api().reboot();
    } catch (caught) {
      setError(messageOf(caught));
    }
  }, []);

  const handleRestartAdmin = useCallback(async () => {
    try {
      const result = await api().restartAsAdmin();
      if (!result.started && result.reason) setError(result.reason);
    } catch (caught) {
      setError(messageOf(caught));
    }
  }, []);

  return (
    <Layout
      lang={lang}
      theme={theme}
      tab={tab}
      appInfo={appInfo}
      onTab={setTab}
      onToggleTheme={() => setTheme((value) => (value === 'dark' ? 'light' : 'dark'))}
      onToggleLang={() => setLang((value) => (value === 'ru' ? 'en' : 'ru'))}
      onOpenFaq={() => setFaqOpen(true)}
      t={t}
    >
      {error && (
        <div className="notice error" role="alert">
          <AlertCircle size={16} />
          <span>{error}</span>
          <button type="button" className="icon-button" onClick={() => setError(null)}>
            ×
          </button>
        </div>
      )}

      {tab === 'overview' && <OverviewView report={report} appInfo={appInfo} t={t} />}
      {tab === 'scan' && (
        <ScanView
          report={report}
          busy={busy}
          selected={selected}
          onToggle={toggleFinding}
          onScan={runScan}
          lang={lang}
          t={t}
        />
      )}
      {tab === 'plan' && (
        <PlanView
          report={report}
          presets={presets}
          selected={selected}
          preview={preview}
          outcome={outcome}
          applying={applying}
          onPreset={handlePreset}
          onToggle={toggleFinding}
          onApply={handleApply}
          onRestartAdmin={handleRestartAdmin}
          t={t}
        />
      )}
      {tab === 'tools' && (
        <ToolsView
          tools={tools}
          report={report}
          isAdmin={Boolean(appInfo?.isAdmin)}
          busyId={busyTool}
          lastResult={toolResult}
          onRun={runTool}
          onRestartAdmin={handleRestartAdmin}
          t={t}
        />
      )}
      {tab === 'report' && <ReportView comparison={comparison} lang={lang} t={t} />}
      {tab === 'journal' && <JournalView entries={journal} onRollback={handleRollback} lang={lang} t={t} />}

      {report?.metrics.rebootPending && (
        <button type="button" className="reboot-fab" onClick={() => setConfirmReboot(true)}>
          {t('common.reboot')}
        </button>
      )}

      {confirmReboot && (
        <ConfirmDialog
          title={t('confirm.reboot.title')}
          body={t('confirm.reboot.body')}
          onConfirm={handleReboot}
          onCancel={() => setConfirmReboot(false)}
          t={t}
        />
      )}

      {faqOpen && <FaqDialog lang={lang} t={t} onClose={closeFaq} />}
    </Layout>
  );
}
