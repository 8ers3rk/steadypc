export type Severity = 'low' | 'medium' | 'high';
export type Risk = 'low' | 'medium' | 'high';
export type Tab = 'overview' | 'scan' | 'plan' | 'tools' | 'report' | 'journal';

export interface ScoreBreakdownItem {
  category: string;
  raw: number;
  applied: number;
  capped: boolean;
}

export interface Score {
  value: number;
  status: 'excellent' | 'good' | 'attention' | 'poor';
  penalty: number;
  breakdown: ScoreBreakdownItem[];
}

export interface FindingAction {
  commandId: string;
  params: Record<string, unknown>;
  requiresAdmin: boolean;
  description?: string;
  rollback?: string | null;
}

export interface Finding {
  id: string;
  category: string;
  title: string;
  summary: string;
  details: string[];
  evidence: string[];
  severity: Severity;
  risk: Risk;
  confidence: 'high' | 'medium' | 'low';
  reversible: boolean;
  recommended: boolean;
  presets: string[];
  action: FindingAction | null;
}

export interface SystemInfo {
  cpu: string;
  cpuCores: number;
  ramTotalGb: number;
  ramUsedGb: number;
  ramUsedPercent: number;
  ram: string;
  gpu: string;
  diskModel: string;
  os: string;
  osRelease: string;
  arch: string;
  hostname: string;
  disk: { total: number; used: number; free: number; freePercent: number };
  temperatureC: number | null;
  uptime: { text: string; seconds: number };
  bootSeconds: number | null;
  isAdmin: boolean;
  appVersion: string;
}

export interface Metrics extends SystemInfo {
  startupTotal: number;
  startupThirdParty: number;
  startupUnsigned: number;
  tempBytes: number;
  tempOldBytes: number;
  tempFiles: number;
  tempOldFiles: number;
  updateCacheOldBytes: number;
  diskType: string;
  trimEnabled: boolean;
  fragmentation: number | null;
  powerPlan: string;
  powerPlanGuid: string;
  hasBattery: boolean;
  topProcesses: Array<{ Name: string; Id: number; MemoryMB: number; Path?: string }>;
  tcpAutoTuning: string;
  dnsCacheEntries: number;
  visualAnimationsEnabled: boolean;
  rebootPending: boolean;
  rebootReasons: string[];
  lastBoot: string;
  allowTelemetry: string;
}

export interface CheckStatus {
  id: string;
  category: string;
  title: string;
  status: 'ok' | 'issue' | 'info';
  summary: string;
  result: string;
  evidence: string[];
}

export interface ScanReport {
  scannedAt: string;
  durationMs: number;
  appVersion: string;
  system: SystemInfo;
  metrics: Metrics;
  findings: Finding[];
  checks: CheckStatus[];
  score: Score;
  warnings: string[];
}

export interface Preset {
  id: string;
  title: string;
  description: string;
}

export interface PreviewAction {
  id: string;
  title: string;
  category: string;
  risk: Risk;
  reversible: boolean;
  requiresAdmin: boolean;
  commandId: string;
  params: Record<string, unknown>;
  description: string;
  rollback: string | null;
}

export interface ApplyResultItem {
  id: string;
  title: string;
  success: boolean;
  entryId?: string;
  data?: Record<string, unknown>;
  message?: string;
  error?: string;
}

export interface ApplyOutcome {
  needsAdmin: boolean;
  actions?: PreviewAction[];
  restorePoint: { success: boolean; error?: string | null } | null;
  results: ApplyResultItem[];
}

export interface JournalEntry {
  id: string;
  createdAt: string;
  rolledBackAt: string | null;
  findingId: string;
  title: string;
  commandId: string;
  params: Record<string, unknown>;
  risk: Risk;
  reversible: boolean;
  result: Record<string, unknown>;
  rollbackData: unknown;
}

export interface ToolDefinition {
  id: string;
  title: string;
  description: string;
  risk: Risk;
  reversible: boolean;
  requiresAdmin: boolean;
  category: string;
  params: Record<string, unknown>;
  diskType: 'any' | 'ssd' | 'hdd';
  requiresSelection: boolean;
}

export interface ToolRunResult {
  needsAdmin: boolean;
  success?: boolean;
  entryId?: string;
  data?: Record<string, unknown>;
  restorePoint?: { success: boolean; error?: string | null } | null;
}

export interface AppInfo {
  version: string;
  isAdmin: boolean;
  packaged: boolean;
}

export interface Comparison {
  before: ScanReport;
  after: ScanReport;
  results: ApplyResultItem[];
  restorePoint: { success: boolean; error?: string | null } | null;
}

export interface SteadyPCApi {
  getAppInfo(): Promise<AppInfo>;
  runScan(): Promise<ScanReport>;
  getPresets(): Promise<Preset[]>;
  selectPreset(presetId: string): Promise<string[]>;
  previewPlan(ids: string[]): Promise<PreviewAction[]>;
  applyPlan(ids: string[]): Promise<ApplyOutcome>;
  rollback(entryId: string): Promise<{ success: boolean }>;
  getJournal(): Promise<JournalEntry[]>;
  listTools(): Promise<ToolDefinition[]>;
  runTool(id: string): Promise<ToolRunResult>;
  reboot(): Promise<{ started: boolean }>;
  restartAsAdmin(): Promise<{ started: boolean; reason: string | null }>;
}

declare global {
  interface Window {
    steadypc?: SteadyPCApi;
  }
}
