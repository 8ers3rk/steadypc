'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('steadypc', {
  getAppInfo: () => ipcRenderer.invoke('app:info'),
  runScan: () => ipcRenderer.invoke('scan:run'),
  getPresets: () => ipcRenderer.invoke('plan:presets'),
  selectPreset: (presetId) => ipcRenderer.invoke('plan:select-preset', presetId),
  previewPlan: (ids) => ipcRenderer.invoke('plan:preview', ids),
  applyPlan: (ids) => ipcRenderer.invoke('plan:apply', ids),
  rollback: (entryId) => ipcRenderer.invoke('plan:rollback', entryId),
  getJournal: () => ipcRenderer.invoke('journal:list'),
  listTools: () => ipcRenderer.invoke('tools:list'),
  runTool: (id) => ipcRenderer.invoke('tools:run', id),
  reboot: () => ipcRenderer.invoke('reboot-pc'),
  restartAsAdmin: () => ipcRenderer.invoke('app:restart-admin'),
  revealPath: (target) => ipcRenderer.invoke('security:reveal', target),
  copyText: (text) => ipcRenderer.invoke('security:copy', text),
  openTaskManager: () => ipcRenderer.invoke('security:open-task-manager'),
});
