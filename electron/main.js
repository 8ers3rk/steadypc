'use strict';

const path = require('path');
const { app, BrowserWindow, clipboard, ipcMain, shell } = require('electron');
const { spawn } = require('child_process');
const { runScan } = require('./collectors');
const { PRESETS, selectedForPreset, buildPreview } = require('./plan');
const { executeCommand, rollbackCommand, isAdmin, createRestorePoint, restartAsAdmin, commands, listTools } = require('./commands');
const { readJournal, addEntry, markRolledBack } = require('./journal');
const {
  validatePresetId,
  validateIds,
  validateToolId,
  validateEntryId,
  validateSecurityPath,
  validateSecurityText,
} = require('./validation');

let mainWindow = null;
let lastScan = null;
let applying = false;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 1060,
    minHeight: 720,
    title: 'SteadyPC',
    backgroundColor: '#f4f6f9',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
}

function requiresPrivileges(action) {
  return Boolean(action.requiresAdmin || commands[action.commandId]?.requiresAdmin);
}

ipcMain.handle('app:info', () => ({
  version: require('../package.json').version,
  isAdmin: isAdmin(),
  packaged: app.isPackaged,
}));

ipcMain.handle('scan:run', async () => {
  const report = await runScan();
  lastScan = report;
  return report;
});

ipcMain.handle('plan:presets', () => PRESETS);

ipcMain.handle('plan:select-preset', (event, presetId) => {
  if (!lastScan) return [];
  return selectedForPreset(lastScan.findings, validatePresetId(presetId, PRESETS));
});

ipcMain.handle('plan:preview', (event, ids) => {
  if (!lastScan) return [];
  return buildPreview(lastScan.findings, validateIds(ids, lastScan.findings.map((item) => item.id)));
});

ipcMain.handle('plan:apply', async (event, ids) => {
  if (!lastScan) throw new Error('Сначала выполните сканирование');
  if (applying) throw new Error('Другое применение уже выполняется');

  const actions = buildPreview(lastScan.findings, validateIds(ids, lastScan.findings.map((item) => item.id)));
  if (!actions.length) return { needsAdmin: false, restorePoint: null, results: [] };

  const needsAdmin = actions.some(requiresPrivileges) && !isAdmin();
  if (needsAdmin) {
    return { needsAdmin: true, actions, restorePoint: null, results: [] };
  }

  const shouldCreatePoint = actions.some((action) => action.risk !== 'low' || requiresPrivileges(action));
  const restorePoint = shouldCreatePoint ? await createRestorePoint() : null;

  applying = true;
  const results = [];
  try {
    for (const action of actions) {
      try {
        const executed = await executeCommand(action.commandId, action.params);
        const entry = addEntry(app, {
          findingId: action.id,
          title: action.title,
          commandId: action.commandId,
          params: action.params,
          risk: action.risk,
          reversible: executed.reversible,
          result: executed.data,
          rollbackData: executed.rollbackData,
        });
        results.push({
          id: action.id,
          title: action.title,
          success: true,
          entryId: entry.id,
          data: executed.data,
          message: executed.reversible ? 'Изменение применено, откат доступен' : 'Изменение применено',
        });
      } catch (error) {
        results.push({
          id: action.id,
          title: action.title,
          success: false,
          error: error.message || String(error),
        });
      }
    }
  } finally {
    applying = false;
  }

  return { needsAdmin: false, restorePoint, results };
});

ipcMain.handle('tools:list', () => listTools());

ipcMain.handle('tools:run', async (event, id) => {
  const tools = listTools();
  const toolId = validateToolId(id, tools);
  const tool = tools.find((item) => item.id === toolId);
  if (!tool) throw new Error('Неизвестный инструмент');
  if (tool.requiresSelection) {
    throw new Error('Выберите конкретную запись на экране диагностики');
  }

  if (tool.diskType !== 'any') {
    const detected = String(lastScan?.metrics?.diskType || '').toLowerCase();
    if (!detected) throw new Error('Сначала выполните сканирование');
    if (!detected.includes(tool.diskType)) {
      throw new Error(`Операция доступна только для накопителя ${tool.diskType.toUpperCase()}`);
    }
  }

  if (tool.requiresAdmin && !isAdmin()) return { needsAdmin: true };
  if (applying) throw new Error('Другое изменение уже выполняется');

  const restorePoint = tool.risk !== 'low' || tool.requiresAdmin
    ? await createRestorePoint()
    : null;

  applying = true;
  try {
    let executed;
    try {
      executed = await executeCommand(tool.id, tool.params);
    } catch (error) {
      if (/не найдено/i.test(error.message || '')) {
        executed = {
          data: { freedBytes: 0, filesRemoved: 0, nothingFound: true },
          rollbackData: null,
          reversible: tool.reversible,
        };
      } else {
        throw error;
      }
    }

    if (executed.data?.nothingFound) {
      return { needsAdmin: false, success: true, data: executed.data, restorePoint };
    }

    const entry = addEntry(app, {
      findingId: `tool:${tool.id}`,
      title: tool.title,
      commandId: tool.id,
      params: tool.params,
      risk: tool.risk,
      reversible: executed.reversible,
      result: executed.data,
      rollbackData: executed.rollbackData,
    });
    return {
      needsAdmin: false,
      restorePoint,
      success: true,
      entryId: entry.id,
      data: executed.data,
    };
  } finally {
    applying = false;
  }
});

ipcMain.handle('plan:rollback', async (event, entryId) => {
  const id = validateEntryId(entryId);
  const entry = readJournal(app).find((item) => item.id === id);
  if (!entry) throw new Error('Запись журнала не найдена');
  await rollbackCommand(entry.commandId, entry.rollbackData);
  markRolledBack(app, id);
  return { success: true };
});

ipcMain.handle('journal:list', () => readJournal(app));

ipcMain.handle('reboot-pc', () => {
  spawn('shutdown.exe', ['/r', '/t', '10', '/c', 'SteadyPC: перезагрузка запрошена пользователем'], {
    windowsHide: true,
    detached: true,
    stdio: 'ignore',
  }).unref();
  return { started: true };
});

ipcMain.handle('app:restart-admin', () => restartAsAdmin());

ipcMain.handle('security:reveal', (event, target) => {
  const filePath = validateSecurityPath(target, 512);
  shell.showItemInFolder(filePath);
  return { shown: true };
});

ipcMain.handle('security:copy', (event, target) => {
  const text = validateSecurityText(target, 8192);
  clipboard.writeText(text);
  return { copied: true };
});

ipcMain.handle('security:open-task-manager', () => {
  const child = spawn('taskmgr.exe', [], { detached: true, stdio: 'ignore' });
  child.unref();
  return { started: true };
});

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    app.setAppUserModelId('com.steadypc.app');
    createWindow();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
