const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog } = require('electron');
const path = require('path');
const Store = require('electron-store');
const notifier = require('node-notifier');
const os = require('os');
const { exec, spawn } = require('child_process');
const fs = require('fs');

const store = new Store();
let mainWindow;
let tray;
let monitoringActive = false;
let threatDatabase = [];
let payloadExecutions = [];
let isAuthenticated = false;

// Track known devices by serial
const knownDevicesFile = path.join(app.getPath('userData'), 'known-devices.json');
function getKnownDevices() {
  try {
    if (fs.existsSync(knownDevicesFile)) return JSON.parse(fs.readFileSync(knownDevicesFile, 'utf8'));
  } catch(e) {}
  return [];
}
function saveKnownDevice(serial) {
  const known = getKnownDevices();
  if (!known.includes(serial)) {
    known.push(serial);
    fs.writeFileSync(knownDevicesFile, JSON.stringify(known, null, 2));
  }
}
function isKnownDevice(serial) {
  return getKnownDevices().includes(serial);
}

const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

class ThreatDetector {
  constructor() {
    this.usbMonitoring = false;
    this.processMonitoring = false;
    this.networkMonitoring = false;
    this.adbPinPending = false;
  }

  getSystemInfo() {
    return {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      username: os.userInfo().username,
      homeDir: os.userInfo().homedir,
      networkInterfaces: os.networkInterfaces(),
      cpus: os.cpus().length,
      totalMemory: Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB',
      uptime: Math.floor(os.uptime() / 3600) + 'h'
    };
  }

  startUSBMonitoring() {
    this.usbMonitoring = true;
    let previousDevices = new Set();

    const getDevices = (callback) => {
      exec(`wmic path Win32_PnPEntity where "DeviceID like 'USB%'" get DeviceID,Name,Status /format:list`, (error, stdout) => {
        const devices = new Set();
        if (!error) {
          stdout.split('\n').forEach(line => {
            if (line.includes('DeviceID=')) devices.add(line.trim());
          });
        }
        callback(devices);
      });
    };

    getDevices(devices => { previousDevices = devices; });

    setInterval(() => {
      getDevices(currentDevices => {
        currentDevices.forEach(device => {
          if (!previousDevices.has(device)) {
            exec(`wmic path Win32_PnPEntity where "DeviceID like 'USB%'" get DeviceID,Name,Manufacturer,Description /format:list`, (err, details) => {
              exec('wmic logicaldisk where "DriveType=2" get DeviceID,VolumeName,Size,FileSystem /format:list', (err2, drives) => {
                exec('adb devices -l', (aerr, adbOut) => {
                  this.logThreat({
                    type: 'USB_DEVICE_CONNECTED',
                    severity: 'CRITICAL',
                    description: `Unauthorized USB device connected`,
                    deviceInfo: device,
                    deviceDetails: details || 'N/A',
                    driveInfo: drives || 'N/A',
                    adbDevices: adbOut || 'N/A',
                    systemInfo: this.getSystemInfo(),
                    timestamp: new Date().toISOString(),
                    triggerPayload: true,
                    deployUSBPayload: true
                  });
                });
              });
            });
          }
        });
        previousDevices = currentDevices;
      });
    }, 2000);
  }

  startProcessMonitoring() {
    this.processMonitoring = true;
    setInterval(() => {
      this.scanForensicTools();
      this.scanADB();
    }, 5000);
  }

  scanForensicTools() {
    const forensicProcesses = [
      'wireshark', 'tcpdump', 'fiddler', 'burpsuite',
      'ida64', 'x64dbg', 'ollydbg', 'cheatengine',
      'processhacker', 'procmon', 'procexp'
    ];

    exec('tasklist', (error, stdout) => {
      if (error) return;
      const processes = stdout.toLowerCase();
      forensicProcesses.forEach(tool => {
        if (processes.includes(tool)) {
          exec(`wmic process where "name like '%${tool}%'" get ProcessId,ExecutablePath,CommandLine /format:list`, (err, details) => {
            this.logThreat({
              type: 'FORENSIC_TOOL_DETECTED',
              severity: 'CRITICAL',
              description: `Forensic tool detected: ${tool}`,
              processName: tool,
              processDetails: details || 'N/A',
              systemInfo: this.getSystemInfo(),
              timestamp: new Date().toISOString(),
              triggerPayload: true
            });
          });
        }
      });
    });
  }

  scanADB() {
    if (this.adbPinPending) return;

    exec('adb devices -l', (error, stdout) => {
      if (error) return;

      const lines = stdout.split('\n').filter(line =>
        line.includes('\t') && !line.includes('List of devices')
      );

      lines.forEach(line => {
        const serial = line.split('\t')[0].trim();
        if (!serial) return;

        const known = isKnownDevice(serial);

        // Get detailed device info
        exec(`adb -s ${serial} shell getprop ro.product.model`, (e1, model) => {
          exec(`adb -s ${serial} shell getprop ro.product.manufacturer`, (e2, manufacturer) => {
            exec(`adb -s ${serial} shell getprop ro.build.version.release`, (e3, androidVer) => {
              exec(`adb -s ${serial} shell getprop ro.product.device`, (e4, device) => {
                exec(`adb -s ${serial} shell pm list packages | grep -i adb`, (e5, adbPackages) => {
                  exec(`adb -s ${serial} shell ls -la /sdcard/Download/`, (e6, downloads) => {

                    const deviceInfo = {
                      serial: serial.trim(),
                      model: (model || '').trim(),
                      manufacturer: (manufacturer || '').trim(),
                      androidVersion: (androidVer || '').trim(),
                      device: (device || '').trim(),
                      adbRelatedApps: (adbPackages || 'None found').trim(),
                      downloads: (downloads || 'Unable to read').trim(),
                      knownDevice: known
                    };

                    // Save evidence
                    const evidenceDir = path.join(app.getPath('userData'), 'evidence');
                    if (!fs.existsSync(evidenceDir)) fs.mkdirSync(evidenceDir, { recursive: true });
                    const evidenceFile = path.join(evidenceDir, `adb-${serial}-${Date.now()}.json`);
                    fs.writeFileSync(evidenceFile, JSON.stringify(deviceInfo, null, 2));

                    this.logThreat({
                      type: 'ADB_DEVICE_DETECTED',
                      severity: 'CRITICAL',
                      description: `ADB device connected: ${deviceInfo.manufacturer} ${deviceInfo.model}`,
                      deviceInfo: deviceInfo,
                      systemInfo: this.getSystemInfo(),
                      timestamp: new Date().toISOString(),
                      triggerPayload: !known,
                      deployADBPayload: false, // Only after PIN skip
                      knownDevice: known,
                      evidenceFile: evidenceFile
                    });

                    // Show PIN prompt on this PC
                    this.adbPinPending = true;
                    showADBPinPrompt(serial, deviceInfo, known);
                  });
                });
              });
            });
          });
        });
      });
    });
  }

  startNetworkMonitoring() {
    this.networkMonitoring = true;
    setInterval(() => this.checkSuspiciousConnections(), 10000);
  }

  checkSuspiciousConnections() {
    exec('netstat -ano', (error, stdout) => {
      if (error) return;

      const suspiciousPorts = [4444, 5555, 8888, 9999];
      stdout.split('\n').forEach(line => {
        suspiciousPorts.forEach(port => {
          if (new RegExp(`[\\s:]${port}[\\s:]`).test(line) && line.includes('ESTABLISHED')) {
            const parts = line.trim().split(/\s+/);
            const pid = parts[parts.length - 1];

            exec(`wmic process where "ProcessId=${pid}" get Name,ExecutablePath,CommandLine /format:list`, (err, details) => {
              this.logThreat({
                type: 'SUSPICIOUS_NETWORK',
                severity: 'HIGH',
                description: `Suspicious port ${port} connection detected`,
                connectionDetails: line.trim(),
                processDetails: details || 'N/A',
                systemInfo: this.getSystemInfo(),
                timestamp: new Date().toISOString()
              });
            });
          }
        });
      });
    });
  }

  logThreat(threat) {
    threatDatabase.push(threat);

    if (threat.triggerPayload && threat.severity === 'CRITICAL') {
      PayloadEngine.executeThreatResponse(threat);
    }

    notifier.notify({
      title: `⚠️ ${threat.severity}`,
      message: threat.description,
      icon: path.join(__dirname, '../assets/icon.png'),
      sound: true
    });

    if (mainWindow) mainWindow.webContents.send('threat-detected', threat);

    const logFile = path.join(app.getPath('userData'), 'threat-log.txt');
    const logEntry = `\n${'='.repeat(80)}\n[${threat.timestamp}] ${threat.severity}: ${threat.type}\n${JSON.stringify(threat, null, 2)}\n`;
    fs.appendFileSync(logFile, logEntry);
  }
}

class PayloadEngine {
  static executeThreatResponse(threat) {
    const settings = store.get('payloadSettings', {
      lockWorkstation: true,
      killProcesses: false,
      wipeData: false,
      shutdownSystem: false,
      alertOnly: false
    });

    const execution = {
      threat: threat,
      timestamp: new Date().toISOString(),
      actions: []
    };

    if (settings.alertOnly) {
      this.showAlert(threat);
      execution.actions.push('ALERT_ONLY');
    } else {
      if (threat.deployUSBPayload) {
        this.deployUSBPayload();
        execution.actions.push('USB_PAYLOAD_DEPLOYED');
      }

      if (threat.deployADBPayload) {
        this.deployADBPayload(threat.deviceInfo ? threat.deviceInfo.serial : null);
        execution.actions.push('ADB_PAYLOAD_DEPLOYED');
      }

      if (settings.lockWorkstation) {
        this.lockWorkstation();
        execution.actions.push('LOCK_WORKSTATION');
      }

      if (settings.killProcesses && threat.processName) {
        this.killSuspiciousProcesses(threat);
        execution.actions.push(`KILL_PROCESS: ${threat.processName}`);
      }

      if (settings.wipeData) {
        this.confirmAndWipeData();
        execution.actions.push('DATA_WIPE');
      }

      if (settings.shutdownSystem) {
        this.shutdownSystem();
        execution.actions.push('SYSTEM_SHUTDOWN');
      }
    }

    payloadExecutions.push(execution);
    if (mainWindow) mainWindow.webContents.send('payload-executed', execution);

    const logFile = path.join(app.getPath('userData'), 'payload-log.txt');
    fs.appendFileSync(logFile, `\n${'='.repeat(80)}\n[${execution.timestamp}] PAYLOAD\nActions: ${execution.actions.join(', ')}\n${JSON.stringify(execution, null, 2)}\n`);
  }

  static deployUSBPayload() {
    exec('wmic logicaldisk where "DriveType=2" get DeviceID', (error, stdout) => {
      if (error) return;

      const drives = stdout.split('\n').filter(line => line.includes(':'));
      drives.forEach(drive => {
        const driveLetter = drive.trim();

        const warningFile = path.join(driveLetter, 'SECURITY_WARNING.txt');
        const warningContent = `
====================================
        SECURITY ALERT
====================================
This device accessed unauthorized system
Time: ${new Date().toLocaleString()}
System: ${os.hostname()}
Access logged and reported.
====================================
`;
        try { fs.writeFileSync(warningFile, warningContent); } catch(e) {}

        exec(`diskpart /s ${this.createDiskpartScript(driveLetter, 'readonly')}`);
        this.fillUSBStorage(driveLetter);
      });
    });
  }

  static fillUSBStorage(drive) {
    const dummyDir = path.join(drive, '.guardian_lock');
    try {
      fs.mkdirSync(dummyDir, { recursive: true });
      for (let i = 0; i < 100; i++) {
        const junkFile = path.join(dummyDir, `data_${i}.tmp`);
        fs.writeFileSync(junkFile, Buffer.alloc(1024 * 1024, 0));
      }
      exec(`attrib +h "${dummyDir}"`);
    } catch(e) {}
  }

  static createDiskpartScript(drive, action) {
    const scriptPath = path.join(app.getPath('temp'), 'diskpart.txt');
    const script = `select volume ${drive.charAt(0)}\nattributes disk set readonly\n`;
    fs.writeFileSync(scriptPath, script);
    return scriptPath;
  }

  static deployADBPayload(serial) {
    const target = serial ? `-s ${serial}` : '';
    exec(`adb ${target} shell setprop persist.adb.tcp.port -1`);
    exec(`adb ${target} shell input keyevent 26`);
    exec(`adb ${target} shell settings put system screen_brightness 255`);
    exec(`adb ${target} shell media volume --stream 3 --set 15`);
    exec(`adb ${target} shell "echo 'SECURITY BREACH - ${new Date().toISOString()}' > /sdcard/SECURITY_WARNING.txt"`);
  }

  static showAlert(threat) {
    if (mainWindow) {
      dialog.showMessageBoxSync(mainWindow, {
        type: 'error',
        title: '🛡️ Security Threat',
        message: threat.description,
        detail: `Severity: ${threat.severity}\nTime: ${threat.timestamp}`,
        buttons: ['OK']
      });
    }
  }

  static lockWorkstation() {
    if (os.platform() === 'win32') exec('rundll32.exe user32.dll,LockWorkStation');
  }

  static killSuspiciousProcesses(threat) {
    if (threat.processName) exec(`taskkill /IM ${threat.processName}.exe /F`);
  }

  static confirmAndWipeData() {
    if (mainWindow) {
      const response = dialog.showMessageBoxSync(mainWindow, {
        type: 'warning',
        title: '⚠️ Data Wipe',
        message: 'Wipe sensitive data?',
        buttons: ['Cancel', 'Wipe'],
        defaultId: 0
      });
      if (response === 1) {
        const paths = store.get('monitoredPaths', []);
        paths.forEach(dirPath => {
          try {
            if (fs.existsSync(dirPath)) fs.rmSync(dirPath, { recursive: true, force: true });
          } catch (e) {}
        });
      }
    }
  }

  static shutdownSystem() {
    if (os.platform() === 'win32') exec('shutdown /s /t 0');
  }
}

const detector = new ThreatDetector();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    icon: path.join(__dirname, '../assets/icon.png'),
    frame: true,
    autoHideMenuBar: true,  // Removes File/Edit/View menu bar
    webPreferences: { nodeIntegration: true, contextIsolation: false },
    show: false
  });

  mainWindow.loadFile('index.html');
  mainWindow.setMenu(null); // Fully remove menu bar
  mainWindow.once('ready-to-show', () => mainWindow.show());

  mainWindow.on('minimize', (e) => {
    e.preventDefault();
    mainWindow.hide();
  });

  mainWindow.on('close', (e) => {
    if (!app.isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
    return false;
  });
}

function showPinPrompt() {
  const pinWindow = new BrowserWindow({
    width: 400,
    height: 300,
    resizable: false,
    frame: false,
    alwaysOnTop: true,
    webPreferences: { nodeIntegration: true, contextIsolation: false }
  });
  pinWindow.loadFile('pin-prompt.html');
}

function showPinSetup() {
  const pinWindow = new BrowserWindow({
    width: 400,
    height: 350,
    resizable: false,
    frame: false,
    alwaysOnTop: true,
    webPreferences: { nodeIntegration: true, contextIsolation: false }
  });
  pinWindow.loadFile('pin-setup.html');
}

// ADB PIN prompt - shown on THIS PC when ADB device connects
function showADBPinPrompt(serial, deviceInfo, knownDevice) {
  const adbPinWindow = new BrowserWindow({
    width: 480,
    height: knownDevice ? 320 : 420,
    resizable: false,
    frame: false,
    alwaysOnTop: true,
    webPreferences: { nodeIntegration: true, contextIsolation: false }
  });

  adbPinWindow.loadFile('adb-pin-prompt.html');

  adbPinWindow.webContents.once('did-finish-load', () => {
    adbPinWindow.webContents.send('adb-device-info', { serial, deviceInfo, knownDevice });
  });

  ipcMain.once('adb-pin-verified', (event, pin) => {
    if (pin === store.get('securityPin')) {
      // Correct PIN - authorize device
      saveKnownDevice(serial);
      detector.adbPinPending = false;
      adbPinWindow.close();
      notifier.notify({ title: 'Guardian', message: `Device ${serial} authorized` });
    } else {
      adbPinWindow.webContents.send('adb-pin-error', 'Invalid PIN');
    }
  });

  ipcMain.once('adb-pin-skipped', () => {
    // Skip = unauthorized - deploy payload and disconnect
    detector.adbPinPending = false;
    adbPinWindow.close();

    notifier.notify({
      title: '⚠️ UNAUTHORIZED DEVICE',
      message: `Disconnecting and deploying countermeasures for ${serial}`,
      sound: true
    });

    // Deploy ADB payload
    PayloadEngine.deployADBPayload(serial);

    // Force disconnect ADB
    exec(`adb -s ${serial} disconnect`);
    exec(`adb disconnect`);

    // Log the skip event
    const logFile = path.join(app.getPath('userData'), 'threat-log.txt');
    fs.appendFileSync(logFile, `\n${'='.repeat(80)}\n[${new Date().toISOString()}] CRITICAL: ADB_UNAUTHORIZED_SKIP\nSerial: ${serial}\nDevice: ${JSON.stringify(deviceInfo)}\n`);
  });
}

function createTray() {
  try {
    const icon = nativeImage.createFromPath(path.join(__dirname, '../assets/tray-icon.png'));
    tray = new Tray(icon.resize({ width: 16, height: 16 }));
    updateTrayMenu();
    tray.on('click', () => {
      if (mainWindow && isAuthenticated) {
        mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
      }
    });
  } catch(e) {
    console.error('Tray creation failed:', e);
  }
}

function updateTrayMenu() {
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open Guardian', click: () => { if (mainWindow) mainWindow.show(); } },
    { label: monitoringActive ? '🟢 Active' : '🔴 Inactive', enabled: false },
    { type: 'separator' },
    { label: monitoringActive ? 'Stop' : 'Start', click: () => toggleMonitoring() },
    { type: 'separator' },
    { label: `Threats: ${threatDatabase.length} | Payloads: ${payloadExecutions.length}`, enabled: false },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.isQuitting = true; app.quit(); } }
  ]);
  tray.setToolTip(monitoringActive ? 'Guardian - Active' : 'Guardian - Inactive');
  tray.setContextMenu(contextMenu);
}

function toggleMonitoring() {
  monitoringActive = !monitoringActive;
  if (monitoringActive) {
    detector.startUSBMonitoring();
    detector.startProcessMonitoring();
    detector.startNetworkMonitoring();
    notifier.notify({ title: 'Guardian', message: '🛡️ Active', icon: path.join(__dirname, '../assets/icon.png') });
  } else {
    notifier.notify({ title: 'Guardian', message: '⏸️ Paused', icon: path.join(__dirname, '../assets/icon.png') });
  }
  updateTrayMenu();
  if (mainWindow) mainWindow.webContents.send('monitoring-status', monitoringActive);
}

app.whenReady().then(() => {
  createTray();
  if (!store.get('securityPin')) {
    showPinSetup();
  } else {
    showPinPrompt();
  }
  app.setLoginItemSettings({ openAtLogin: store.get('autoStart', false) });
});

app.on('window-all-closed', () => {
  // Keep app running in tray
});

app.on('before-quit', () => {
  app.isQuitting = true;
});

ipcMain.on('pin-verified', (event, pin) => {
  if (pin === store.get('securityPin')) {
    isAuthenticated = true;
    BrowserWindow.getFocusedWindow().close();
    createWindow();
    if (store.get('autoStartMonitoring', false)) {
      setTimeout(() => toggleMonitoring(), 2000);
    }
  } else {
    event.reply('pin-error', 'Invalid PIN');
  }
});

ipcMain.on('pin-setup', (event, pin) => {
  store.set('securityPin', pin);
  isAuthenticated = true;
  BrowserWindow.getFocusedWindow().close();
  createWindow();
});

ipcMain.on('set-auto-start', (e, enabled) => {
  store.set('autoStart', enabled);
  app.setLoginItemSettings({ openAtLogin: enabled });
});

ipcMain.on('set-auto-start-monitoring', (e, enabled) => store.set('autoStartMonitoring', enabled));
ipcMain.on('toggle-monitoring', () => toggleMonitoring());
ipcMain.on('get-threats', (e) => e.reply('threats-data', threatDatabase));
ipcMain.on('get-payload-executions', (e) => e.reply('payload-executions-data', payloadExecutions));
ipcMain.on('clear-threats', () => {
  threatDatabase = [];
  payloadExecutions = [];
  updateTrayMenu();
  if (mainWindow) mainWindow.webContents.send('threats-cleared');
});
ipcMain.on('update-payload-settings', (e, settings) => store.set('payloadSettings', settings));
ipcMain.on('get-payload-settings', (e) => e.reply('payload-settings', store.get('payloadSettings', {})));
ipcMain.on('add-monitored-path', (e, p) => {
  const paths = store.get('monitoredPaths', []);
  paths.push(p);
  store.set('monitoredPaths', paths);
  e.reply('monitored-paths', paths);
});
ipcMain.on('get-monitored-paths', (e) => e.reply('monitored-paths', store.get('monitoredPaths', [])));
