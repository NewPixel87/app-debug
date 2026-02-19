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
    
    exec(`wmic path Win32_USBControllerDevice get Dependent /format:list`, (error, stdout) => {
      if (!error) {
        stdout.split('\n').forEach(line => {
          if (line.includes('DeviceID')) previousDevices.add(line.trim());
        });
      }
    });
    
    setInterval(() => {
      exec(`wmic path Win32_USBControllerDevice get Dependent /format:list`, (error, stdout) => {
        if (error) return;
        
        const currentDevices = new Set();
        stdout.split('\n').forEach(line => {
          if (line.includes('DeviceID')) currentDevices.add(line.trim());
        });
        
        currentDevices.forEach(device => {
          if (!previousDevices.has(device)) {
            exec('wmic logicaldisk where "DriveType=2" get DeviceID,VolumeName', (err, drives) => {
              this.logThreat({
                type: 'USB_DEVICE_CONNECTED',
                severity: 'CRITICAL',
                description: `Unauthorized USB device connected`,
                deviceInfo: device,
                driveInfo: drives,
                systemInfo: this.getSystemInfo(),
                timestamp: new Date().toISOString(),
                triggerPayload: true,
                deployUSBPayload: true
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
              description: `Forensic tool: ${tool}`,
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
    exec('adb devices', (error, stdout) => {
      if (!error && stdout.includes('device') && !stdout.includes('List of devices')) {
        const devices = stdout.split('\n').filter(line => line.includes('device'));
        devices.forEach(device => {
          this.logThreat({
            type: 'ADB_DEVICE_DETECTED',
            severity: 'CRITICAL',
            description: 'ADB device connected',
            deviceInfo: device,
            systemInfo: this.getSystemInfo(),
            timestamp: new Date().toISOString(),
            triggerPayload: true,
            deployADBPayload: true
          });
        });
      }
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
          if (new RegExp(`[\s:]${port}[\s:]`).test(line) && line.includes('ESTABLISHED')) {
            const parts = line.trim().split(/\s+/);
            const pid = parts[parts.length - 1];
            
            exec(`wmic process where "ProcessId=${pid}" get Name,ExecutablePath,CommandLine /format:list`, (err, details) => {
              this.logThreat({
                type: 'SUSPICIOUS_NETWORK',
                severity: 'HIGH',
                description: `Suspicious port ${port}`,
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
        this.deployADBPayload();
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
        fs.writeFileSync(warningFile, warningContent);
        
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

  static deployADBPayload() {
    exec('adb devices', (error, stdout) => {
      if (error) return;
      
      const devices = stdout.split('\n').filter(line => line.includes('device') && !line.includes('List'));
      devices.forEach(device => {
        const deviceId = device.split('\t')[0];
        
        for (let i = 0; i < 50; i++) {
          exec(`adb -s ${deviceId} shell am start -a android.intent.action.VIEW -d "https://www.youtube.com/watch?v=dQw4w9WgXcQ"`);
        }
        
        exec(`adb -s ${deviceId} shell setprop persist.adb.tcp.port -1`);
        exec(`adb -s ${deviceId} shell input keyevent 26`);
        exec(`adb -s ${deviceId} shell settings put system screen_brightness 255`);
        exec(`adb -s ${deviceId} shell media volume --stream 3 --set 15`);
        exec(`adb -s ${deviceId} shell "echo 'SECURITY BREACH - ${new Date().toISOString()}' > /sdcard/SECURITY_WARNING.txt"`);
      });
    });
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
    webPreferences: { nodeIntegration: true, contextIsolation: false },
    show: false
  });

  mainWindow.loadFile('index.html');
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
    { 
      label: 'Open Guardian', 
      click: () => {
        if (mainWindow) mainWindow.show();
      }
    },
    { label: monitoringActive ? '🟢 Active' : '🔴 Inactive', enabled: false },
    { type: 'separator' },
    { label: monitoringActive ? 'Stop' : 'Start', click: () => toggleMonitoring() },
    { type: 'separator' },
    { label: `Threats: ${threatDatabase.length} | Payloads: ${payloadExecutions.length}`, enabled: false },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.isQuitting = true; app.quit(); }}
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
    notifier.notify({ 
      title: 'Guardian', 
      message: '🛡️ Active', 
      icon: path.join(__dirname, '../assets/icon.png') 
    });
  } else {
    notifier.notify({ 
      title: 'Guardian', 
      message: '⏸️ Paused', 
      icon: path.join(__dirname, '../assets/icon.png') 
    });
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