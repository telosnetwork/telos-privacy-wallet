const {app, BrowserWindow, session, shell, protocol, net, nativeImage, ipcMain} = require('electron');
const {join} = require('path');
const fs = require('fs')
const zp = require('libzkbob-rs-node');

let mainWindow;
const proofParamsCache = new Map();
const proofParameterFiles = new Map([
  ['prod', 'transfer_params_prod.bin'],
  ['staging', 'transfer_params.bin'],
]);

// Configure logging based on platform and environment
if (process.platform === 'win32' && app.isPackaged) {
  // Disable console logging in packaged Windows app to prevent console windows
  app.commandLine.appendSwitch('disable-logging');
} else {
  // Enable logging for development and other platforms
  app.commandLine.appendSwitch('enable-logging');
}

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'app',
    privileges: {
      secure: true,
      standard: true,
      supportFetchAPI: true,
      corsEnabled: true,
      stream: true,
    },
  },
]);

function isAppAsset(url) {
  return url.startsWith('app://');
}

const EMBED_TYPES = new Set([
  'mainFrame',
  'subFrame',
  'script',
  'xhr',
  'fetch',
  'other',
  'stylesheet',
  'image',
  'font',
]);

function installSecurityHooks() {
  // Set origin header for WalletConnect compatibility
  session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    const {url, requestHeaders} = details;

    // Override origin for WalletConnect relay connections
    if (url.includes('relay.walletconnect.com') || url.includes('walletconnect')) {
      requestHeaders['Origin'] = 'https://privacy.telos.protofire.io';
    }

    callback({requestHeaders});
  });

  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const {url, responseHeaders, resourceType} = details;
    let headers = {...responseHeaders};

    const isWS =
      resourceType === 'webSocket' ||
      resourceType === 'websocket' ||
      url.startsWith('ws:') ||
      url.startsWith('wss:');

    if (!isAppAsset(url) || isWS || !EMBED_TYPES.has(resourceType)) {
      callback({responseHeaders: headers});
      return;
    }

    if (url.endsWith('.wasm')) headers['Content-Type'] = ['application/wasm'];
    else if (url.endsWith('.bin')) headers['Content-Type'] = ['application/octet-stream'];

    headers['Cross-Origin-Opener-Policy'] = ['same-origin'];
    headers['Cross-Origin-Embedder-Policy'] = ['credentialless'];

    callback({responseHeaders: headers});
  });

  session.defaultSession.webRequest.onCompleted((d) => {
    if (d.resourceType === 'webSocket' && d.url.startsWith('wss://relay.walletconnect.com')) {
      console.log('[WS completed]', {statusCode: d.statusCode});
    }
  });
  session.defaultSession.webRequest.onErrorOccurred((d) => {
    if (d.resourceType === 'webSocket' && d.url.startsWith('wss://relay.walletconnect.com')) {
      console.log('[WS errorOccurred]', {error: d.error});
    }
  });
}

async function registerAppProtocolHandler() {
  protocol.handle('app', async (request) => {
    const url = new URL(request.url);
    let rel = decodeURIComponent(url.pathname);
    if (rel.startsWith('/')) rel = rel.slice(1);

    if (rel.startsWith('assets/')) {
      const assetPath = join(__dirname, 'assets', rel.replace(/^assets\//, ''));
      return net.fetch('file://' + assetPath);
    }

    if (rel === '' || rel.endsWith('/')) rel += 'index.html';
    const buildPath = join(__dirname, '../build', rel);
    return net.fetch('file://' + buildPath);
  });
}

function createWindow() {
  // Set app icon
  const iconPath = app.isPackaged
    ? join(__dirname, '../build/logo512.png')
    : join(__dirname, '../public/logo512.png');

  const icon = nativeImage.createFromPath(iconPath);

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    show: false,
    icon: icon,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: true,
      sandbox: false,
      experimentalFeatures: true,
      preload: join(__dirname, 'preload.js'),
    },
  });

  // Set platform-specific user agent
  const userAgent = process.platform === 'win32'
    ? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
    : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

  mainWindow.webContents.setUserAgent(userAgent);

  mainWindow.loadURL(app.isPackaged ? 'app://local/index.html' : 'http://localhost:3000');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => (mainWindow = null));

  mainWindow.webContents.setWindowOpenHandler(({url}) => {
    shell.openExternal(url);
    return {action: 'deny'};
  });
}

function loadProofParameters(alias) {
  // Resolve only bundled, known parameter sets; never accept a renderer path.
  const filename = proofParameterFiles.get(alias);
  if (!filename) {
    throw new Error('Unsupported proof parameter set');
  }
  if (!proofParamsCache.has(alias)) {
    const bin = fs.readFileSync(join(__dirname, 'assets', filename));
    proofParamsCache.set(alias, zp.readParamsFromBinary(bin, false));
  }
  return proofParamsCache.get(alias);
}

app.whenReady().then(async () => {
  await registerAppProtocolHandler();
  installSecurityHooks();
  setupRustIpcHandler();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('web-contents-created', (_event, contents) => {
  contents.on('new-window', (event, navigationUrl) => {
    event.preventDefault();
    shell.openExternal(navigationUrl);
  });
});

app.on('certificate-error', (_event, _webContents, _url, _error, _certificate, callback) => {
  callback(false);
});

function setupRustIpcHandler() {
  // Channel name for the request
  const channel = 'prove-tx';

  // Handle synchronous request from the Renderer
  ipcMain.handle(channel, async (_, inputData) => {
    try {
      const params = loadProofParameters(inputData[2])
      const result = await zp.proveTxAsync(params, inputData[0], inputData[1])

      return result
    } catch (error) {
      // Native errors can contain transaction inputs; never log or return them.
      console.error('[IPC Main] Local proof generation failed');
      // Return an error object
      return {success: false, error: 'Unable to generate proof locally.'};
    }
  });
}
