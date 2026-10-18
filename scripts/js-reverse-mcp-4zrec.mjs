#!/usr/bin/env node
// js-reverse-mcp 的 4zrec 启动包装（跨平台）。
//
// 上游默认启动有头 Chrome（browser.js 里写死 headless: false），在无桌面的
// 容器/服务器里会直接失败。这里默认走无头 attach：
//
//   1. 用 Playwright 已装好的 Chromium 起一个临时 profile 的无头实例；
//   2. 等 Chromium 把随机调试端口写进 DevToolsActivePort；
//   3. 让 js-reverse-mcp 通过 --browserUrl 接入该 CDP 端点。
//
// 桌面环境想用上游默认的有头 Chrome（反检测更好）时，设
// JS_REVERSE_MCP_DIRECT=1；此时要求系统已安装 Google Chrome。
//
// stdout 必须留给 MCP 的 JSON-RPC，诊断信息一律走 stderr。

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const MCP_BIN = process.env.JS_REVERSE_MCP_BIN || 'js-reverse-mcp';
const cliArgs = process.argv.slice(2);

function log(msg) {
  console.error(`[js-reverse] ${msg}`);
}

function fail(msg, logPath) {
  log(msg);
  if (logPath) {
    try {
      const lines = fs.readFileSync(logPath, 'utf8').split(/\r?\n/);
      console.error(lines.slice(-30).join('\n'));
    } catch {
      // no log to print
    }
  }
  process.exit(1);
}

function isUsableFile(p) {
  try {
    if (!fs.statSync(p).isFile()) return false;
    if (process.platform !== 'win32') fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function which(cmd) {
  const exts = process.platform === 'win32'
    ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';')
    : [''];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    for (const ext of exts) {
      const p = path.join(dir, cmd + ext);
      if (isUsableFile(p)) return p;
    }
  }
  return null;
}

function playwrightCacheRoots() {
  const roots = [process.env.PLAYWRIGHT_BROWSERS_PATH];
  if (process.platform === 'darwin') {
    roots.push(path.join(os.homedir(), 'Library', 'Caches', 'ms-playwright'));
  } else if (process.platform === 'win32') {
    roots.push(path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'ms-playwright'));
  } else {
    roots.push(path.join(os.homedir(), '.cache', 'ms-playwright'));
  }
  return roots.filter(Boolean);
}

function chromiumCandidates() {
  const out = [];
  if (process.env.JS_REVERSE_CHROMIUM) out.push(process.env.JS_REVERSE_CHROMIUM);

  const preferred = process.platform === 'win32'
    ? ['chrome.exe']
    : ['google-chrome', 'google-chrome-stable'];
  for (const name of preferred) {
    const p = which(name);
    if (p) out.push(p);
  }

  if (process.platform === 'win32') {
    for (const base of [process.env['ProgramFiles'], process.env['ProgramFiles(x86)'], process.env.LOCALAPPDATA]) {
      if (base) out.push(path.join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'));
    }
  } else if (process.platform === 'darwin') {
    out.push('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome');
  }

  for (const root of playwrightCacheRoots()) {
    let entries;
    try {
      entries = fs.readdirSync(root);
    } catch {
      continue;
    }
    // 完整 Chromium 优先，headless shell 只作兜底；新版本优先。
    const full = entries.filter((e) => /^chromium-\d/.test(e)).sort().reverse();
    const shells = entries.filter((e) => /^chromium_headless_shell-/.test(e)).sort().reverse();
    for (const dir of [...full, ...shells]) {
      const base = path.join(root, dir);
      if (process.platform === 'win32') {
        out.push(
          path.join(base, 'chrome-win64', 'chrome.exe'),
          path.join(base, 'chrome-win', 'chrome.exe'),
        );
      } else if (process.platform === 'darwin') {
        out.push(
          path.join(base, 'chrome-mac-arm64', 'Chromium.app', 'Contents', 'MacOS', 'Chromium'),
          path.join(base, 'chrome-mac', 'Chromium.app', 'Contents', 'MacOS', 'Chromium'),
        );
      } else {
        out.push(
          path.join(base, 'chrome-linux64', 'chrome'),
          path.join(base, 'chrome-linux', 'chrome'),
          path.join(base, 'chrome-linux', 'headless_shell'),
        );
      }
    }
  }

  // 最后才用发行版自带的 chromium/chromium-browser：有些环境里它们只是
  // snap/包装脚本，实际启动会失败；Playwright 缓存优先。
  const fallback = process.platform === 'win32'
    ? ['chromium.exe']
    : ['chromium', 'chromium-browser'];
  for (const name of fallback) {
    const p = which(name);
    if (p) out.push(p);
  }
  return [...new Set(out)];
}

function findChromium() {
  for (const p of chromiumCandidates()) {
    if (isUsableFile(p)) return p;
  }
  return null;
}

function spawnWithInheritedStdio(command, args) {
  const child = spawn(command, args, {
    stdio: 'inherit',
    // Windows 上 js-reverse-mcp 是 .cmd shim，需要 shell 才能解析。
    shell: process.platform === 'win32',
  });
  child.on('error', (err) => fail(`无法启动 ${command}：${err.message}`));
  child.on('exit', (code, signal) => {
    if (signal) {
      process.exit(128 + (os.constants.signals[signal] || 15));
    }
    process.exit(code ?? 0);
  });
}

// --help / --version 不启动浏览器，直接透传。
if (cliArgs.some((a) => a === '-h' || a === '--help' || a === '-v' || a === '--version' || a.startsWith('--version='))) {
  spawnWithInheritedStdio(MCP_BIN, cliArgs);
} else if (process.env.JS_REVERSE_MCP_DIRECT === '1') {
  // 上游默认：有头 Chrome + Patchright。需要系统装好 Google Chrome。
  spawnWithInheritedStdio(MCP_BIN, cliArgs);
} else {
  await runHeadlessAttach();
}

async function runHeadlessAttach() {
  const chromium = findChromium();
  if (!chromium) {
    fail('找不到 Chromium；请安装 Chrome/Chromium，或设置 JS_REVERSE_CHROMIUM=/path/to/chrome');
  }
  if (process.env.JS_REVERSE_DEBUG === '1') {
    log(`chromium: ${chromium}`);
  }

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'js-reverse-chrome-'));
  const logPath = path.join(profile, 'chrome.log');
  const chromeArgs = [
    '--headless=new',
    '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1',
    '--remote-allow-origins=*',
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--disable-dev-shm-usage',
  ];
  if (process.getuid?.() === 0 || process.env.JS_REVERSE_NO_SANDBOX === '1') {
    chromeArgs.push('--no-sandbox');
  }
  chromeArgs.push('about:blank');

  const logFd = fs.openSync(logPath, 'a');
  const chrome = spawn(chromium, chromeArgs, { stdio: ['ignore', 'ignore', logFd] });
  fs.closeSync(logFd);
  chrome.on('error', (err) => fail(`无法启动 Chromium：${err.message}`, logPath));

  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    try {
      chrome.kill('SIGTERM');
    } catch {
      // already gone
    }
    try {
      fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    } catch {
      // best effort
    }
  };
  process.on('exit', cleanup);
  process.on('SIGINT', () => {
    cleanup();
    process.exit(130);
  });
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(143);
  });

  const portFile = path.join(profile, 'DevToolsActivePort');
  const deadline = Date.now() + 15_000;
  let port = '';
  while (Date.now() < deadline) {
    if (chrome.exitCode !== null) {
      fail(`Chromium 启动失败（exit ${chrome.exitCode}）`, logPath);
    }
    try {
      const first = fs.readFileSync(portFile, 'utf8').split(/\r?\n/)[0].trim();
      if (first) {
        port = first;
        break;
      }
    } catch {
      // not written yet
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!port) {
    fail('等待 Chromium CDP 端口超时', logPath);
  }

  const mcp = spawn(MCP_BIN, ['--browserUrl', `http://127.0.0.1:${port}`, ...cliArgs], {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  mcp.on('error', (err) => fail(`无法启动 ${MCP_BIN}：${err.message}`, logPath));
  mcp.on('exit', (code, signal) => {
    cleanup();
    if (signal) {
      process.exit(128 + (os.constants.signals[signal] || 15));
    }
    process.exit(code ?? 0);
  });
}
