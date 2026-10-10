(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const ui = {
    platform: $('platform-label'), statusDot: $('status-indicator'), statusTitle: $('status-title'),
    statusDetail: $('status-detail'), error: $('global-error'), configState: $('config-state'),
    file: $('yaml-file'), fileName: $('file-name'), yaml: $('yaml-input'), importButton: $('import-button'),
    core: $('core-path'), saveCore: $('save-core-button'), node: $('node-select'), saveNode: $('save-node-button'),
    nodeHint: $('node-hint'), proxy: $('proxy-address'), ports: $('port-summary'), version: $('version-label'),
    footerVersion: $('footer-version'), start: $('start-button'), stop: $('stop-button'), apps: $('apps-list'),
    launchAll: $('launch-all-button'), appLabel: $('app-label'), appPath: $('app-path'),
    appAdapter: $('app-adapter'), appArgs: $('app-args'), addApp: $('add-app-button'), availablePaths: $('available-app-paths'),
    appSearch: $('app-search'), refreshApps: $('refresh-apps-button'), availableApps: $('available-apps-list'),
    availableAppsCount: $('available-apps-count'),
    protectionCard: $('protection-card'), protectionBadge: $('protection-badge'), protectionDetail: $('protection-detail'),
    protectionBackend: $('protection-backend'), protectionLimitations: $('protection-limitations'),
    runtimeSettings: $('windows-runtime-settings'), runtimePath: $('runtime-path'), saveRuntime: $('save-runtime-button'),
  };
  let state = null;
  let busy = false;
  let lastAppsSignature = '';
  let lastAvailableSignature = '';
  let refreshingApps = false;

  function showError(message, source = 'local') {
    if (message) {
      ui.error.className = 'notice error-notice';
      ui.error.dataset.source = source;
    } else {
      delete ui.error.dataset.source;
    }
    ui.error.textContent = message || '';
    ui.error.hidden = !message;
  }

  function setBusy(value) {
    busy = value;
    renderControls();
  }

  function renderControls() {
    const ready = !!state;
    const imported = ready && !!state.imported;
    const running = ready && !!state.running;
    const protectedBackend = ready && !!state.protection && !!state.protection.supported;
    ui.importButton.disabled = busy || !ready;
    ui.core.disabled = busy || !ready || running;
    ui.saveCore.disabled = busy || !ready || running;
    ui.saveNode.disabled = busy || !imported || !ui.node.value;
    ui.node.disabled = busy || !imported || !((state && state.nodes) || []).length;
    ui.start.disabled = busy || !imported || running;
    ui.stop.disabled = busy || !running;
    ui.addApp.disabled = busy || !ready;
    ui.refreshApps.disabled = busy || refreshingApps || !ready;
    ui.refreshApps.textContent = refreshingApps ? '正在扫描…' : '重新扫描';
    ui.launchAll.disabled = busy || !running || !protectedBackend || !(state.apps || []).some((app) => app.enabled && !app.active && !app.cleanup_pending);
    if (ui.saveRuntime) ui.saveRuntime.disabled = busy || !ready || running;
    if (ui.runtimePath) ui.runtimePath.disabled = busy || !ready || running;
    ui.apps.querySelectorAll('.app-toggle input, .remove-app').forEach((control) => { control.disabled = busy; });
    ui.availableApps.querySelectorAll('.discovery-add').forEach((control) => { control.disabled = busy || control.dataset.added === 'true'; });
    ui.apps.querySelectorAll('.app-action').forEach((control) => {
      const app = (state.apps || []).find((item) => String(item.id) === control.dataset.appId);
      const canLaunch = app && app.enabled && running && protectedBackend;
      control.disabled = busy || (!(app?.active || app?.cleanup_pending) && !canLaunch);
      control.title = app?.cleanup_pending ? '关闭上次启动中保留的隔离守卫' : (app?.active ? '关闭此工具启动的隔离实例' : (!running ? '请先启动核心' : (!protectedBackend ? '本机隔离能力不可用，启动已阻断' : (!app?.enabled ? '请先加入待保护列表' : '通过隔离方式启动此应用'))));
    });
  }

  function textElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function renderApps() {
    const apps = state && Array.isArray(state.apps) ? state.apps : [];
    const signature = JSON.stringify(apps);
    if (signature === lastAppsSignature) return;
    lastAppsSignature = signature;
    const active = document.activeElement;
    const activeId = active && active.dataset ? active.dataset.appControl : '';
    ui.apps.replaceChildren();
    if (!apps.length) {
      const empty = textElement('div', 'empty-state');
      empty.append(textElement('span', 'empty-symbol', '＋'), textElement('strong', '', '还没有添加应用'), textElement('span', '', '从已安装应用中选择，或展开手动添加。'));
      ui.apps.append(empty);
      return;
    }
    for (const app of apps) {
      const row = textElement('article', 'app-row');
      const enabledLabel = textElement('label', 'app-toggle');
      const enabled = document.createElement('input');
      enabled.type = 'checkbox';
      enabled.checked = !!app.enabled;
      enabled.disabled = busy;
      enabled.setAttribute('aria-label', `将 ${app.label || '应用'}加入启动清单`);
      enabled.dataset.appControl = `${app.id}:enabled`;
      enabled.addEventListener('change', () => {
        const requested = enabled.checked;
        mutate(`/api/apps/${encodeURIComponent(app.id)}`, { method: 'POST', body: { enabled: requested } }).then((result) => {
          if (!result) enabled.checked = !!app.enabled;
        });
      });
      const toggleMark = textElement('span', 'toggle-mark');
      enabledLabel.append(enabled, toggleMark);

      const appInfo = textElement('div', 'app-info');
      appInfo.append(textElement('strong', 'app-name', app.label || '未命名应用'));
      const statusText = app.cleanup_pending ? '清理待完成' : (app.active ? '隔离中运行' : (app.enabled ? '待启动' : '未启用'));
      const statusClass = app.cleanup_pending ? 'is-pending' : (app.active ? 'is-active' : (app.enabled ? 'is-enabled' : ''));
      appInfo.append(textElement('span', `app-inline-status ${statusClass}`, statusText));
      appInfo.append(textElement('span', 'app-path', app.path || '未设置路径'));
      const adapter = friendlyAdapter(app.adapter);
      const appMeta = textElement('div', 'app-meta');
      appMeta.append(textElement('span', 'app-adapter', adapter));
      const status = textElement('span', `app-status ${statusClass}`, statusText);
      appMeta.append(status);
      const launch = textElement('button', 'button button-launch app-action', app.cleanup_pending ? '关闭守卫' : (app.active ? '关闭实例' : '启动隔离实例 ↗'));
      launch.type = 'button';
      launch.dataset.appId = String(app.id);
      launch.disabled = busy || ((app.active || app.cleanup_pending) ? false : !(app.enabled && state.running && state.protection && state.protection.supported));
      launch.title = app.cleanup_pending ? '关闭上次启动中保留的隔离守卫' : (app.active ? '关闭此工具启动的隔离实例' : (!state.running ? '请先启动核心' : (!(state.protection && state.protection.supported) ? '本机隔离能力不可用，启动已阻断' : (!app.enabled ? '请先加入待保护列表' : '通过隔离方式启动此应用'))));
      launch.addEventListener('click', () => (app.active || app.cleanup_pending) ? stopApp(app) : launchApp(app));
      const remove = textElement('button', 'icon-button remove-app', '×');
      remove.type = 'button';
      remove.setAttribute('aria-label', `移除 ${app.label || '应用'}`);
      remove.title = '移除应用';
      remove.disabled = busy;
      remove.addEventListener('click', () => removeApp(app));
      row.append(enabledLabel, appInfo, appMeta, launch, remove);
      ui.apps.append(row);
    }
    if (activeId) {
      const restored = ui.apps.querySelector(`[data-app-control="${CSS.escape(activeId)}"]`);
      if (restored) restored.focus({ preventScroll: true });
    }
  }

  function friendlyAdapter(adapter) {
    const names = { chrome: '浏览器 / Electron · 独立配置', chromium: '浏览器 / Electron · 独立配置', edge: '浏览器 / Electron · 独立配置', brave: '浏览器 / Electron · 独立配置', firefox: 'Firefox · 独立配置', env: '代理环境变量启动', environment: '代理环境变量启动' };
    return names[adapter] || (adapter ? String(adapter) : '应用启动');
  }

  function compatibilityHint(adapter) {
    if (adapter === 'chromium' || adapter === 'chrome' || adapter === 'edge' || adapter === 'brave') return '使用独立配置；已有窗口不会自动接管。';
    if (adapter === 'firefox') return '使用独立 Firefox 配置；已有窗口不会接管。';
    if (adapter === 'environment' || adapter === 'env') return '应用若不遵循代理设置，其联网请求会被阻断。';
    return '需通过本机隔离能力检查后才能启动。';
  }

  function sameAppPath(left, right) {
    const normalize = (value) => String(value || '').replaceAll('\\', '/').replace(/\/$/, '');
    const a = normalize(left);
    const b = normalize(right);
    const windows = /windows|win32|win64/i.test(String(state && state.platform || ''));
    return windows ? a.toLocaleLowerCase() === b.toLocaleLowerCase() : a === b;
  }

  function renderAvailableApps() {
    const available = state && Array.isArray(state.available_apps) ? state.available_apps : [];
    const saved = state && Array.isArray(state.apps) ? state.apps : [];
    const signature = JSON.stringify({ available, saved: saved.map((app) => [app.path, app.enabled, app.active]) });
    if (signature === lastAvailableSignature && ui.availableApps.dataset.query === ui.appSearch.value) return;
    lastAvailableSignature = signature;
    const query = ui.appSearch.value.trim().toLocaleLowerCase();
    ui.availableApps.dataset.query = ui.appSearch.value;
    ui.availableApps.replaceChildren();
    const matches = available.filter((app) => `${app.label || ''} ${app.path || ''} ${friendlyAdapter(app.adapter)}`.toLocaleLowerCase().includes(query));
    const limit = query ? 60 : 24;
    const visible = matches.slice(0, limit);
    ui.availableAppsCount.textContent = available.length
      ? (query ? `找到 ${matches.length} 项` : `发现 ${available.length} 项`)
      : '未发现可添加的应用';
    if (!visible.length) {
      const empty = textElement('div', 'discovery-empty', query ? '没有找到匹配的应用。' : '系统暂未发现可添加的应用。');
      ui.availableApps.append(empty);
      return;
    }
    for (const app of visible) {
      const row = textElement('article', 'available-app-row');
      const info = textElement('div', 'available-app-info');
      info.append(textElement('strong', 'available-app-name', app.label || '未命名应用'));
      info.append(textElement('span', 'available-app-kind', friendlyAdapter(app.adapter)));
      info.append(textElement('span', 'available-app-hint', compatibilityHint(app.adapter)));
      const button = textElement('button', 'button button-secondary discovery-add');
      button.type = 'button';
      const alreadyAdded = saved.some((savedApp) => sameAppPath(savedApp.path, app.path));
      button.dataset.added = String(alreadyAdded);
      button.disabled = busy || alreadyAdded;
      button.textContent = alreadyAdded ? '已添加' : '添加';
      button.setAttribute('aria-label', `${alreadyAdded ? '已添加' : '添加'} ${app.label || '应用'}`);
      button.addEventListener('click', () => addDiscoveredApp(app));
      row.append(info, button);
      ui.availableApps.append(row);
    }
    if (matches.length > visible.length) {
      ui.availableApps.append(textElement('div', 'discovery-more', `仅显示前 ${visible.length} 项，请继续搜索缩小范围。`));
    }
  }

  async function addDiscoveredApp(app) {
    if (busy || !app || !app.path || !app.adapter) return;
    const label = String(app.label || app.path);
    const args = Array.isArray(app.args) ? app.args : [];
    await mutate('/api/apps', { body: { label, path: app.path, adapter: app.adapter, args, enabled: true } });
  }

  function render(stateValue) {
    state = stateValue;
    if (!state) return;
    ui.platform.textContent = state.platform || '本机服务';
    ui.statusDot.className = `status-indicator ${state.running ? 'is-running' : ''}`;
    ui.statusTitle.textContent = state.running ? '核心正在运行' : (state.imported ? '配置已就绪' : '等待导入配置');
    ui.statusDetail.textContent = state.running ? '本机 Mihomo 已启动；应用保护状态见下方' : (state.imported ? '核心尚未启动' : '导入 YAML 配置以开始');
    ui.configState.textContent = state.imported ? '已导入' : '尚未导入';
    ui.configState.className = `pill ${state.imported ? 'pill-ready' : ''}`;
    if (document.activeElement !== ui.core) ui.core.value = state.core_path || '';
    if (document.activeElement !== ui.node) {
      const previous = ui.node.value;
      const selected = state.selected_node || '';
      const nodes = Array.isArray(state.nodes) ? state.nodes : [];
      ui.node.replaceChildren();
      if (!nodes.length) {
        ui.node.append(new Option(state.imported ? '配置中没有可选择的节点' : '先导入配置', ''));
      } else {
        ui.node.append(new Option('选择一个节点', ''));
        for (const node of nodes) {
          const name = typeof node === 'string' ? node : node.name;
          const type = typeof node === 'string' ? '' : node.type;
          const label = type ? `${name} · ${type}` : name;
          ui.node.append(new Option(label || '未命名节点', name || ''));
        }
        ui.node.value = selected || previous;
        if (ui.node.value !== selected && selected) ui.node.value = selected;
      }
    }
    ui.nodeHint.textContent = state.primary_group ? `节点来自：${state.primary_group}` : '选择节点后保存，即可作为当前代理线路。';
    ui.proxy.textContent = state.proxy_url || '等待配置';
    const ports = state.ports || {};
    const portParts = [];
    if (ports.mixed) portParts.push(`混合端口 ${ports.mixed}`);
    if (ports.panel) portParts.push(`面板 ${ports.panel}`);
    ui.ports.textContent = portParts.length ? portParts.join(' · ') : '端口：—';
    ui.version.textContent = state.version ? `版本：${state.version}` : '版本：—';
    ui.footerVersion.textContent = state.version ? `· ${state.version}` : '';
    const protection = state.protection || {};
    ui.protectionCard.className = `protection-card ${protection.supported ? 'is-supported' : 'is-unsupported'}`;
    ui.protectionBadge.textContent = protection.supported ? '隔离能力可用' : '不支持，启动受阻';
    ui.protectionDetail.textContent = protection.detail || (protection.supported ? '本机报告隔离能力可用。实例启动后会显示隔离状态。' : '本机未报告可用隔离能力，受保护应用启动已阻断。');
    ui.protectionBackend.textContent = protection.backend ? `隔离后端：${protection.backend}` : '';
    ui.protectionLimitations.replaceChildren();
    const limitations = Array.isArray(protection.limitations) ? protection.limitations : [];
    ui.protectionLimitations.hidden = limitations.length === 0;
    for (const limitation of limitations) ui.protectionLimitations.append(textElement('li', '', limitation));
    const isWindows = /windows|win32|win64/i.test(String(state.platform || ''));
    ui.runtimeSettings.hidden = !isWindows;
    if (isWindows && document.activeElement !== ui.runtimePath) ui.runtimePath.value = state.runtime_path || '';
    ui.availablePaths.replaceChildren();
    for (const app of (Array.isArray(state.available_apps) ? state.available_apps : [])) {
      const option = document.createElement('option');
      option.value = app.path || '';
      option.label = app.label || '';
      ui.availablePaths.append(option);
    }
    renderAvailableApps();
    renderApps();
    renderControls();
  }

  async function readState({ quiet = false, refreshApps = false } = {}) {
    try {
      const response = await fetch(refreshApps ? '/api/state?refresh_apps=1' : '/api/state', { cache: 'no-store' });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || '无法读取本机服务状态。');
      render(result);
      if (result.error) showError(result.error, 'state');
      else if (!quiet || ui.error.dataset.source === 'state') showError('');
    } catch (error) {
      if (!quiet || !state) showError(error.message || '无法连接本机服务。请确认 RuleProxy 服务正在运行。');
      if (!state) {
        ui.statusTitle.textContent = '无法连接本机服务';
        ui.statusDetail.textContent = '请确认 RuleProxy 服务正在运行';
      }
    }
  }

  async function mutate(url, { method = 'POST', body = {} } = {}, options = {}) {
    if (busy) return null;
    setBusy(true);
    showError('');
    try {
      if (!state || !state.token) throw new Error('本机安全令牌尚未就绪，请稍后重试。');
      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json', 'X-RuleProxy-Token': state.token },
        body: method === 'DELETE' ? undefined : JSON.stringify(body),
      });
      const result = response.status === 204 ? {} : await response.json();
      if (!response.ok) throw new Error(result.error || '操作未完成，请检查输入后重试。');
      if (options.launch) {
        const detail = result.detail ? ` ${result.detail}` : '';
        showError('');
        setNotice(`${options.launch}已启动。${detail}`);
        await readState({ quiet: true });
      } else if (options.stopped) {
        showError('');
        setNotice(`${options.stopped}的隔离实例已关闭。`);
        await readState({ quiet: true });
      } else if (options.stoppingCore) {
        showError('');
        if (result && result.token) render(result);
        else await readState({ quiet: true });
        setNotice('受保护应用实例已关闭，本机核心已停止。');
      } else if (options.launchAll) {
        showLaunchResults(result.results || []);
        await readState({ quiet: true });
      } else {
        if (result && result.token) render(result);
        else await readState({ quiet: true });
      }
      return result;
    } catch (error) {
      showError(error.message || '操作未完成，请重试。');
      return null;
    } finally {
      setBusy(false);
    }
  }

  function setNotice(message) {
    delete ui.error.dataset.source;
    ui.error.className = 'notice success-notice';
    ui.error.textContent = message;
    ui.error.hidden = false;
    window.setTimeout(() => {
      if (ui.error.classList.contains('success-notice')) ui.error.hidden = true;
      ui.error.className = 'notice error-notice';
    }, 5000);
  }

  function showLaunchResults(results) {
    const alreadyRunning = results.filter((item) => item.error && /已经在隔离中运行/.test(item.error));
    const failures = results.filter((item) => item.error && !/已经在隔离中运行/.test(item.error));
    if (!failures.length) {
      setNotice(`已处理 ${results.length} 个应用${alreadyRunning.length ? `，其中 ${alreadyRunning.length} 个已在隔离中运行` : ''}。`);
      return;
    }
    const summary = failures.map((item) => `${item.label || '应用'}：${item.error}`).join('；');
    showError(`部分应用未能启动：${summary}`);
  }

  function launchApp(app) {
    if (!state || !state.running || !state.protection || !state.protection.supported || !app.enabled || app.active || app.cleanup_pending) return;
    mutate(`/api/apps/${encodeURIComponent(app.id)}/launch`, {}, { launch: app.label || '应用' });
  }

  function stopApp(app) {
    if (!app.active && !app.cleanup_pending) return;
    mutate(`/api/apps/${encodeURIComponent(app.id)}/stop`, {}, { stopped: app.label || '应用' });
  }

  function removeApp(app) {
    mutate(`/api/apps/${encodeURIComponent(app.id)}`, { method: 'DELETE' });
  }

  ui.file.addEventListener('change', async () => {
    const file = ui.file.files && ui.file.files[0];
    if (!file) return;
    ui.fileName.textContent = file.name;
    try {
      ui.yaml.value = await file.text();
      showError('');
    } catch (_) {
      showError('无法读取这个配置文件，请重试。');
    }
  });

  ui.importButton.addEventListener('click', async () => {
    const yaml = ui.yaml.value.trim();
    if (!yaml) {
      showError('请选择配置文件，或先粘贴 YAML 内容。');
      ui.yaml.focus();
      return;
    }
    const result = await mutate('/api/import', { body: { yaml } });
    if (result) {
      if (ui.yaml.value.trim() === yaml) {
        ui.yaml.value = '';
        ui.file.value = '';
        ui.fileName.textContent = '支持 .yaml / .yml';
        setNotice('配置已导入。核心仍处于停止状态；需要时再手动启动。');
      } else {
        setNotice('配置已导入；导入期间修改的内容仍保留在编辑框中。');
      }
    }
  });

  function settingsBody() {
    const body = { core_path: ui.core.value.trim() };
    if (/windows|win32|win64/i.test(String(state && state.platform || ''))) body.runtime_path = ui.runtimePath.value.trim();
    return body;
  }

  ui.saveCore.addEventListener('click', () => mutate('/api/settings', { body: settingsBody() }));
  ui.saveRuntime.addEventListener('click', () => mutate('/api/settings', { body: settingsBody() }));
  ui.saveNode.addEventListener('click', () => {
    if (ui.node.value) mutate('/api/node', { body: { name: ui.node.value } });
  });
  ui.start.addEventListener('click', () => mutate('/api/start'));
  ui.stop.addEventListener('click', () => mutate('/api/stop', {}, { stoppingCore: true }));
  ui.launchAll.addEventListener('click', () => {
    if (!state || !state.running || !state.protection || !state.protection.supported) return;
    mutate('/api/launch-enabled', {}, { launchAll: true });
  });

  ui.appSearch.addEventListener('input', renderAvailableApps);
  ui.refreshApps.addEventListener('click', async () => {
    if (busy || refreshingApps) return;
    refreshingApps = true;
    renderControls();
    try {
      await readState({ refreshApps: true });
    } finally {
      refreshingApps = false;
      renderControls();
    }
  });

  ui.addApp.addEventListener('click', () => {
    const label = ui.appLabel.value.trim();
    const path = ui.appPath.value.trim();
    if (!label || !path) {
      showError('请填写应用名称和程序路径。');
      (!label ? ui.appLabel : ui.appPath).focus();
      return;
    }
    const args = ui.appArgs.value.split(/\r?\n/).map((arg) => arg.trim()).filter(Boolean);
    mutate('/api/apps', { body: { label, path, adapter: ui.appAdapter.value, args, enabled: true } }).then((result) => {
      if (!result) return;
      ui.appLabel.value = '';
      ui.appPath.value = '';
      ui.appArgs.value = '';
      ui.appLabel.focus();
    });
  });

  ui.appPath.addEventListener('change', () => {
    const match = (state && state.available_apps || []).find((app) => app.path === ui.appPath.value);
    if (!match) return;
    if (!ui.appLabel.value.trim()) ui.appLabel.value = match.label || '';
    if (Array.from(ui.appAdapter.options).some((option) => option.value === match.adapter)) ui.appAdapter.value = match.adapter;
  });

  readState();
  window.setInterval(() => {
    if (!document.hidden && !busy && !refreshingApps) readState({ quiet: true });
  }, 5000);
})();
