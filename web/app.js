(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const ui = {
    platform: $('platform-label'), statusDot: $('status-indicator'), statusTitle: $('status-title'),
    statusDetail: $('status-detail'), error: $('global-error'), configState: $('config-state'),
    file: $('yaml-file'), fileName: $('file-name'), yaml: $('yaml-input'), importButton: $('import-button'),
    core: $('core-path'), saveCore: $('save-core-button'), node: $('node-select'), saveNode: $('save-node-button'),
    captureMode: $('capture-mode'), captureModeDetail: $('capture-mode-detail'),
    nodeHint: $('node-hint'), proxy: $('proxy-address'), ports: $('port-summary'), version: $('version-label'),
    footerVersion: $('footer-version'), start: $('start-button'), stop: $('stop-button'), apps: $('apps-list'),
    launchAll: $('launch-all-button'), appLabel: $('app-label'), appPath: $('app-path'),
    appAdapter: $('app-adapter'), appArgs: $('app-args'), addApp: $('add-app-button'), availablePaths: $('available-app-paths'),
    appSearch: $('app-search'), refreshApps: $('refresh-apps-button'), availableApps: $('available-apps-list'),
    availableAppsCount: $('available-apps-count'), storeAppsNote: $('store-apps-note'),
    protectionCard: $('protection-card'), protectionBadge: $('protection-badge'), protectionDetail: $('protection-detail'),
    protectionBackend: $('protection-backend'), protectionLimitations: $('protection-limitations'),
    processPermissionNote: $('process-permission-note'),
    coreSettings: $('core-path-settings'), relatedField: $('related-paths-field'), relatedPaths: $('app-related-paths'),
    hostedNote: $('hosted-note'), filesNote: $('files-note'), configNotes: $('config-notes'), configWarnings: $('config-warnings'),
    autostartRow: $('autostart-row'), autostart: $('autostart-toggle'), autostartDetail: $('autostart-detail'), quit: $('quit-button'),
  };
  const AUTOSTART_TEXT = '登录系统后自动启动面板，不打开窗口，也不启动核心；从快捷方式或面板启动应用时再启动核心。';
  const AUTOSTART_STALE_TEXT = '已有的自动启动设置指向别的位置或端口（例如移动过文件夹）。打开开关即可改为当前面板。';
  let state = null;
  let busy = false;
  // Set once the panel was quit from this page: nothing is left to talk to.
  let stopped = false;
  let lastAppsSignature = '';
  let lastAvailableSignature = '';
  let refreshingApps = false;
  const isWindows = () => /windows|win32|win64/i.test(String(state && state.platform || ''));
  const isGlobal = () => state?.capture_mode === 'global';

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
    if (stopped) {
      document.querySelectorAll('button, input, select, textarea').forEach((control) => { control.disabled = true; });
      return;
    }
    const ready = !!state;
    const imported = ready && !!state.imported;
    const running = ready && !!state.running;
    const recoveryPending = ready && (state.global_fault === true
      || (state.apps || []).some((app) => app.cleanup_pending));
    const protectedBackend = ready && !!state.protection && !!state.protection.supported;
    ui.importButton.disabled = busy || !ready;
    ui.core.disabled = busy || !ready || running;
    ui.saveCore.disabled = busy || !ready || running;
    ui.saveNode.disabled = busy || !imported || !ui.node.value;
    ui.node.disabled = busy || !imported || !((state && state.nodes) || []).length;
    ui.start.disabled = busy || !imported || running || recoveryPending || (isGlobal() && !protectedBackend);
    ui.stop.disabled = busy || !ready || !(isGlobal() || running || recoveryPending);
    if (ui.captureMode) ui.captureMode.disabled = busy || !ready || running || recoveryPending
      || (state?.apps || []).some((app) => app.active || app.cleanup_pending || app.profile_preparing);
    ui.addApp.disabled = busy || !ready;
    ui.refreshApps.disabled = busy || refreshingApps || !ready;
    ui.refreshApps.textContent = refreshingApps ? '正在扫描…' : '重新扫描';
    ui.launchAll.disabled = busy || !running || !protectedBackend || (state.apps || []).some((app) => app.profile_preparing)
      || !(state.apps || []).some((app) => app.enabled && !app.active && !app.cleanup_pending);
    ui.autostart.disabled = busy || !ready;
    ui.quit.disabled = busy || !ready;
    ui.apps.querySelectorAll('.app-toggle input, .remove-app, .app-shortcut').forEach((control) => {
      const app = (state.apps || []).find((item) => String(item.id) === control.dataset.appId);
      control.disabled = busy || !!app?.profile_preparing;
    });
    ui.availableApps.querySelectorAll('.discovery-add').forEach((control) => { control.disabled = busy || control.dataset.added === 'true'; });
    ui.apps.querySelectorAll('.app-profile-option input').forEach((control) => {
      const app = (state.apps || []).find((item) => String(item.id) === control.dataset.appId);
      control.disabled = busy || !app || !!app.active || !!app.cleanup_pending || !!app.profile_preparing;
    });
    ui.apps.querySelectorAll('.app-action').forEach((control) => {
      const app = (state.apps || []).find((item) => String(item.id) === control.dataset.appId);
      const canLaunch = app && app.enabled && running && protectedBackend;
      control.disabled = busy || !!app?.profile_preparing || (!(app?.active || app?.cleanup_pending) && !canLaunch);
      control.title = app?.profile_preparing ? '正在检查应用资料，请稍候' : (app?.active ? '关闭此工具启动的实例' : (!running ? '请先启动核心' : (!protectedBackend ? '本机代理能力不可用' : '启动此应用')));
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
      enabled.disabled = busy || !!app.profile_preparing;
      enabled.setAttribute('aria-label', `将 ${app.label || '应用'}加入启动清单`);
      enabled.dataset.appId = String(app.id);
      enabled.dataset.appControl = `${app.id}:enabled`;
      enabled.addEventListener('change', () => {
        if (busy || app.profile_preparing) {
          enabled.checked = !!app.enabled;
          return;
        }
        const requested = enabled.checked;
        mutate(`/api/apps/${encodeURIComponent(app.id)}`, { method: 'POST', body: { enabled: requested } }).then((result) => {
          if (!result) enabled.checked = !!app.enabled;
        });
      });
      const toggleMark = textElement('span', 'toggle-mark');
      enabledLabel.append(enabled, toggleMark);

      const appInfo = textElement('div', 'app-info');
      appInfo.append(textElement('strong', 'app-name', app.label || '未命名应用'));
      const statusText = app.profile_preparing ? '检查应用资料…' : (app.cleanup_pending ? '清理待完成' : (app.active ? (isGlobal() ? '全局代理中运行' : (isWindows() ? '代理中运行' : '隔离中运行')) : (app.routed ? (isGlobal() ? '全局接管已启用' : '路径代理已启用') : (app.enabled ? '待启动' : '未启用'))));
      const statusClass = (app.profile_preparing || app.cleanup_pending) ? 'is-pending' : (app.active ? 'is-active' : (app.enabled ? 'is-enabled' : ''));
      appInfo.append(textElement('span', `app-inline-status ${statusClass}`, statusText));
      const appPath = textElement('span', 'app-path', app.path || '未设置路径');
      appPath.title = app.path || '未设置路径';
      appInfo.append(appPath);
      if (app.store_binding) appInfo.append(textElement('span', 'app-path', '自动跟随当前商店软件包版本；包含包内全部辅助程序。'));
      if (app.related_paths?.length) appInfo.append(textElement('span', 'app-path', `相关程序：${app.related_paths.join('；')}`));
      appInfo.append(appTools(app));
      const adapter = friendlyAdapter(app.adapter, app.use_original_data === true);
      const appMeta = textElement('div', 'app-meta');
      appMeta.append(textElement('span', 'app-adapter', adapter));
      const status = textElement('span', `app-status ${statusClass}`, statusText);
      appMeta.append(status);
      const launch = textElement('button', 'button button-launch app-action', app.profile_preparing ? '检查应用资料…' : (app.cleanup_pending ? '关闭守卫' : (app.active ? '关闭实例' : (isWindows() ? '启动应用 ↗' : '启动隔离实例 ↗'))));
      launch.type = 'button';
      launch.dataset.appId = String(app.id);
      launch.disabled = busy || !!app.profile_preparing || ((app.active || app.cleanup_pending) ? false : !(app.enabled && state.running && state.protection && state.protection.supported));
      launch.title = app.active ? '关闭此工具启动的实例' : '启动此应用';
      launch.addEventListener('click', () => (app.active || app.cleanup_pending) ? stopApp(app) : launchApp(app));
      const remove = textElement('button', 'icon-button remove-app', '×');
      remove.type = 'button';
      remove.setAttribute('aria-label', `移除 ${app.label || '应用'}`);
      remove.title = '移除应用';
      remove.dataset.appId = String(app.id);
      remove.disabled = busy || !!app.profile_preparing;
      remove.addEventListener('click', () => removeApp(app));
      row.append(enabledLabel, appInfo, appMeta, launch, remove);
      ui.apps.append(row);
    }
    if (activeId) {
      const restored = ui.apps.querySelector(`[data-app-control="${CSS.escape(activeId)}"]`);
      if (restored) restored.focus({ preventScroll: true });
    }
  }

  function appTools(app) {
    const tools = textElement('div', 'app-tools');
    const shortcut = textElement('button', 'button button-secondary app-shortcut', '创建快捷方式');
    shortcut.type = 'button';
    shortcut.title = '生成系统启动入口，不打开面板也能启动这个应用';
    shortcut.disabled = busy || !!app.profile_preparing;
    shortcut.dataset.appId = String(app.id);
    shortcut.dataset.appControl = `${app.id}:shortcut`;
    shortcut.addEventListener('click', () => createShortcut(app));
    tools.append(shortcut);
    if (isBrowserAdapter(app.adapter)) {
      const profileLabel = textElement('label', 'app-profile-option');
      const label = '使用原应用数据';
      profileLabel.title = '直接使用原应用资料，书签、历史和设置的修改会同步到原应用；请先关闭原应用后再使用。';
      const profile = document.createElement('input');
      profile.type = 'checkbox';
      profile.title = profileLabel.title;
      profile.checked = app.use_original_data === true;
      profile.disabled = busy || !!app.active || !!app.cleanup_pending || !!app.profile_preparing;
      profile.dataset.appId = String(app.id);
      profile.dataset.appControl = `${app.id}:profile`;
      profile.setAttribute('aria-label', `${app.label || '应用'}：${label}`);
      profile.addEventListener('change', () => {
        if (busy || app.active || app.cleanup_pending || app.profile_preparing) {
          profile.checked = app.use_original_data === true;
          return;
        }
        const useOriginalData = profile.checked;
        const hadFocus = document.activeElement === profile;
        mutate(`/api/apps/${encodeURIComponent(app.id)}/profile`, {
          body: { use_original_data: useOriginalData },
        }).then(async (result) => {
          if (!result) {
            profile.checked = app.use_original_data === true;
            const failureMessage = ui.error.textContent;
            const failureSource = ui.error.dataset.source || 'local';
            await readState({ quiet: true });
            if (failureMessage) showError(failureMessage, failureSource);
          }
          if (hadFocus && (!document.activeElement || document.activeElement === document.body || document.activeElement === profile)) {
            const current = ui.apps.querySelector(`[data-app-control="${CSS.escape(`${app.id}:profile`)}"]`);
            if (current && !current.disabled) current.focus({ preventScroll: true });
          }
        });
      });
      profileLabel.append(profile, textElement('span', '', label));
      tools.append(profileLabel);
    }
    if (isWindows() && !isGlobal() && !app.store_binding && app.use_original_data !== true) {
      tools.append(isolationOption(app));
    }
    return tools;
  }

  function isolationOption(app) {
    const optionLabel = textElement('label', 'app-profile-option');
    const label = '强隔离（实验）';
    optionLabel.title = '在 Windows AppContainer 中启动，仅放行本机代理端口。当前 Edge、Chrome、Firefox 未通过兼容测试；商店应用和共用原应用资料模式不支持。';
    const option = document.createElement('input');
    option.type = 'checkbox';
    option.title = optionLabel.title;
    option.checked = app.windows_container === true;
    option.disabled = busy || !!app.active || !!app.cleanup_pending || !!app.profile_preparing;
    option.dataset.appId = String(app.id);
    option.dataset.appControl = `${app.id}:isolation`;
    option.setAttribute('aria-label', `${app.label || '应用'}：${label}`);
    option.addEventListener('change', () => {
      if (busy || app.active || app.cleanup_pending || app.profile_preparing) {
        option.checked = app.windows_container === true;
        return;
      }
      mutate(`/api/apps/${encodeURIComponent(app.id)}/isolation`, {
        body: { windows_container: option.checked },
      }).then((result) => {
        if (!result) option.checked = app.windows_container === true;
      });
    });
    optionLabel.append(option, textElement('span', '', label));
    return optionLabel;
  }

  function createShortcut(app) {
    mutate(`/api/apps/${encodeURIComponent(app.id)}/shortcut`, { body: {} }, {
      notice: (result) => `快捷方式已创建：${((result && result.created) || []).join('；')}。`,
    });
  }

  function isBrowserAdapter(adapter) {
    return ['chrome', 'chromium', 'edge', 'brave', 'firefox'].includes(adapter);
  }

  function friendlyAdapter(adapter, useOriginalData = false) {
    if (isWindows() && (adapter === 'environment' || adapter === 'env')) return '普通应用 · 按路径透明代理';
    const profile = useOriginalData ? '原应用数据' : '独立配置';
    const browser = `浏览器 / Electron · ${profile}`;
    const names = { chrome: browser, chromium: browser, edge: browser, brave: browser, firefox: `Firefox · ${profile}`, env: '代理环境变量启动', environment: '代理环境变量启动' };
    return names[adapter] || (adapter ? String(adapter) : '应用启动');
  }

  function compatibilityHint(adapter) {
    if (isWindows()) return '按完整程序路径接管；不同 exe 的联网子进程需作为相关程序显式添加。';
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
    const scanning = !!(state && state.apps_scanning);
    const query = ui.appSearch.value.trim().toLocaleLowerCase();
    const expandedLimit = Number(ui.availableApps.dataset.limit);
    const limit = ui.availableApps.dataset.query === ui.appSearch.value && Number.isSafeInteger(expandedLimit) && expandedLimit > 0
      ? expandedLimit : (query ? 60 : 24);
    const signature = JSON.stringify({ available, scanning, limit, saved: saved.map((app) => [app.path, app.enabled, app.active]) });
    if (signature === lastAvailableSignature && ui.availableApps.dataset.query === ui.appSearch.value) return;
    lastAvailableSignature = signature;
    ui.availableApps.dataset.query = ui.appSearch.value;
    ui.availableApps.dataset.limit = String(limit);
    ui.availableApps.replaceChildren();
    const matches = available.filter((app) => `${app.label || ''} ${app.path || ''} ${friendlyAdapter(app.adapter)}`.toLocaleLowerCase().includes(query));
    const visible = matches.slice(0, limit);
    ui.availableAppsCount.textContent = available.length
      ? (query ? `找到 ${matches.length} 项` : `发现 ${available.length} 项`)
      : (scanning ? '正在读取应用清单…' : '未发现可添加的应用');
    if (!visible.length) {
      const empty = textElement('div', 'discovery-empty', query ? '没有找到匹配的应用。' : (scanning ? '正在读取应用清单…' : '系统暂未发现可添加的应用。'));
      ui.availableApps.append(empty);
      return;
    }
    for (const app of visible) {
      const row = textElement('article', 'available-app-row');
      const info = textElement('div', 'available-app-info');
      info.append(textElement('strong', 'available-app-name', app.label || '未命名应用'));
      const kind = textElement('span', 'available-app-kind', friendlyAdapter(app.adapter));
      if (app.source === 'windows-store') {
        kind.append(textElement('span', 'available-app-source', '商店应用'));
      }
      info.append(kind);
      if (app.source === 'windows-store') {
        const path = textElement('span', 'available-app-path', app.path || '未设置路径');
        path.title = app.path || '未设置路径';
        info.append(path);
      }
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
      const controls = textElement('div', 'discovery-more');
      controls.append(textElement('span', '', `已显示 ${visible.length} / ${matches.length} 项`));
      const more = textElement('button', 'button button-secondary discovery-expand', `显示更多（${Math.min(24, matches.length - visible.length)} 项）`);
      more.type = 'button';
      more.addEventListener('click', () => {
        ui.availableApps.dataset.limit = String(limit + 24);
        renderAvailableApps();
      });
      const all = textElement('button', 'button button-secondary discovery-expand', `显示全部（${matches.length} 项）`);
      all.type = 'button';
      all.addEventListener('click', () => {
        ui.availableApps.dataset.limit = String(Number.MAX_SAFE_INTEGER);
        renderAvailableApps();
      });
      controls.append(more, all);
      ui.availableApps.append(controls);
    }
  }

  async function addDiscoveredApp(app) {
    if (busy || !app || !app.path || !app.adapter) return;
    const label = String(app.label || app.path);
    const args = Array.isArray(app.args) ? app.args : [];
    await mutate('/api/apps', { body: { label, path: app.path, adapter: app.adapter, args, enabled: true,
      ...(app.store_binding ? { store_binding: app.store_binding } : {}) } });
  }

  function render(stateValue) {
    state = stateValue;
    if (!state) return;
    ui.platform.textContent = state.platform || '本机服务';
    ui.storeAppsNote.hidden = !isWindows();
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
    const warnings = Array.isArray(state.warnings) ? state.warnings : [];
    ui.configWarnings.replaceChildren(...warnings.map((warning) => textElement('li', '', warning)));
    ui.configNotes.hidden = warnings.length === 0;
    ui.hostedNote.hidden = !state.hosted;
    ui.filesNote.hidden = !state.files_dir;
    ui.filesNote.textContent = state.files_dir
      ? `隔离应用可以读写下载文件夹 ${state.files_dir}：下载的文件保存在这里，要上传的文件也请先放到这里。家目录里的其他文件对隔离应用不可见。`
      : '';
    const protection = state.protection || {};
    const supported = !!protection.supported;
    if (ui.captureMode) ui.captureMode.value = state.capture_mode || 'applications';
    if (ui.captureModeDetail) ui.captureModeDetail.textContent = isGlobal()
      ? '全局把系统代理指向本机核心，不安装 TUN、不改防火墙和 DNS；停止、核心退出或下次打开面板时恢复原系统代理。'
      : (isWindows() ? '仅接管启用的程序及其辅助路径；已识别商店软件包会自动跟随本机版本。'
                      : '从面板启动的应用进入独立隔离；其他应用继续使用原网络。');
    ui.stop.textContent = state.global_fault === true ? '重试恢复网络与清理'
      : (isGlobal() ? '停止全局代理并恢复系统代理' : '关闭受保护应用并停止');
    ui.protectionCard.className = `protection-card ${supported ? 'is-supported' : 'is-unsupported'}`;
    ui.protectionBadge.textContent = !supported ? '不可用，启动受阻'
      : (isGlobal() ? '全局系统代理可用' : (isWindows() ? '应用代理可用' : '隔离能力可用'));
    ui.protectionDetail.textContent = (protection.detail || (supported ? '本机报告隔离能力可用。实例启动后会显示隔离状态。' : '本机未报告可用隔离能力，受保护应用启动已阻断。'));
    ui.protectionBackend.textContent = protection.backend ? `运行后端：${protection.backend}` : '';
    const elevated = isWindows() && state.process_elevated === true;
    ui.processPermissionNote.hidden = !elevated;
    ui.processPermissionNote.textContent = elevated ? '当前以管理员权限运行；从面板启动的应用将继承该权限。' : '';
    ui.protectionLimitations.replaceChildren();
    const limitations = Array.isArray(protection.limitations) ? protection.limitations : [];
    ui.protectionLimitations.hidden = limitations.length === 0;
    for (const limitation of limitations) ui.protectionLimitations.append(textElement('li', '', limitation));
    const autostart = state.autostart || 'unsupported';
    ui.autostartRow.hidden = autostart === 'unsupported';
    ui.autostartRow.classList.toggle('is-stale', autostart === 'stale');
    ui.autostart.checked = autostart === 'on';
    ui.autostartDetail.textContent = autostart === 'stale' ? AUTOSTART_STALE_TEXT : AUTOSTART_TEXT;
    ui.coreSettings.hidden = isWindows();
    ui.relatedField.hidden = !isWindows();
    const ordinaryOption = ui.appAdapter.querySelector('option[value="environment"]');
    if (ordinaryOption) ordinaryOption.textContent = isWindows() ? '普通应用（按程序路径透明代理）' : '遵循代理环境变量的应用（不兼容即阻断）';
    if (isGlobal()) {
      $('connection-intro').textContent = '启动后把系统代理指向本机核心，遵循系统代理的程序都会经过规则。';
      $('protection-note').textContent = '不读取系统代理的程序仍会直连。切换模式前请先停止。';
      $('apps-intro').textContent = '全局模式下，从面板启动的应用额外继承代理环境变量；其余程序按系统代理设置联网。';
      $('compatibility-note').textContent = '全局模式不安装 TUN、不改防火墙和 DNS；恢复系统代理失败时请按提示重试，指向不可用端口期间可能暂时无法联网。Windows 强隔离仍为实验功能，需逐个应用验证兼容性。';
    } else if (isWindows()) {
      $('connection-intro').textContent = '启动核心后，启用清单中的程序路径交给 ProxiFyre 转发；也可以从下方启动独立应用实例。';
      $('protection-note').textContent = '同一路径的所有实例都会受规则影响。已有连接需重启应用；关闭单个实例不会取消路径规则，关闭对应开关或停止核心才会取消。';
      $('apps-intro').textContent = '打开开关即加入代理清单；已识别商店应用同时接管本机当前软件包内的辅助程序。包外辅助程序可填写相关程序路径。';
      $('compatibility-note').textContent = 'Windows 按程序路径转发 TCP 与可支持的 UDP，不提供 Linux 同等的隔离。UDP 53、系统 DNS、IPv6 分片及代理引擎故障后直连仍有限制。';
    } else {
      $('connection-intro').textContent = '应用从面板启动并进入独立隔离后使用代理。';
      $('protection-note').textContent = '仅面板或快捷方式启动的隔离实例受保护；其他已有实例保持原网络。';
      $('apps-intro').textContent = '已添加的应用显示待启动；启动后进入独立网络隔离。';
      $('compatibility-note').textContent = 'Linux 按应用模式继续使用独立命名空间；不支持的流量阻断。';
    }
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

  // While the app list is being scanned in the background, check back soon instead of
  // waiting for the next regular refresh.
  let scanTimer = 0;
  function followScan(scanning) {
    if (!scanning || scanTimer) return;
    scanTimer = window.setTimeout(() => {
      scanTimer = 0;
      readState({ quiet: true });
    }, 1500);
  }

  async function readState({ quiet = false, refreshApps = false } = {}) {
    if (stopped) return;
    try {
      const response = await fetch(refreshApps ? '/api/state?refresh_apps=1' : '/api/state', { cache: 'no-store' });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || '无法读取本机服务状态。');
      render(result);
      followScan(result.apps_scanning);
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
      } else if (options.quit) {
        // The panel is shutting down; there is no state left to read.
      } else if (options.notice) {
        showError('');
        if (result && result.token) render(result);
        else await readState({ quiet: true });
        setNotice(typeof options.notice === 'function' ? options.notice(result) : options.notice);
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
      if (stopped) return;  // keep the final "panel has quit" message
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
    if (!state || !state.running || !state.protection || !state.protection.supported || !app.enabled || app.active || app.cleanup_pending || app.profile_preparing) return;
    mutate(`/api/apps/${encodeURIComponent(app.id)}/launch`, {}, { launch: app.label || '应用' });
  }

  function stopApp(app) {
    if (!app.active && !app.cleanup_pending) return;
    mutate(`/api/apps/${encodeURIComponent(app.id)}/stop`, {}, { stopped: app.label || '应用' });
  }

  function removeApp(app) {
    if (app.profile_preparing) return;
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
    return body;
  }

  ui.saveCore.addEventListener('click', () => mutate('/api/settings', { body: settingsBody() }));
  ui.saveNode.addEventListener('click', () => {
    if (ui.node.value) mutate('/api/node', { body: { name: ui.node.value } });
  });
  ui.start.addEventListener('click', () => mutate('/api/start'));
  ui.captureMode?.addEventListener('change', async () => {
    const result = await mutate('/api/mode', { body: { capture_mode: ui.captureMode.value } });
    if (!result && state) render(state);
  });
  ui.stop.addEventListener('click', () => mutate('/api/stop', {}, { stoppingCore: true }));
  ui.launchAll.addEventListener('click', () => {
    if (!state || !state.running || !state.protection || !state.protection.supported) return;
    mutate('/api/launch-enabled', {}, { launchAll: true });
  });

  ui.autostart.addEventListener('change', async () => {
    const enabled = ui.autostart.checked;
    const result = await mutate('/api/autostart', { body: { enabled } }, {
      notice: enabled ? '已开启：登录后会在后台自动启动面板。' : '已关闭登录后自动启动。',
    });
    if (!result && state) render(state);  // put the switch back when the change failed
  });

  ui.quit.addEventListener('click', async () => {
    if (busy || !state) return;
    if (!window.confirm('退出面板会关闭此工具启动的受保护应用，并停止核心。确定退出吗？')) return;
    const isWindows = /windows|win32|win64/i.test(String(state.platform || ''));
    if (!await mutate('/api/quit', {}, { quit: true })) return;
    stopped = true;
    ui.statusDot.className = 'status-indicator';
    ui.statusTitle.textContent = '面板已退出';
    ui.statusDetail.textContent = '可以关闭此页面';
    ui.error.className = 'notice success-notice';
    ui.error.textContent = isWindows
      ? '面板已退出，受保护应用已关闭，核心已停止。需要时双击 Start-Windows.cmd 或应用的快捷方式即可重新打开。'
      : '面板已退出，受保护应用已关闭，核心已停止。需要时运行 sh start-linux.sh 或点应用的快捷方式即可重新打开。';
    ui.error.hidden = false;
    renderControls();
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
    const related_paths = isWindows() ? ui.relatedPaths.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) : [];
    mutate('/api/apps', { body: { label, path, adapter: ui.appAdapter.value, args, related_paths, enabled: true } }).then((result) => {
      if (!result) return;
      ui.appLabel.value = '';
      ui.appPath.value = '';
      ui.appArgs.value = '';
      ui.relatedPaths.value = '';
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
  // Refresh every 5 seconds while visible. A background tab still checks in about
  // twice a minute, which also keeps a panel started by a shortcut from exiting.
  let hiddenTicks = 0;
  window.setInterval(() => {
    if (stopped || busy || refreshingApps) return;
    if (document.hidden && ++hiddenTicks < 6) return;
    hiddenTicks = 0;
    readState({ quiet: true });
  }, 5000);
})();
