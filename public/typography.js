/* Local lettering only: an unavailable calligraphy font is never impersonated. */
(() => {
  'use strict';
  const specs = [
    { id: 'shoujin', name: '瘦金体', note: '清瘦挺拔，铁画银钩', names: ['方正瘦金书简体', '方正瘦金书', 'FZShouJinShu-S10S', 'FZShouJinShu-S10', '汉仪瘦金书简', 'HYShouJinShuJ', 'SJS'], link: 'https://www.foundertype.com/index.php/FontInfo/ductdetail/id/150.html' },
    { id: 'liu', name: '柳公权体', note: '骨力遒劲，端正清朗', names: ['方正柳公权楷书', '方正柳公权楷书简体', 'FZLiuGongQuanKaiShu-R', 'FZLiuGongQuanKaiShuS-R-GB'], link: 'https://www.foundertype.com/index.php/FontInfo/ductdetail/id/6135.html' },
    { id: 'mao', name: '毛体', note: '纵逸奔放，气势舒展', names: ['华光毛体', '华光毛泽东字体', '方正毛泽东字体', 'FZMaoZeDongTi'], link: 'https://corporate.hgfonts.com/fontInfoNew_194.html' },
    { id: 'yan', name: '颜体', note: '宽博厚重，雍容大度', names: ['方正颜体', '方正颜真卿楷书', 'FZYanZhenQingKaiShu-R', 'FZYanZhenQingKaiShuS-R-GB', '汉仪颜楷简', 'HYYanKaiJ'] },
    { id: 'ou', name: '欧体', note: '险峻秀整，法度严谨', names: ['方正欧体', '方正欧阳询楷书', 'FZOuYangXunKaiShu-R', 'FZOuYangXunKaiShuS-R-GB', '汉仪欧楷简', 'HYOuKaiJ'] },
    { id: 'zhao', name: '赵体', note: '圆润流美，温雅从容', names: ['方正赵体', '方正赵孟頫楷书', 'FZZhaoMengFuKaiShu-R', 'FZZhaoMengFuKaiShuS-R-GB', '汉仪赵楷简', 'HYZhaoKaiJ'] },
    { id: 'kai', name: '楷体', note: '端正舒展，适合长读', names: ['KaiTi', '楷体', 'STKaiti', '华文楷体'] },
    { id: 'xingkai', name: '行楷', note: '行云流水，落笔有情', names: ['STXingkai', '华文行楷', '方正行楷简体', 'FZXingKai-S04S'] },
    { id: 'lishu', name: '隶书', note: '古拙平和，蚕头燕尾', names: ['LiSu', '隶书', 'STLiti', '华文隶书', '方正隶书简体', 'FZLiShu-S01S'] }
  ];
  const defaults = { font: 'shoujin', scope: 'reading', scopeVersion: 2, sizingVersion: 1, size: 16, lineHeight: 1.5, localNames: {} };
  // Release packages load installed or user-imported fonts only.
  const evaluationFonts = {};
  const systemFont = '"Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", sans-serif';
  const fonts = new Map();
  const pending = new Map();
  const generations = new Map();
  const savedFiles = new Set();
  let preferences = { ...defaults, localNames: {} };
  let onChange = () => {};
  let active = null;
  let status = '正在检测本机字库…';
  let selectionToken = 0;
  let familyCounter = 0;
  let databasePromise;
  let initialized = false;

  const byId = id => specs.find(spec => spec.id === id);
  const escape = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  const clamp = (value, min, max, fallback) => Number.isFinite(Number(value)) ? Math.min(max, Math.max(min, Number(value))) : fallback;
  const familyName = id => `YuetiLettering-${id}-${++familyCounter}`;
  const copyPreferences = () => ({ ...preferences, localNames: { ...preferences.localNames } });
  const setStatus = value => { status = value; updatePicker(); };

  function notify() {
    try { onChange(copyPreferences()); } catch (error) { console.warn('Lettering preference could not be saved:', error.message); }
  }

  function database() {
    if (!databasePromise) {
      databasePromise = new Promise((resolve, reject) => {
        if (!window.indexedDB) return reject(new Error('此浏览器无法保存字库'));
        const request = indexedDB.open('yueti-lettering-v1', 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains('fonts')) request.result.createObjectStore('fonts', { keyPath: 'id' });
        };
        request.onsuccess = () => { request.result.onversionchange = () => request.result.close(); resolve(request.result); };
        request.onerror = () => reject(request.error || new Error('无法打开本地字库'));
        request.onblocked = () => reject(new Error('本地字库正被另一个页面占用'));
      });
    }
    return databasePromise;
  }

  async function readRecord(id) {
    const db = await database();
    return new Promise((resolve, reject) => {
      const request = db.transaction('fonts', 'readonly').objectStore('fonts').get(id);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  async function writeRecord(record) {
    const db = await database();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction('fonts', 'readwrite');
      transaction.objectStore('fonts').put(record);
      transaction.oncomplete = () => { savedFiles.add(record.id); resolve(); };
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error || new Error('字库保存中断'));
    });
  }

  async function deleteRecord(id) {
    const db = await database();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction('fonts', 'readwrite');
      transaction.objectStore('fonts').delete(id);
      transaction.oncomplete = () => { savedFiles.delete(id); resolve(); };
      transaction.onerror = () => reject(transaction.error);
    });
  }

  async function readSavedKeys() {
    try {
      const db = await database();
      await new Promise((resolve, reject) => {
        const request = db.transaction('fonts', 'readonly').objectStore('fonts').getAllKeys();
        request.onsuccess = () => { request.result.forEach(id => savedFiles.add(id)); resolve(); };
        request.onerror = () => reject(request.error);
      });
    } catch { /* Fonts still work for this visit when browser storage is unavailable. */ }
  }

  async function makeLocalFace(id, name) {
    const family = familyName(id);
    const face = new FontFace(family, `local(${JSON.stringify(name)})`);
    await face.load();
    return { id, available: true, family, face, source: 'local', localName: name, fileName: '' };
  }

  async function makeFileFace(id, bytes, fileName) {
    const family = familyName(id);
    const face = new FontFace(family, bytes);
    await face.load();
    return { id, available: true, family, face, source: 'file', localName: '', fileName };
  }

  function install(entry) {
    document.fonts.add(entry.face);
    const previous = fonts.get(entry.id);
    fonts.set(entry.id, entry);
    if (previous?.face && previous.face !== entry.face && active?.face !== previous.face) document.fonts.delete(previous.face);
    updatePicker();
    return entry;
  }

  function activate(entry) {
    const previous = active;
    active = entry;
    if (previous?.face && previous.face !== entry?.face && fonts.get(previous.id)?.face !== previous.face) document.fonts.delete(previous.face);
  }

  async function ensureFont(id) {
    if (fonts.has(id)) return fonts.get(id);
    if (pending.has(id)) return pending.get(id);
    const generation = generations.get(id) || 0;
    const promise = (async () => {
      let entry;
      const custom = preferences.localNames[id];
      if (!custom) {
        try {
          const record = await readRecord(id);
          if (record?.bytes) entry = await makeFileFace(id, record.bytes, record.fileName || '已保存字库');
        } catch { /* An unusable stored file falls back to a real local face. */ }
      }
      if (!entry) {
        if (!custom && evaluationFonts[id]) {
          try {
            const specimen = evaluationFonts[id];
            const family = familyName(id);
            const face = new FontFace(family, `url(${JSON.stringify(new URL(specimen.url, document.baseURI).href)})`);
            await face.load();
            entry = { id, available: true, family, face, source: 'evaluation', localName: '', fileName: specimen.fileName, specimenName: specimen.name };
          } catch { /* A missing specimen keeps the normal local-font and honest fallback path. */ }
        }
      }
      if (!entry) {
        const names = custom ? [custom] : byId(id).names;
        for (const name of names) {
          try { entry = await makeLocalFace(id, name); break; } catch { /* local() must load successfully. */ }
        }
      }
      if (!entry) entry = { id, available: false, family: '', fileName: '', localName: '' };
      if ((generations.get(id) || 0) === generation) {
        if (entry.available) install(entry); else { fonts.set(id, entry); updatePicker(); }
      }
      return entry;
    })();
    pending.set(id, promise);
    try { return await promise; } finally { if (pending.get(id) === promise) pending.delete(id); }
  }

  function apply() {
    const family = active?.available ? `"${active.family}", "KaiTi", "STKaiti", serif` : systemFont;
    const root = document.documentElement;
    root.style.setProperty('--display-font', family);
    root.style.setProperty('--ui-font', preferences.scope === 'all' ? family : systemFont);
    root.style.setProperty('--heading-font', preferences.scope === 'reading' ? systemFont : family);
    root.style.setProperty('--reading-font', preferences.scope === 'title' ? systemFont : family);
    root.style.setProperty('--reading-size', `${preferences.size}px`);
    root.style.setProperty('--reading-line-height', String(preferences.lineHeight));
    document.body.dataset.lettering = active?.available ? active.id : 'system';
    document.body.dataset.fontScope = preferences.scope;
    updatePicker();
  }

  function loadedStatus(entry) {
    const name = byId(entry.id).name;
    if (entry.source === 'evaluation') return `${name}已载入：${entry.specimenName} · 本机样稿评估字库`;
    return entry.source === 'file' ? `${name}已载入：${entry.fileName} · 仅保存在此浏览器`
      : `${name}已载入：${entry.localName} · 本机字库`;
  }

  async function selectCurrent() {
    const token = ++selectionToken;
    const requested = preferences.font;
    setStatus(`正在检测${byId(requested).name}字库…`);
    const [selected, fallback] = await Promise.all([ensureFont(requested), ensureFont('kai')]);
    if (token !== selectionToken || requested !== preferences.font) return;
    activate(selected.available ? selected : fallback.available ? fallback : null);
    status = selected.available ? loadedStatus(selected) : `${byId(requested).name}尚未载入，暂用${fallback.available ? '楷体' : '系统字体'}。请选择正规的字体文件。`;
    apply();
  }

  function getState() {
    const selected = fonts.get(preferences.font);
    return Object.freeze({
      requested: preferences.font,
      active: active?.available ? active.id : 'system',
      loaded: Boolean(selected?.available && active?.id === preferences.font),
      scope: preferences.scope, scopeVersion: preferences.scopeVersion, sizingVersion: preferences.sizingVersion, size: preferences.size, lineHeight: preferences.lineHeight,
      fileName: selected?.available ? selected.fileName || '' : '', status
    });
  }

  function updatePicker() {
    const dialog = document.getElementById('dialog');
    if (!dialog?.open || !dialog.classList.contains('typography-dialog')) return;
    document.querySelectorAll('[data-font-choice]').forEach(card => {
      const id = card.dataset.fontChoice;
      const entry = fonts.get(id);
      const sample = card.querySelector('.font-choice-sample');
      const detail = card.querySelector('small');
      card.classList.toggle('selected', preferences.font === id);
      card.setAttribute('aria-pressed', String(preferences.font === id));
      if (entry?.available) {
        sample.style.fontFamily = `"${entry.family}", serif`;
        detail.textContent = entry.source === 'evaluation' ? `本机预览 · ${entry.specimenName}` : entry.source === 'file' ? `已载入 · ${entry.fileName}` : `本机可用 · ${entry.localName}`;
      } else {
        sample.style.fontFamily = systemFont;
        detail.textContent = pending.has(id) ? '正在检测本机字库…' : savedFiles.has(id) ? '已保存字库 · 点击载入' : '需加载字库';
      }
    });
    const preview = document.getElementById('font-preview-text');
    if (preview) {
      preview.style.fontFamily = active?.available ? `"${active.family}", serif` : systemFont;
      preview.style.fontSize = `${preferences.size}px`;
      preview.style.lineHeight = String(preferences.lineHeight);
    }
    const statusElement = document.getElementById('font-status');
    if (statusElement) statusElement.textContent = status;
    const size = document.getElementById('font-size-value');
    const line = document.getElementById('font-line-value');
    if (size) size.textContent = `${preferences.size} px`;
    if (line) line.textContent = preferences.lineHeight.toFixed(2);
    const importName = document.getElementById('font-import-name');
    if (importName) importName.textContent = `为${byId(preferences.font).name}加载字库`;
    const link = document.getElementById('font-source');
    const spec = evaluationFonts[preferences.font] || byId(preferences.font);
    if (link) {
      link.hidden = !spec.link;
      if (spec.link) { link.href = spec.link; link.textContent = `${spec.name}官方字库说明`; }
    }
  }

  async function importFile(file) {
    if (!file) return;
    if (!/\.(ttf|otf|woff|woff2)$/i.test(file.name)) return setStatus('请选择 TTF、OTF、WOFF 或 WOFF2 字体文件，原有效字库已保留。');
    if (!file.size || file.size > 40 * 1024 * 1024) return setStatus('字体文件须大于 0 且不超过 40 MB，原有效字库已保留。');
    const id = preferences.font;
    const generation = (generations.get(id) || 0) + 1;
    generations.set(id, generation);
    ++selectionToken;
    setStatus(`正在载入${file.name}…`);
    try {
      const bytes = await file.arrayBuffer();
      const entry = await makeFileFace(id, bytes, file.name);
      if (generations.get(id) !== generation) return;
      let saved = true;
      try { await writeRecord({ id, bytes, fileName: file.name, updatedAt: Date.now() }); } catch { saved = false; }
      if (generations.get(id) !== generation) return;
      delete preferences.localNames[id];
      install(entry);
      notify();
      if (preferences.font === id) {
        ++selectionToken;
        activate(entry);
        status = saved ? loadedStatus(entry) : `${byId(id).name}已载入：${file.name}。浏览器未能保存，刷新后需重新加载。`;
        apply();
      }
    } catch {
      if (generations.get(id) === generation && preferences.font === id) {
        setStatus('未能载入该字体文件，文件可能损坏或格式不受支持。原有效字库已保留。');
      }
    }
  }

  async function bindLocal(name) {
    name = String(name || '').trim();
    if (!name || name.length > 200 || /[\u0000-\u001f]/.test(name)) return setStatus('请填写本机已安装字体的完整名称。');
    const id = preferences.font;
    const generation = (generations.get(id) || 0) + 1;
    generations.set(id, generation);
    ++selectionToken;
    setStatus(`正在检测本机字库：${name}…`);
    try {
      const entry = await makeLocalFace(id, name);
      if (generations.get(id) !== generation) return;
      try { await deleteRecord(id); } catch { /* A saved explicit local name takes precedence. */ }
      if (generations.get(id) !== generation) return;
      preferences.localNames[id] = name;
      install(entry);
      notify();
      if (preferences.font === id) {
        ++selectionToken;
        activate(entry);
        status = `${byId(id).name}已绑定：${name} · 用户指定的本机字库`;
        apply();
      }
    } catch {
      if (generations.get(id) === generation && preferences.font === id) setStatus(`未找到本机字库“${name}”，请检查完整名称。原有效字库已保留。`);
    }
  }

  function openPicker() {
    if (!initialized) init();
    const dialog = document.getElementById('dialog');
    const content = document.getElementById('dialogcontent');
    if (!dialog || !content) return;
    document.getElementById('dialogtitle').textContent = '字体与阅读';
    dialog.classList.remove('scene-dialog');
    dialog.classList.add('typography-dialog');
    content.innerHTML = `<p class="dialogcopy">默认让书法留在聊天正文和品牌题字，列表与按钮保持清晰。也可选择全界面书法。未载入的书体会明确提示。</p>
      <p id="font-status" class="font-status" role="status" aria-live="polite"></p>
      <div class="font-preview"><p id="font-preview-text">山水清音，落笔成诗。<br>与你聊一川烟雨，也聊人间日常。</p></div>
      <div class="font-controls"><label>应用范围<select id="font-scope"><option value="reading"${preferences.scope === 'reading' ? ' selected' : ''}>聊天正文与品牌（推荐）</option><option value="title"${preferences.scope === 'title' ? ' selected' : ''}>仅标题与品牌</option><option value="all"${preferences.scope === 'all' ? ' selected' : ''}>全界面书法</option></select></label>
      <label>正文字号 <output id="font-size-value">${preferences.size} px</output><input id="font-size" type="range" min="16" max="24" step="1" value="${preferences.size}"></label>
      <label>正文行距 <output id="font-line-value">${preferences.lineHeight.toFixed(2)}</output><input id="font-line-height" type="range" min="1.4" max="2.3" step="0.05" value="${preferences.lineHeight}"></label></div>
      <div class="font-grid">${specs.map(spec => `<button type="button" class="font-choice" data-font-choice="${spec.id}" aria-pressed="${preferences.font === spec.id}"><strong>${spec.name}</strong><span class="font-choice-sample">山水清音，落笔成诗</span><small>需加载字库</small><span class="font-choice-note">${spec.note}</span></button>`).join('')}</div>
      <div class="font-import"><label for="font-file" id="font-import-name">加载字体文件</label><input id="font-file" type="file" accept=".ttf,.otf,.woff,.woff2"><p>TTF / OTF / WOFF / WOFF2，最多 40 MB。文件仅存在此浏览器，不会上传或安装到电脑。请使用有权使用的正规字库。</p>
      <a id="font-source" href="#" target="_blank" rel="noopener noreferrer" hidden></a>
      <label for="font-local-name">或绑定本机已安装字体的完整名称</label><div class="font-local-row"><input id="font-local-name" type="text" maxlength="200" value="${escape(preferences.localNames[preferences.font] || '')}" placeholder="例如 KaiTi 或完整中文字体名"><button id="font-local-bind" type="button" class="secondarybtn">检测并绑定</button></div></div>
      <div class="dialogactions"><button id="font-reset" type="button" class="secondarybtn">恢复默认字号与范围</button><button id="font-done" type="button" class="sendbtn">完成</button></div>`;
    content.querySelectorAll('[data-font-choice]').forEach(card => {
      card.onclick = () => {
        preferences.font = card.dataset.fontChoice;
        document.getElementById('font-local-name').value = preferences.localNames[preferences.font] || '';
        notify();
        selectCurrent();
      };
    });
    const change = () => {
      const scope = document.getElementById('font-scope').value;
      preferences.scope = ['reading', 'title', 'all'].includes(scope) ? scope : defaults.scope;
      preferences.scopeVersion = defaults.scopeVersion;
      preferences.size = clamp(document.getElementById('font-size').value, 16, 24, defaults.size);
      preferences.lineHeight = clamp(document.getElementById('font-line-height').value, 1.4, 2.3, defaults.lineHeight);
      apply();
      notify();
    };
    document.getElementById('font-scope').onchange = change;
    document.getElementById('font-size').oninput = change;
    document.getElementById('font-line-height').oninput = change;
    document.getElementById('font-file').onchange = event => { const file = event.target.files?.[0]; event.target.value = ''; importFile(file); };
    document.getElementById('font-local-bind').onclick = () => bindLocal(document.getElementById('font-local-name').value);
    document.getElementById('font-local-name').onkeydown = event => {
      if (event.key === 'Enter' && !event.isComposing) { event.preventDefault(); bindLocal(event.currentTarget.value); }
    };
    document.getElementById('font-reset').onclick = () => {
      preferences.scope = defaults.scope; preferences.scopeVersion = defaults.scopeVersion; preferences.size = defaults.size; preferences.lineHeight = defaults.lineHeight;
      document.getElementById('font-scope').value = preferences.scope;
      document.getElementById('font-size').value = preferences.size;
      document.getElementById('font-line-height').value = preferences.lineHeight;
      apply(); notify();
    };
    document.getElementById('font-done').onclick = () => dialog.close();
    if (!dialog.open) dialog.showModal();
    updatePicker();
    // Saved files load when chosen; only small local font probes run for all cards.
    specs.forEach(spec => {
      if (!savedFiles.has(spec.id) || spec.id === preferences.font) ensureFont(spec.id).then(updatePicker).catch(() => {});
    });
  }

  function init(options = {}) {
    const supplied = options.preferences || {};
    const font = supplied.font || supplied.requested || defaults.font;
    const localNames = {};
    Object.entries(supplied.localNames || {}).forEach(([id, name]) => {
      if (byId(id) && typeof name === 'string' && name.trim() && name.length <= 200) localNames[id] = name.trim();
    });
    preferences = {
      font: byId(font) ? font : defaults.font,
      // Old versions applied calligraphy to every control automatically. Migrate
      // that default once; later explicit full-interface choices stay intact.
      scope: supplied.scope === 'title' ? 'title' : supplied.scopeVersion >= 2 && ['reading', 'all'].includes(supplied.scope) ? supplied.scope : defaults.scope,
      scopeVersion: defaults.scopeVersion,
      // Adopt the compact reading scale once; later user adjustments survive reloads.
      sizingVersion: defaults.sizingVersion,
      size: supplied.sizingVersion >= defaults.sizingVersion ? clamp(supplied.size, 16, 24, defaults.size) : defaults.size,
      lineHeight: supplied.sizingVersion >= defaults.sizingVersion ? clamp(supplied.lineHeight, 1.4, 2.3, defaults.lineHeight) : defaults.lineHeight, localNames
    };
    onChange = typeof options.onChange === 'function' ? options.onChange : () => {};
    if (!initialized) {
      document.getElementById('dialog')?.addEventListener('close', event => event.currentTarget.classList.remove('typography-dialog'));
      initialized = true;
    }
    apply();
    if (supplied.scopeVersion !== defaults.scopeVersion || supplied.sizingVersion !== defaults.sizingVersion) notify();
    readSavedKeys().then(updatePicker);
    return selectCurrent();
  }

  window.YuetiFonts = Object.freeze({ init, openPicker, getState });
})();
