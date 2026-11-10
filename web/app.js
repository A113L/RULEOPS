const $ = (id) => document.getElementById(id);
let csrfToken = '';
const uploadState = {
  base: null, target: null, seed: null,
  ranker_wordlist: null, ranker_cracked: null, ranker_rules: null,
  ranker_source_csv: null, ranker_source_rules: null, ranker_analysis_csv: null,
  concentrator_files: [],
  rulestripper_base: null, rulestripper_target: null,
  minimizer_rules: null, minimizer_probe: null,
};
const uploadInProgress = Object.fromEntries(Object.keys(uploadState).map((key) => [key, false]));
let activeTool = 'rulest';
let activeRankerWorkflow = 'rank';
let activeRankingMode = 'mab';
let activeConcentratorMode = 'extract';
// Hard caps on how much log data the tab keeps, regardless of how long a run
// lasts. Without these, a long CELF/ranker run used to append one DOM node
// per log event forever, which slowed the page down more and more until the
// tab became unresponsive -- even though the engine process itself kept
// running and finished normally. The server log file and the downloadable
// run outputs still contain the full, untruncated log.
const MAX_RENDERED_LOG_LINES = 1500;
const MAX_STORED_LOG_ENTRIES = 20000;
let lastLogId = 0;
let logGeneration = null;
let totalLogEvents = 0;
let logEntries = [];
let pollTimer = null;
let toastTimer = null;
let currentStatus = 'idle';
let lastStorageSummaryAt = 0;
let completionAudioContext = null;
let completionSoundEnabled = true;
const pendingCompletionJobIds = new Set();
let latestStatusJobId = null;
const LIBRARY_FIELD_CATEGORIES = {
  base: 'wordlists', target: 'wordlists', ranker_wordlist: 'wordlists', ranker_cracked: 'wordlists',
  seed: 'rules', ranker_rules: 'rules', ranker_source_rules: 'rules', concentrator_files: 'rules',
  rulestripper_base: 'wordlists', rulestripper_target: 'wordlists',
  minimizer_rules: 'rules', minimizer_probe: 'wordlists',
};
try { completionSoundEnabled = localStorage.getItem('ruleops-completion-sound') !== 'off'; } catch {}

const defaults = {
  max_depth: 2, target_hours: 0.5, max_chains: 0, rng_seed: '', bloom_mb: 0, device: '', output_name: 'rulest_output.txt',
  bloom_no_shard: false, allow_reject_rules: false, no_builtin_seeds: false,
  token_strip: false, token_strip_min_stem: 4, token_strip_max_prefix: 4,
  token_strip_max_suffix: 4, token_strip_min_leet_amb: 3, token_strip_workers: 0, token_strip_chunk_size: 0,
  token_strip_bloom_mb: 0,
  genetic: false, genetic_generations: 50, genetic_pop: 200, genetic_elite: 0.15,
  select_mode: 'frequency', select_budget: 0, select_budgets: '', select_cost_alpha: 0, exact_recovery: false,
  debug: false, profile: false,
};

function toast(message, isError = false) {
  const el = $('toast');
  el.textContent = message;
  el.classList.toggle('error', isError);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3200);
}
function humanSize(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let val = bytes / 1024, index = 0;
  while (val >= 1024 && index < units.length - 1) { val /= 1024; index++; }
  return `${val.toFixed(val >= 100 ? 0 : 1)} ${units[index]}`;
}

function unlockCompletionAudio() {
  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextClass) return;
  try {
    if (!completionAudioContext) completionAudioContext = new AudioContextClass();
    if (completionAudioContext.state === 'suspended') completionAudioContext.resume().catch(() => {});
  } catch { /* Audio is optional; the task itself must never depend on it. */ }
}
document.addEventListener('pointerdown', unlockCompletionAudio, { once: true, capture: true });
document.addEventListener('keydown', unlockCompletionAudio, { once: true, capture: true });

function playCompletionSound() {
  if (!completionSoundEnabled || !completionAudioContext) return;
  const context = completionAudioContext;
  const schedule = () => {
    const startAt = context.currentTime + 0.025;
    [659.25, 880, 1174.66].forEach((frequency, index) => {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      const noteStart = startAt + index * 0.16;
      oscillator.type = 'sine';
      oscillator.frequency.setValueAtTime(frequency, noteStart);
      gain.gain.setValueAtTime(0.0001, noteStart);
      gain.gain.linearRampToValueAtTime(0.11, noteStart + 0.025);
      gain.gain.exponentialRampToValueAtTime(0.0001, noteStart + 0.22);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(noteStart);
      oscillator.stop(noteStart + 0.23);
    });
  };
  if (context.state === 'suspended') context.resume().then(schedule).catch(() => {});
  else schedule();
}

function trackStartedJob(result) {
  if (!result || !result.job_id) return;
  const jobId = String(result.job_id);
  // Cover a very short job that might finish before the launch POST response
  // has returned and registered its ID in the pending set.
  if (latestStatusJobId === jobId && currentStatus === 'completed') {
    playCompletionSound();
    toast('Task completed successfully.');
    return;
  }
  pendingCompletionJobIds.add(jobId);
}
function handleTaskCompletionSound(data) {
  const jobId = data && data.job_id ? String(data.job_id) : '';
  if (jobId) latestStatusJobId = jobId;
  if (!jobId || !pendingCompletionJobIds.has(jobId)) return;
  if (data.status === 'completed') {
    pendingCompletionJobIds.delete(jobId);
    playCompletionSound();
    toast('Task completed successfully.');
  } else if (['failed', 'stopped'].includes(data.status)) {
    pendingCompletionJobIds.delete(jobId);
  }
}

function libraryPlaceholder(field) {
  if (field === 'concentrator_files') return 'Add saved rule file…';
  return LIBRARY_FIELD_CATEGORIES[field] === 'wordlists' ? 'Choose saved wordlist…' : 'Choose saved rule file…';
}
let libraryRefreshPromise = null;
async function refreshLibraryMenus(showToast = false) {
  const selectors = Array.from(document.querySelectorAll('[data-library-field]'));
  if (!selectors.length) return false;
  if (libraryRefreshPromise) return libraryRefreshPromise;
  libraryRefreshPromise = (async () => {
    try {
      // Explicit no-cache headers keep saved-file menus fresh behind local proxies.
      const response = await fetch('/api/library', { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } });
      if (response.status === 401) { window.location.replace('/'); return false; }
      const library = await response.json();
      if (!response.ok) throw new Error(library.error || 'Could not load saved inputs.');
      selectors.forEach((select) => {
        const field = select.dataset.libraryField;
        const category = LIBRARY_FIELD_CATEGORIES[field];
        const items = Array.isArray(library[category]) ? library[category] : [];
        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = items.length ? libraryPlaceholder(field) : `No saved ${category === 'wordlists' ? 'wordlists' : 'rule files'}`;
        select.replaceChildren(placeholder);
        items.forEach((item) => {
          const option = document.createElement('option');
          option.value = item.id;
          option.textContent = `${item.label || item.name} · ${humanSize(Number(item.size))}`;
          select.append(option);
        });
        // Keep an empty menu openable so it can display its empty-state text.
        select.disabled = currentStatus === 'running' || currentStatus === 'stopping';
      });
      if (showToast) {
        const count = (library.rules || []).length;
        toast(`Saved input library refreshed · ${count} rule file(s).`);
      }
      return true;
    } catch (error) {
      selectors.forEach((select) => {
        const option = document.createElement('option'); option.value = ''; option.textContent = 'Saved inputs unavailable';
        select.replaceChildren(option); select.disabled = currentStatus === 'running' || currentStatus === 'stopping';
      });
      console.warn('Could not refresh saved input library:', error);
      if (showToast) toast(`Could not refresh saved inputs: ${error.message}`, true);
      return false;
    } finally {
      libraryRefreshPromise = null;
    }
  })();
  return libraryRefreshPromise;
}
async function selectLibraryAsset(field, assetId, select) {
  if (!assetId) return;
  try {
    const result = await apiPost('/api/library/select', { field, asset_id: assetId });
    const meta = { name: result.name, size: result.size, library: true, asset_id: result.asset_id, category: result.category };
    if (field === 'concentrator_files') {
      if (!result.already_selected) uploadState[field] = [...(uploadState[field] || []), meta];
      renderConcentratorFileState();
    } else {
      uploadState[field] = meta;
      if (field === 'seed') $('seed-state').textContent = `✓ ${result.name} · ${humanSize(result.size)} · saved`;
      else setUploadCard(field, meta);
    }
    toast(`Loaded saved ${result.category === 'wordlists' ? 'wordlist' : 'rules'}: ${result.name}`);
    await pollStatus();
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (select) select.value = '';
    if (select) select.blur();
  }
}
function configureLibrarySelectors() {
  document.querySelectorAll('[data-library-field]').forEach((select) => {
    select.addEventListener('change', () => selectLibraryAsset(select.dataset.libraryField, select.value, select));
    const wrapper = select.closest('.library-pick');
    if (wrapper && !wrapper.querySelector('.library-refresh')) {
      const refresh = document.createElement('button');
      refresh.type = 'button';
      refresh.className = 'library-refresh';
      refresh.textContent = '↻';
      refresh.title = 'Refresh saved files';
      refresh.setAttribute('aria-label', 'Refresh saved wordlists and rules');
      refresh.addEventListener('click', () => refreshLibraryMenus(true));
      wrapper.append(refresh);
    }
  });
  refreshLibraryMenus();
}
function fmtTime(seconds) {
  if (seconds == null || !Number.isFinite(seconds)) return '00:00';
  seconds = Math.floor(seconds);
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60), s = seconds % 60;
  return h ? `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}` : `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}
function toggleStage(name, enabled) {
  const options = $(`${name}-options`);
  const note = $(`${name}-note`);
  const state = $(`${name}-state`);
  const panel = $(`${name}-stage-panel`);
  if (options) options.classList.toggle('disabled', !enabled);
  if (note) note.classList.toggle('hidden', enabled);
  if (state) {
    state.textContent = enabled ? 'ENABLED' : 'DISABLED';
    state.dataset.enabled = String(enabled);
  }
  if (panel) panel.dataset.enabled = String(enabled);
}
function initDepthOverrides() {
  const grid = $('depth-grid');
  for (let depth = 2; depth <= 10; depth++) {
    const wrap = document.createElement('div');
    wrap.className = 'depth-field';
    const label = document.createElement('label');
    label.textContent = `DEPTH ${depth}`;
    label.htmlFor = `depth${depth}_chains`;
    const input = document.createElement('input');
    input.type = 'number'; input.min = '0'; input.placeholder = 'Auto'; input.id = `depth${depth}_chains`;
    input.setAttribute('aria-label', `Depth ${depth} chains override`);
    wrap.append(label, input); grid.append(wrap);
  }
}
function setDefaults() {
  Object.entries(defaults).forEach(([key, value]) => {
    const el = $(key);
    if (!el) return;
    if (el.type === 'checkbox') el.checked = value;
    else el.value = value;
  });
  for (let d = 2; d <= 10; d++) $(`depth${d}_chains`).value = '';
  toggleStage('token', false);
  toggleStage('genetic', false);
}
function collectConfig() {
  const config = {};
  Object.keys(defaults).forEach((key) => {
    const el = $(key);
    if (!el) return;
    config[key] = el.type === 'checkbox' ? el.checked : el.value;
  });
  for (let d = 2; d <= 10; d++) config[`depth${d}_chains`] = $(`depth${d}_chains`).value;
  return config;
}
function setUploadCard(field, file) {
  const stateEl = $(`${field}-state`);
  stateEl.classList.remove('error');
  stateEl.classList.add('uploaded');
  stateEl.innerHTML = '';
  const dot = document.createElement('span'); dot.className = 'file-state-dot';
  const text = document.createElement('span'); text.textContent = `${file.name} · ${humanSize(file.size)}`;
  stateEl.append(dot, text);
}
function setUploadError(field, message) {
  const el = field === 'seed' ? $('seed-state') : $(`${field}-state`);
  el.classList.add('error'); el.textContent = message;
}
function clearUploadField(field) {
  uploadState[field] = field === 'concentrator_files' ? [] : null;
  const stateEl = field === 'seed' ? $('seed-state') : $(`${field}-state`);
  stateEl.classList.remove('uploaded', 'error');
  if (field === 'seed') {
    stateEl.textContent = 'No custom seed rules uploaded';
  } else if (field === 'concentrator_files') {
    stateEl.innerHTML = '';
    const dot = document.createElement('span'); dot.className = 'file-state-dot';
    const text = document.createElement('span'); text.textContent = 'No rules files selected';
    stateEl.append(dot, text);
  } else {
    stateEl.innerHTML = '';
    const dot = document.createElement('span'); dot.className = 'file-state-dot';
    const text = document.createElement('span'); text.textContent = 'No file selected';
    stateEl.append(dot, text);
  }
  const progress = $(`${field}-progress`);
  if (progress) progress.style.width = '0%';
  const input = $(`${field}-file`);
  if (input) input.value = '';
}
function uploadFile(field, file) {
  if (!file) return;
  uploadInProgress[field] = true;
  const progress = $(`${field}-progress`);
  const stateEl = field === 'seed' ? $('seed-state') : $(`${field}-state`);
  if (field !== 'seed') {
    stateEl.classList.remove('uploaded', 'error');
    stateEl.textContent = `Uploading ${file.name}…`;
  } else stateEl.textContent = `Uploading ${file.name}…`;
  if (progress) progress.style.width = '0%';
  const xhr = new XMLHttpRequest();
  const uploadEndpoint = field.startsWith('ranker_') ? `/api/ranker/upload/${field}` : ['rulestripper_base','rulestripper_target','minimizer_rules','minimizer_probe'].includes(field) ? `/api/tools/upload/${field}` : `/api/upload/${field}`;
  xhr.open('POST', `${uploadEndpoint}?filename=${encodeURIComponent(file.name)}`);
  xhr.setRequestHeader('Content-Type', 'application/octet-stream');
  xhr.setRequestHeader('X-CSRF-Token', csrfToken);
  xhr.upload.onprogress = (event) => {
    if (event.lengthComputable && progress) progress.style.width = `${Math.round(event.loaded / event.total * 100)}%`;
  };
  xhr.onload = async () => {
    uploadInProgress[field] = false;
    let result;
    try { result = JSON.parse(xhr.responseText); } catch { result = { error: 'Invalid server response.' }; }
    if (xhr.status === 401) { window.location.replace('/'); return; }
    if (xhr.status >= 200 && xhr.status < 300 && result.ok) {
      uploadState[field] = { name: result.name, size: result.size, library: !!result.library, asset_id: result.asset_id, category: result.category };
      if (field === 'seed') {
        stateEl.classList.remove('error'); stateEl.textContent = `✓ ${result.name} · ${humanSize(result.size)}`;
      } else setUploadCard(field, file);
      if (progress) progress.style.width = '100%';
      const uploadLabels = { base: 'BASE', target: 'TARGET', seed: 'Seed rules', ranker_wordlist: 'Base wordlist', ranker_cracked: 'Cracked-password list', ranker_rules: 'Candidate rules', ranker_source_csv: 'Ranking CSV', ranker_source_rules: 'Optimization ruleset', ranker_analysis_csv: 'Analysis CSV', rulestripper_base: 'Rulestripper BASE', rulestripper_target: 'Rulestripper TARGET', minimizer_rules: 'Minimizer rules', minimizer_probe: 'Minimizer probe wordlist' };
      toast(`${uploadLabels[field] || field} uploaded successfully.`);
      if (result.library) await refreshLibraryMenus();
    } else {
      setUploadError(field, result.error || 'Upload failed.');
      if (progress) progress.style.width = '0%';
      toast(result.error || 'Upload failed.', true);
    }
  };
  xhr.onerror = () => { uploadInProgress[field] = false; setUploadError(field, 'Network error during upload.'); toast('Upload failed due to a network error.', true); };
  xhr.send(file);
}
function renderConcentratorFileState() {
  const stateEl = $('concentrator_files-state');
  const files = uploadState.concentrator_files || [];
  stateEl.innerHTML = '';
  stateEl.classList.toggle('uploaded', files.length > 0);
  stateEl.classList.remove('error');
  const dot = document.createElement('span'); dot.className = 'file-state-dot'; stateEl.append(dot);
  const text = document.createElement('span');
  text.textContent = files.length ? `${files.length} file(s) uploaded · ${humanSize(files.reduce((sum, file) => sum + (file.size || 0), 0))}` : 'No rules files selected';
  stateEl.append(text);
  if (files.length) {
    const names = document.createElement('small'); names.className = 'concentrator-upload-names';
    names.textContent = files.map((file) => file.name).join(' · ');
    stateEl.append(names);
  }
}
function uploadConcentratorFile(file) {
  return new Promise((resolve, reject) => {
    const field = 'concentrator_files';
    const progress = $('concentrator_files-progress');
    const stateEl = $('concentrator_files-state');
    stateEl.classList.remove('error');
    const prior = (uploadState[field] || []).length;
    stateEl.textContent = `Uploading ${file.name} (${prior + 1} of selected files)…`;
    progress.style.width = '0%';
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/concentrator/upload/${field}?filename=${encodeURIComponent(file.name)}`);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('X-CSRF-Token', csrfToken);
    xhr.upload.onprogress = (event) => { if (event.lengthComputable) progress.style.width = `${Math.round(event.loaded / event.total * 100)}%`; };
    xhr.onload = async () => {
      let result;
      try { result = JSON.parse(xhr.responseText); } catch { result = { error: 'Invalid server response.' }; }
      if (xhr.status === 401) { window.location.replace('/'); reject(new Error('Authentication required.')); return; }
      if (xhr.status >= 200 && xhr.status < 300 && result.ok) {
        uploadState[field] = [...(uploadState[field] || []), { name: result.name, size: result.size, library: !!result.library, asset_id: result.asset_id, category: result.category }];
        progress.style.width = '100%';
        renderConcentratorFileState();
        if (result.library) await refreshLibraryMenus();
        resolve(result);
      } else {
        stateEl.classList.add('error'); stateEl.textContent = result.error || 'Upload failed.'; progress.style.width = '0%';
        reject(new Error(result.error || 'Upload failed.'));
      }
    };
    xhr.onerror = () => { stateEl.classList.add('error'); stateEl.textContent = `Network error uploading ${file.name}.`; reject(new Error('Network error during upload.')); };
    xhr.send(file);
  });
}
async function uploadConcentratorFiles(files) {
  if (!files.length) return;
  uploadInProgress.concentrator_files = true;
  const input = $('concentrator_files-file');
  try {
    if ((uploadState.concentrator_files || []).length + files.length > 32) throw new Error('Select no more than 32 Concentrator files.');
    for (const file of files) await uploadConcentratorFile(file);
    toast(`${files.length} Concentrator input file(s) uploaded.`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    uploadInProgress.concentrator_files = false;
    if (input) input.value = '';
    renderConcentratorFileState();
  }
}
function configureFileInputs() {
  Object.keys(uploadState).forEach((field) => {
    if (field === 'concentrator_files') {
      const input = $('concentrator_files-file');
      if (input) input.addEventListener('change', (event) => uploadConcentratorFiles(Array.from(event.target.files || [])));
      const drop = document.querySelector('[data-upload="concentrator_files"] .drop-zone');
      if (drop) {
        ['dragenter','dragover'].forEach(type => drop.addEventListener(type, (event) => { event.preventDefault(); drop.classList.add('dragover'); }));
        ['dragleave','drop'].forEach(type => drop.addEventListener(type, (event) => { event.preventDefault(); drop.classList.remove('dragover'); }));
        drop.addEventListener('drop', (event) => { const files = Array.from(event.dataTransfer.files || []); if (files.length) uploadConcentratorFiles(files); });
      }
      return;
    }
    const input = $(`${field}-file`);
    if (!input) return;
    input.addEventListener('change', (e) => uploadFile(field, e.target.files[0]));
    const drop = document.querySelector(`[data-upload="${field}"] .drop-zone`);
    if (drop) {
      ['dragenter','dragover'].forEach(type => drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.add('dragover'); }));
      ['dragleave','drop'].forEach(type => drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.remove('dragover'); }));
      drop.addEventListener('drop', (e) => { const file = e.dataTransfer.files[0]; if (file) uploadFile(field, file); });
    }
  });
}
function addLog(entry) {
  logEntries.push(entry.text);
  if (logEntries.length > MAX_STORED_LOG_ENTRIES) {
    logEntries.splice(0, logEntries.length - MAX_STORED_LOG_ENTRIES);
  }
  totalLogEvents++;
  const body = $('log-output');
  const nearBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 70;
  const placeholder = body.querySelector('.terminal-placeholder');
  if (placeholder) placeholder.remove();
  const row = document.createElement('div');
  row.className = 'log-line';
  const lower = entry.text.toLowerCase();
  if (lower.includes('[error]') || lower.includes('error:') || lower.includes('traceback')) row.classList.add('error');
  else if (lower.includes('[warn]') || lower.includes('warning')) row.classList.add('warn');
  else if (lower.includes('done') || lower.includes('finished') || lower.includes('[out]')) row.classList.add('success');
  else if (/\[(?:s[0-3]|seed|celf)\]|stage [0-3s]/i.test(entry.text)) row.classList.add('info');
  const time = new Date(entry.time * 1000).toLocaleTimeString([], { hour12: false });
  const stamp = document.createElement('span'); stamp.className = 'log-time'; stamp.textContent = time;
  const text = document.createElement('span'); text.className = 'log-message'; text.textContent = entry.text;
  row.append(stamp, text); body.append(row);
  // Keep the live terminal's DOM size bounded. A run that emits tens of
  // thousands of events (e.g. a multi-hour CELF selection) must not keep
  // growing the number of rendered elements forever -- that growth is what
  // eventually froze the tab. Trimming the oldest rows is cheap and keeps
  // the visible scrollback generous.
  while (body.children.length > MAX_RENDERED_LOG_LINES) {
    body.removeChild(body.firstChild);
  }
  if (nearBottom) body.scrollTop = body.scrollHeight;
  $('log-line-count').textContent = `${totalLogEvents.toLocaleString()} EVENTS`;
}

function renderOutputs(outputs = []) {
  $('metric-outputs').textContent = outputs.length;
  $('output-count').textContent = outputs.length;
  $('ranker-output-count').textContent = outputs.length;
  $('concentrator-output-count').textContent = outputs.length;
  if ($('rulestripper-output-count')) $('rulestripper-output-count').textContent = outputs.length;
  if ($('minimizer-output-count')) $('minimizer-output-count').textContent = outputs.length;
  ['output-list', 'ranker-output-list', 'concentrator-output-list', 'rulestripper-output-list', 'minimizer-output-list'].forEach((rootId) => {
    const root = $(rootId); if (!root) return; root.innerHTML = '';
    if (!outputs.length) {
      const empty = document.createElement('div'); empty.className = 'empty-output';
      empty.innerHTML = '<span>▤</span><b>No outputs yet</b><small>Generated files will appear here.</small>';
      root.append(empty); return;
    }
    outputs.forEach((file) => {
      const row = document.createElement('div'); row.className = 'output-item';
      const icon = document.createElement('span'); icon.className = 'output-file-icon';
      icon.textContent = file.name.toLowerCase().endsWith('.csv') ? 'CSV' : file.name.toLowerCase().endsWith('.log') ? 'LOG' : 'RULE';
      const meta = document.createElement('div'); meta.className = 'output-meta';
      const name = document.createElement('b'); name.textContent = file.name;
      const size = document.createElement('small'); size.textContent = humanSize(file.size);
      const link = document.createElement('a'); link.className = 'download-output'; link.href = `/api/download/${encodeURIComponent(file.name)}`; link.textContent = '↓'; link.title = 'Download output';
      meta.append(name, size); row.append(icon, meta, link); root.append(row);
    });
  });
}
function updateLocalEngineBadge(data) {
  const card = $('local-engine-card');
  const label = $('local-engine-status');
  if (!card || !label) return;
  const badge = data.engine_badge || (() => {
    if (data.status === 'stopping') return { label: 'STOPPING', state: 'stopping' };
    if (data.status === 'running' && data.paused) return { label: 'PAUSED', state: 'paused' };
    if (data.status === 'running') return { label: 'RUNNING', state: 'running' };
    if (data.status === 'completed') return { label: 'COMPLETE', state: 'complete' };
    if (data.status === 'stopped') return { label: 'STOPPED', state: 'stopped' };
    if (data.status === 'failed') return { label: 'ERROR', state: 'error' };
    if (data.status === 'offline') return { label: 'OFFLINE', state: 'offline' };
    return { label: 'READY', state: 'ready' };
  })();
  card.dataset.engineState = badge.state;
  label.textContent = badge.label;
  const toolNames = { rulest: 'RULEST', ranker: 'RULE RANKER', concentrator: 'CONCENTRATOR', rulestripper: 'RULESTRIPPER', minimizer: 'RULE MINIMIZER' };
  const activeTool = toolNames[data.tool] || 'engine';
  card.setAttribute('aria-label', `Local engine status: ${badge.label.toLowerCase()}${badge.state === 'running' || badge.state === 'paused' || badge.state === 'stopping' ? ` · ${activeTool}` : ''}`);
  card.title = badge.state === 'running' ? `${activeTool} is processing.` : badge.state === 'paused' ? `${activeTool} is paused.` : badge.state === 'stopping' ? `${activeTool} is stopping.` : `Local engine ${badge.label.toLowerCase()}.`;
}
function formatStorageBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = bytes;
  let unit = 'B';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024 || candidate === 'TB') break;
  }
  return `${amount.toFixed(amount >= 100 ? 0 : 1)} ${unit}`;
}
async function loadRunStorageSummary() {
  lastStorageSummaryAt = Date.now();
  const button = $('delete-run-directories');
  const feedback = $('storage-feedback');
  try {
    const response = await fetch('/api/run-storage/summary', { cache: 'no-store' });
    if (response.status === 401) { window.location.replace('/'); return; }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load run storage summary.');
    $('storage-run-count').textContent = Number(data.run_directories || 0).toLocaleString();
    $('storage-file-count').textContent = Number(data.files || 0).toLocaleString();
    $('storage-bytes').textContent = formatStorageBytes(data.bytes);
    const active = !!data.active;
    $('storage-engine-state').textContent = active ? (currentStatus === 'stopping' ? 'STOPPING' : 'RUNNING') : 'READY';
    $('storage-engine-note').textContent = active ? 'Cleanup is locked while a job is active' : 'No active run detected';
    $('storage-cleanup-summary').textContent = `${Number(data.run_directories || 0).toLocaleString()} run folder(s) · ${Number(data.files || 0).toLocaleString()} file(s) · ${formatStorageBytes(data.bytes)}`;
    if (button) button.disabled = active || Number(data.run_directories || 0) === 0;
    if (feedback && !feedback.textContent) feedback.textContent = data.uploads_preserved ? 'Temporary uploads and the reusable runs/library/ wordlist/rules folders are preserved.' : '';
  } catch (error) {
    if (feedback) feedback.textContent = `Storage summary unavailable: ${error.message}`;
    if (button) button.disabled = true;
  }
}
async function deleteAllRunDirectories() {
  const button = $('delete-run-directories');
  const summary = $('storage-cleanup-summary');
  const feedback = $('storage-feedback');
  if (!button || button.disabled) return;
  const count = Number(($('storage-run-count').textContent || '0').replace(/,/g, '')) || 0;
  if (!count) { toast('There are no run folders to delete.'); return; }
  const confirmation = `Permanently delete all ${count} run folder(s)? This removes generated outputs, logs and partial results for RULEST, Rule Ranker and Concentrator. The runs/uploads folder and auth.json will be preserved. This cannot be undone.`;
  if (!window.confirm(confirmation)) return;
  button.disabled = true;
  button.textContent = 'Deleting run folders…';
  if (feedback) feedback.textContent = 'Removing saved run directories…';
  try {
    const result = await apiPost('/api/run-storage/clear', {});
    if (!result.ok) throw new Error((result.failures || []).join('; ') || 'Some run folders could not be deleted.');
    if (feedback) feedback.textContent = `Cleanup complete. Deleted ${Number(result.deleted_directories || 0).toLocaleString()} run folder(s). Uploaded inputs, authentication and application files were preserved.`;
    toast(`Deleted ${result.deleted_directories || 0} run folder(s).`);
    await pollStatus();
    await loadRunStorageSummary();
  } catch (error) {
    if (feedback) feedback.textContent = `Cleanup failed: ${error.message}`;
    toast(`Could not delete run folders: ${error.message}`, true);
    await loadRunStorageSummary();
  } finally {
    button.textContent = '⌫ Delete all run folders';
    if (button && !button.disabled) button.disabled = false;
  }
}

function renderStatus(data) {
  currentStatus = data.status;
  const running = data.status === 'running' || data.status === 'stopping';
  const paused = !!data.paused;
  updateLocalEngineBadge(data);
  let statusText = data.status.charAt(0).toUpperCase() + data.status.slice(1);
  if (paused) statusText = 'Paused';
  if (data.status === 'idle') statusText = 'Idle';
  $('metric-status').textContent = statusText;
  $('status-note').textContent = paused ? 'Paused at safe checkpoint' : data.pause_requested ? 'Pause requested · checkpoint pending' : running ? 'Engine process is active' : data.status === 'completed' ? 'Run finished successfully' : data.status === 'stopped' ? 'Run stopped · partial results preserved' : data.status === 'failed' ? 'Check engine output below' : 'Ready to configure';
  $('metric-stage').textContent = data.stage || '—';
  $('current-stage').textContent = data.stage || 'Waiting for a run';
  $('current-stage-detail').textContent = data.stage_detail || (running ? 'Waiting for the next engine activity update…' : 'Start a run to see the active processing phase.');
  $('current-stage-detail').title = data.stage_detail || '';
  $('metric-elapsed').textContent = fmtTime(data.elapsed);
  $('monitor-runtime').textContent = fmtTime(data.elapsed);
  $('monitor-pid').textContent = data.pid || '—';
  $('live-pill').classList.toggle('running', running && !paused);
  $('live-pill').classList.toggle('paused', paused);
  $('live-pill').innerHTML = `<span></span> ${paused ? 'PAUSED' : data.pause_requested ? 'PAUSE PENDING' : running ? (data.status === 'stopping' ? 'STOPPING' : 'RUNNING') : data.status === 'completed' ? 'COMPLETE' : data.status === 'stopped' ? 'STOPPED' : data.status === 'failed' ? 'FAILED' : 'STANDBY'}`;
  const pct = data.progress;
  const completed = Number.isFinite(data.progress_completed) ? data.progress_completed : null;
  const total = Number.isFinite(data.progress_total) ? data.progress_total : null;
  const formatCount = (value) => Number(value).toLocaleString();
  const countLabel = completed != null && total != null
    ? ` · ${formatCount(completed)}/${formatCount(total)}` : '';
  $('progress-label').textContent = pct == null ? (running ? 'LIVE' : '—') : `${pct}%${countLabel}`;
  $('progress-label').title = [
    completed != null && total != null ? `${formatCount(completed)} of ${formatCount(total)} completed` : '',
    data.progress_rate || '',
    Number.isFinite(data.progress_rules) ? `${Number(data.progress_rules).toLocaleString()} rules` : '',
  ].filter(Boolean).join(' · ');
  $('phase-progress').style.width = pct == null ? '0%' : `${pct}%`;
  $('phase-progress').classList.toggle('indeterminate', running && pct == null);
  $('start-run').disabled = running;
  document.querySelectorAll('[data-library-field]').forEach((select) => { select.disabled = running; });
  $('pause-run').disabled = !running || paused || !!data.pause_requested || data.status === 'stopping';
  $('resume-run').disabled = !running || (!paused && !data.pause_requested) || data.status === 'stopping';
  $('stop-run').disabled = !running || data.status === 'stopping' || data.tool !== 'rulest';
  const rankerRunning = running && data.tool === 'ranker';
  $('ranker-current-stage').textContent = data.stage || 'Waiting for a Ranker job';
  $('ranker-stage-detail').textContent = data.stage_detail || 'Choose a workflow and configure the required inputs.';
  $('ranker-runtime').textContent = fmtTime(data.elapsed);
  $('ranker-pid').textContent = data.pid || '—';
  $('ranker-live-pill').classList.toggle('running', rankerRunning);
  $('ranker-live-pill').classList.toggle('paused', false);
  $('ranker-live-pill').innerHTML = `<span></span> ${rankerRunning ? (data.status === 'stopping' ? 'CANCELLING' : 'RUNNING') : data.status === 'completed' && data.tool === 'ranker' ? 'COMPLETE' : data.status === 'stopped' && data.tool === 'ranker' ? 'CANCELLED' : data.status === 'failed' && data.tool === 'ranker' ? 'FAILED' : 'STANDBY'}`;
  $('ranker-cancel').disabled = !rankerRunning || data.status === 'stopping';
  $('ranker-start-run').disabled = running;
  const concentratorRunning = running && data.tool === 'concentrator';
  $('concentrator-current-stage').textContent = data.tool === 'concentrator' ? (data.stage || 'Waiting for Concentrator') : 'Waiting for a Concentrator job';
  $('concentrator-stage-detail').textContent = data.tool === 'concentrator' ? (data.stage_detail || 'Concentrator output will appear here.') : 'Choose one of the four workflows and configure the required inputs.';
  $('concentrator-runtime').textContent = fmtTime(data.elapsed);
  $('concentrator-pid').textContent = data.tool === 'concentrator' && data.pid ? data.pid : '—';
  $('concentrator-live-pill').classList.toggle('running', concentratorRunning);
  $('concentrator-live-pill').innerHTML = `<span></span> ${concentratorRunning ? (data.status === 'stopping' ? 'CANCELLING' : 'RUNNING') : data.status === 'completed' && data.tool === 'concentrator' ? 'COMPLETE' : data.status === 'stopped' && data.tool === 'concentrator' ? 'CANCELLED' : data.status === 'failed' && data.tool === 'concentrator' ? 'FAILED' : 'STANDBY'}`;
  $('concentrator-cancel').disabled = !concentratorRunning || data.status === 'stopping';
  $('start-concentrator-run').disabled = running;
  const utilityTools = {
    rulestripper: { label: 'Rulestripper', start: 'rulestripper-start', cancel: 'rulestripper-cancel', stage: 'rulestripper-current-stage', detail: 'rulestripper-stage-detail', runtime: 'rulestripper-runtime', pid: 'rulestripper-pid', pill: 'rulestripper-live-pill', waiting: 'Waiting for Rulestripper' },
    minimizer: { label: 'Rule Minimizer', start: 'minimizer-start', cancel: 'minimizer-cancel', stage: 'minimizer-current-stage', detail: 'minimizer-stage-detail', runtime: 'minimizer-runtime', pid: 'minimizer-pid', pill: 'minimizer-live-pill', waiting: 'Waiting for Rule Minimizer' },
  };
  Object.entries(utilityTools).forEach(([tool, ids]) => {
    const active = data.tool === tool;
    const toolRunning = running && active;
    $(ids.stage).textContent = active ? (data.stage || ids.waiting) : ids.waiting;
    $(ids.detail).textContent = active ? (data.stage_detail || `${ids.label} output will appear here.`) : `Configure inputs and start ${ids.label}.`;
    $(ids.runtime).textContent = active ? fmtTime(data.elapsed) : '00:00';
    $(ids.pid).textContent = active && data.pid ? data.pid : '—';
    $(ids.pill).classList.toggle('running', toolRunning);
    $(ids.pill).innerHTML = `<i></i> ${toolRunning ? (data.status === 'stopping' ? 'CANCELLING' : 'RUNNING') : active && data.status === 'completed' ? 'COMPLETE' : active && data.status === 'stopped' ? 'CANCELLED' : active && data.status === 'failed' ? 'FAILED' : 'STANDBY'}`;
    $(ids.start).disabled = running;
    $(ids.cancel).disabled = !toolRunning || data.status === 'stopping';
  });
  if (data.tool === 'ranker') {
    $('terminal-tool-label').textContent = 'rule-ranker / stdout';
  } else if (data.tool === 'concentrator') {
    $('terminal-tool-label').textContent = 'concentrator-v3.5 / stdout';
  } else if (data.tool === 'rulestripper') {
    $('terminal-tool-label').textContent = 'rulestripper / stdout';
  } else if (data.tool === 'minimizer') {
    $('terminal-tool-label').textContent = 'rule-minimizer / stdout';
  } else {
    $('terminal-tool-label').textContent = 'rulest-engine / stdout';
  }
  renderOutputs(data.outputs || []);
  const storageView = $('system-view');
  if (storageView && !storageView.hidden) {
    if (Date.now() - lastStorageSummaryAt > 5000) loadRunStorageSummary();
    const storageState = $('storage-engine-state');
    const storageNote = $('storage-engine-note');
    const deleteButton = $('delete-run-directories');
    if (storageState) storageState.textContent = running ? (data.status === 'stopping' ? 'STOPPING' : paused ? 'PAUSED' : 'RUNNING') : 'READY';
    if (storageNote) storageNote.textContent = running ? 'Cleanup is locked while a job is active' : 'No active run detected';
    if (deleteButton && running) deleteButton.disabled = true;
  }
}
function resetLogView(title = 'Log history cleared', subtitle = 'New engine events will appear here.') {
  logEntries = [];
  totalLogEvents = 0;
  $('log-output').innerHTML = `<div class="terminal-placeholder"><span>⌁</span><b>${title}</b><small>${subtitle}</small></div>`;
  $('log-line-count').textContent = '0 EVENTS';
}
async function pollStatus() {
  try {
    const generationParam = logGeneration === null ? -1 : logGeneration;
    const response = await fetch(`/api/status?since=${lastLogId}&generation=${generationParam}`, { cache: 'no-store' });
    if (response.status === 401) { window.location.replace('/'); return; }
    const data = await response.json();
    handleTaskCompletionSound(data);
    if (typeof data.log_generation === 'number') {
      if (logGeneration !== null && data.log_generation < logGeneration) return; // Ignore stale in-flight polls.
      if (logGeneration === null) {
        logGeneration = data.log_generation;
      } else if (data.log_generation !== logGeneration) {
        logGeneration = data.log_generation;
        lastLogId = 0;
        resetLogView('Log history reset', 'Showing events from the current log session.');
      }
    }
    (data.logs || []).forEach((entry) => { addLog(entry); lastLogId = Math.max(lastLogId, entry.id); });
    if (data.log_seq > lastLogId) lastLogId = data.log_seq;
    if (data.uploads) {
      Object.keys(uploadState).forEach((field) => {
        if (field === 'concentrator_files') {
          const files = Array.isArray(data.uploads[field]) ? data.uploads[field] : [];
          if (!uploadInProgress[field]) {
            uploadState[field] = files;
            renderConcentratorFileState();
          }
          return;
        }
        const upload = data.uploads[field];
        if (!upload && !uploadInProgress[field] && uploadState[field]) {
          clearUploadField(field);
        } else if (upload && !uploadState[field]) {
          uploadState[field] = upload;
          if (field === 'seed') $('seed-state').textContent = `✓ ${upload.name} · ${humanSize(upload.size)}`;
          else {
            const stateEl = $(`${field}-state`); stateEl.classList.add('uploaded');
            stateEl.innerHTML = ''; const dot = document.createElement('span'); dot.className = 'file-state-dot';
            const text = document.createElement('span'); text.textContent = `${upload.name} · ${humanSize(upload.size)}`; stateEl.append(dot, text);
          }
        }
      });
    }
    renderStatus(data);
    if (data.error && data.status === 'failed') $('status-note').textContent = data.error;
  } catch (error) {
    $('status-note').textContent = 'Web interface disconnected';
    updateLocalEngineBadge({ status: 'offline' });
    const card = $('local-engine-card');
    if (card) {
      card.dataset.engineState = 'offline';
      $('local-engine-status').textContent = 'OFFLINE';
      card.setAttribute('aria-label', 'Local engine status: offline');
      card.title = 'The web interface cannot reach the local engine server.';
    }
  }
}
async function apiPost(path, payload) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(payload) });
  const data = await response.json();
  if (response.status === 401 && data.auth_required) { window.location.replace('/'); throw new Error('Your session expired. Please sign in again.'); }
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  if (data.csrf_token) csrfToken = data.csrf_token;
  return data;
}
async function startRun() {
  if (!uploadState.base || !uploadState.target) { toast('Upload both BASE and TARGET wordlists first.', true); return; }
  const config = collectConfig();
  if (!config.output_name.trim()) { toast('Enter an output filename.', true); return; }
  const rngSeedText = String(config.rng_seed ?? '').trim();
  if (rngSeedText !== '' && (!/^[0-9]{1,10}$/.test(rngSeedText) || !Number.isSafeInteger(Number(rngSeedText)) || Number(rngSeedText) > 4294967295)) {
    toast('RNG seed must be an integer from 0 to 4294967295, or left blank for a random run.', true);
    return;
  }
  const numericRanges = [
    ['target_hours', 0.000001, Infinity, 'Target runtime must be greater than zero.'],
    ['max_chains', 0, Infinity, 'Maximum chains cannot be negative.'],
    ['bloom_mb', 0, Infinity, 'Bloom filter size cannot be negative.'],
    ['genetic_generations', 1, Infinity, 'Generations must be at least 1.'],
    ['genetic_pop', 1, Infinity, 'Population size must be at least 1.'],
    ['select_budget', 0, Infinity, 'Selection budget cannot be negative.'],
    ['select_cost_alpha', 0, Infinity, 'Cost alpha cannot be negative.'],
    ['token_strip_min_stem', 1, Infinity, 'Minimum stem length must be at least 1.'],
    ['token_strip_max_prefix', 0, Infinity, 'Maximum prefix length cannot be negative.'],
    ['token_strip_max_suffix', 0, Infinity, 'Maximum suffix length cannot be negative.'],
    ['token_strip_min_leet_amb', 0, Infinity, 'Minimum leet ambiguity cannot be negative.'],
    ['token_strip_workers', 0, Infinity, 'Worker processes cannot be negative.'],
    ['token_strip_chunk_size', 0, Infinity, 'Chunk size cannot be negative.'],
    ['token_strip_bloom_mb', -1, Infinity, 'Base Bloom size must be −1 (auto), 0 (exact set), or a positive MB value.'],
  ];
  if (Number(config.max_depth) < 1 || Number(config.max_depth) > 31) { toast('Maximum depth must be between 1 and 31.', true); return; }
  if (config.genetic && Number(config.max_depth) < 2) { toast('Genetic Algorithm requires Maximum depth ≥ 2. Increase Maximum depth or switch Genetic off.', true); return; }
  if (Number(config.genetic_elite) <= 0 || Number(config.genetic_elite) >= 1 || !Number.isFinite(Number(config.genetic_elite))) { toast('Elite ratio must be between 0 and 1.', true); return; }
  for (const [key, min, max, message] of numericRanges) {
    const value = Number(config[key]);
    if (!Number.isFinite(value) || value < min || value > max) { toast(message, true); return; }
  }
  for (let d = 2; d <= 10; d++) {
    const value = config[`depth${d}_chains`];
    if (value !== '' && (!Number.isInteger(Number(value)) || Number(value) < 0)) { toast(`Depth ${d} chain override must be a non-negative integer.`, true); return; }
  }
  if (config.select_budgets.trim()) {
    const budgets = config.select_budgets.split(',').map(value => value.trim());
    if (budgets.some(value => !/^\d+$/.test(value) || Number(value) <= 0)) { toast('Budget sweep must contain positive integers separated by commas.', true); return; }
  }
  $('start-run').disabled = true;
  resetLogView('Starting a new run', 'Engine output will appear here as soon as processing begins.');
  lastLogId = 0;
  try {
    const started = await apiPost('/api/run', config);
    trackStartedJob(started);
    toast('Rulest engine launched.');
    await pollStatus();
  } catch (error) {
    toast(error.message, true);
    $('start-run').disabled = false;
  }
}
async function controlRun(action) {
  try { await apiPost('/api/control', { action }); toast(action === 'stop' ? 'Partial-save exit requested.' : `${action[0].toUpperCase()}${action.slice(1)} requested.`); await pollStatus(); }
  catch (error) { toast(error.message, true); }
}
function renderGpuDiagnostics(data) {
  const diag = data.diagnostics || {};
  const gpuDevices = data.gpu_devices || (data.devices || []).filter((item) => item.type === 'GPU');
  const state = gpuDevices.length ? 'ready' : (!diag.pyopencl_available ? 'error' : 'warning');
  const summary = $('gpu-diagnostic-summary');
  const action = $('gpu-diagnostic-action');
  const badge = $('gpu-count-badge');
  const panel = $('gpu-diagnostic');
  const icon = $('gpu-diagnostic-icon');
  panel.dataset.state = state;
  summary.textContent = data.message || diag.summary || 'GPU detection completed.';
  action.textContent = diag.recommended_action || 'Check the detailed report below.';
  icon.textContent = gpuDevices.length ? '✓' : (state === 'error' ? '!' : '⚠');
  badge.textContent = gpuDevices.length ? `${gpuDevices.length} GPU${gpuDevices.length === 1 ? '' : 'S'} READY` : 'GPU NOT READY';

  const lines = [
    `System: ${diag.system || 'Unknown'} ${diag.system_release || ''} (${diag.machine || 'unknown architecture'})`,
    `Python version: ${diag.python_version || 'Unknown'}`,
    `Python executable: ${diag.python_executable || 'Unknown'}`,
    `PyOpenCL: ${diag.pyopencl_available ? (diag.pyopencl_version || 'available') : 'NOT AVAILABLE'}`,
    `OpenCL platforms: ${(diag.opencl_platforms || []).length}`,
    `GPU devices: ${diag.gpu_count ?? gpuDevices.length}`,
    `CPU OpenCL devices: ${diag.cpu_count ?? 0}`,
  ];
  if (diag.pyopencl_error) lines.push(`PyOpenCL import error: ${diag.pyopencl_error}`);
  if (diag.opencl_error) lines.push(`OpenCL enumeration error: ${diag.opencl_error}`);
  (diag.opencl_platforms || []).forEach((item) => {
    lines.push(`Platform ${item.index}: ${item.name} | ${item.vendor} | ${item.version}`);
    (item.device_query_errors || []).forEach((error) => lines.push(`  Device query warning: ${error}`));
  });
  (diag.devices || []).forEach((device) => {
    const memory = device.global_memory_bytes ? ` | ${(device.global_memory_bytes / (1024 ** 3)).toFixed(1)} GB` : '';
    lines.push(`Device ${device.index}: ${device.name} (${device.type}) | ${device.vendor}${memory}`);
  });
  Object.entries(diag.probes || {}).forEach(([name, probe]) => {
    lines.push(`${name}: ${probe.available ? (probe.output || 'Available') : 'Not found in PATH'}`);
  });
  lines.push('', `RECOMMENDED ACTION: ${diag.recommended_action || 'Run detection again.'}`);
  $('gpu-diagnostic-report').textContent = lines.join('\n');
}

async function detectDevices(silent = false) {
  const button = $('detect-devices'); button.disabled = true; button.textContent = 'Detecting…';
  try {
    const response = await fetch('/api/devices', { cache: 'no-store' });
    if (response.status === 401) { window.location.replace('/'); return; }
    const data = await response.json();
    if (!response.ok && !data.diagnostics) throw new Error(data.message || `HTTP ${response.status}`);
    const list = $('device-options');
    list.innerHTML = '';
    if ((data.gpu_devices || []).length > 1) {
      const allOption = document.createElement('option'); allOption.value = 'all'; allOption.label = 'All detected GPUs (parallel)'; list.append(allOption);
    }
    (data.gpu_devices || []).forEach((device) => {
      const option = document.createElement('option');
      option.value = device.index;
      option.label = `${device.index}: ${device.name} (${device.vendor || device.type})`;
      list.append(option);
    });
    renderGpuDiagnostics(data);
    if (!silent) {
      const gpuCount = (data.gpu_devices || []).length;
      toast(gpuCount ? `Detected ${gpuCount} OpenCL GPU(s).` : (data.message || 'No OpenCL GPU detected.'), !gpuCount);
    }
  } catch (error) {
    const message = `Device detection failed: ${error.message}`;
    renderGpuDiagnostics({ message, diagnostics: { summary: message, recommended_action: 'Check that the Control Center server is running, then retry GPU detection.' } });
    if (!silent) toast(message, true);
  } finally { button.disabled = false; button.textContent = '⌁ Detect GPUs'; }
}
async function copyGpuReport() {
  try {
    await navigator.clipboard.writeText($('gpu-diagnostic-report').textContent);
    toast('GPU diagnostic report copied.');
  } catch (error) { toast('Clipboard access is unavailable in this browser.', true); }
}

function downloadLog() {
  const blob = new Blob([logEntries.join('\n') + (logEntries.length ? '\n' : '')], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = `rulest-${new Date().toISOString().replace(/[:.]/g,'-')}.log`; a.click(); URL.revokeObjectURL(url);
}
async function clearLogHistoryFromUi() {
  if (!window.confirm('Clear the displayed log history and permanently truncate the server-side engine.log file? This cannot be undone. Generated ruleset files will be kept.')) return;
  const button = $('clear-log');
  button.disabled = true;
  try {
    const result = await apiPost('/api/logs/clear', {});
    logGeneration = result.log_generation;
    lastLogId = result.log_seq || 0;
    resetLogView('Log history cleared', 'New engine events will continue to appear here.');
    toast('Log history cleared. New engine events will continue to stream.');
  } catch (error) {
    toast(`Could not clear logs: ${error.message}`, true);
  } finally {
    button.disabled = false;
  }
}

function setActiveTool(tool, scroll = false) {
  activeTool = ['ranker', 'concentrator', 'rulestripper', 'minimizer'].includes(tool) ? tool : 'rulest';
  $('rulest-view').hidden = activeTool !== 'rulest';
  $('ranker-view').hidden = activeTool !== 'ranker';
  $('concentrator-view').hidden = activeTool !== 'concentrator';
  $('rulestripper-view').hidden = activeTool !== 'rulestripper';
  $('minimizer-view').hidden = activeTool !== 'minimizer';
  const systemView = $('system-view');
  if (systemView) systemView.hidden = true;

  const activeToolLabels = {
    rulest: 'Run workspace',
    ranker: 'Rule Ranker',
    concentrator: 'Concentrator',
    rulestripper: 'Rulestripper',
    minimizer: 'Rule Minimizer',
  };
  const breadcrumb = document.querySelector('.breadcrumb strong');
  if (breadcrumb && !['#tuning', '#gpu-diagnostic', '#live-log'].includes(window.location.hash)) {
    breadcrumb.textContent = activeToolLabels[activeTool];
  }

  const rulestButton = $('nav-rulest');
  if (rulestButton) {
    const isActive = activeTool === 'rulest';
    rulestButton.classList.toggle('active', isActive);
    rulestButton.setAttribute('aria-current', isActive ? 'page' : 'false');
  }
  document.querySelectorAll('[data-nav-tool]').forEach((link) => {
    const active = link.dataset.navTool === activeTool;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });

  try { sessionStorage.setItem('ruleops-active-tool', activeTool); } catch {}
  if (scroll) {
    const target = activeTool === 'ranker' ? $('ranker-view')
      : activeTool === 'concentrator' ? $('concentrator-view')
      : activeTool === 'rulestripper' ? $('rulestripper-view')
        : activeTool === 'minimizer' ? $('minimizer-view') : $('workspace');
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function setActiveSystemView(view = 'storage') {
  $('rulest-view').hidden = true;
  $('ranker-view').hidden = true;
  $('concentrator-view').hidden = true;
  $('rulestripper-view').hidden = true;
  $('minimizer-view').hidden = true;
  $('system-view').hidden = false;
  const aboutElements = new Set(['about', 'about-grid']);
  document.querySelectorAll('#system-view > section, #system-view > div').forEach((el) => {
    const isAbout = aboutElements.has(el.id);
    el.hidden = view === 'about' ? !isAbout : isAbout;
  });

  const rulestButton = $('nav-rulest');
  if (rulestButton) {
    rulestButton.classList.remove('active');
    rulestButton.setAttribute('aria-current', 'false');
  }
  const breadcrumb = document.querySelector('.breadcrumb strong');
  if (breadcrumb) breadcrumb.textContent = view === 'about' ? 'About' : 'Run storage';
  if (view === 'storage') loadRunStorageSummary();
}

function setRulestMenuExpanded(expanded) {
  const button = $('nav-rulest');
  const submenu = $('rulest-subnav');
  if (!button || !submenu) return;
  button.setAttribute('aria-expanded', String(expanded));
  submenu.hidden = !expanded;
  try { sessionStorage.setItem('ruleops-rulest-menu-expanded', String(expanded)); } catch {}
}


function selectRankerWorkflow(mode) {
  if (!['rank', 'optimize', 'analyze'].includes(mode)) mode = 'rank';
  activeRankerWorkflow = mode;
  document.querySelectorAll('.ranker-workflow-tab').forEach((button) => {
    const active = button.dataset.workflow === mode;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('[data-workflow-panel]').forEach((panel) => {
    const active = panel.dataset.workflowPanel === mode;
    panel.hidden = !active;
    panel.classList.toggle('active', active);
  });
  const labels = {
    rank: [activeRankingMode === 'legacy' ? 'Run legacy ranking' : 'Run ranking', activeRankingMode === 'legacy' ? 'Legacy exhaustive ranking ready' : 'GPU ranking ready', activeRankingMode === 'legacy' ? 'Legacy mode evaluates the complete candidate set without MAB elimination.' : 'Upload a wordlist, cracked list and candidate rules to begin.'],
    optimize: ['Optimize ruleset', 'CELF optimization ready', 'Upload a wordlist, cracked list and one existing ruleset or ranking CSV.'],
    analyze: ['Analyze CSV', 'CSV analysis ready', 'Upload a ranking CSV. This workflow can run without GPU acceleration.'],
  };
  $('ranker-start-run').querySelector('span').textContent = labels[mode][0];
  $('ranker-launch-title').textContent = labels[mode][1];
  $('ranker-launch-hint').textContent = labels[mode][2];
  const modeCard = $('ranker-engine-mode-card');
  if (modeCard) modeCard.hidden = mode !== 'rank';
  updateOptimizeSourceVisibility();
}
function selectRankingMode(mode) {
  activeRankingMode = mode === 'legacy' ? 'legacy' : 'mab';
  document.querySelectorAll('.rank-mode-tab').forEach((button) => {
    const active = button.dataset.rankMode === activeRankingMode;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  const legacy = activeRankingMode === 'legacy';
  $('rank-mab-tuning').classList.toggle('mode-muted', legacy);
  $('rank-mab-tuning').querySelectorAll('input, select, button').forEach((control) => { control.disabled = legacy; });
  $('rank-mab-zero-row').classList.toggle('mode-muted', legacy);
  $('rank-mab-zero-row').querySelectorAll('input, select, button').forEach((control) => { control.disabled = legacy; });
  const modeLabel = legacy ? 'LEGACY EXHAUSTIVE' : 'ADAPTIVE MAB';
  const modeDescription = legacy
    ? 'Legacy runs the original exhaustive ranking path and evaluates the full candidate set without MAB screening or elimination.'
    : 'Adaptive MAB screens candidates over multiple passes, then evaluates survivors using the configured final trials.';
  const current = $('rank-mode-current');
  const description = $('rank-mode-description');
  if (current) current.textContent = `ACTIVE · ${modeLabel}`;
  if (description) description.textContent = `${modeDescription} ${legacy ? 'MAB-only tuning controls are disabled.' : 'MAB tuning controls are enabled below.'}`;
  document.querySelectorAll('.rank-mode-tab').forEach((button) => {
    const state = button.querySelector('.mode-state');
    if (state) state.textContent = button.dataset.rankMode === activeRankingMode ? 'ACTIVE' : 'SELECT';
  });
  try { sessionStorage.setItem('ruleops-ranker-mode', activeRankingMode); } catch {}
  $('ranker-launch-title').textContent = legacy ? 'Legacy exhaustive ranking ready' : 'GPU ranking ready';
  $('ranker-launch-hint').textContent = modeDescription;
  $('ranker-start-run').querySelector('span').textContent = legacy ? 'Run legacy ranking' : 'Run ranking';
}

function updateOptimizeSourceVisibility() {
  const csv = document.querySelector('input[name="rank_source_type"][value="csv"]').checked;
  $('opt-csv-upload').hidden = !csv;
  $('opt-rules-upload').hidden = csv;
}
function valueOf(id) { return $(id).value.trim(); }
function integerOrBlank(id, label, minimum = 0) {
  const raw = valueOf(id);
  if (raw === '') return '';
  if (!/^\d+$/.test(raw) || Number(raw) < minimum || !Number.isSafeInteger(Number(raw))) throw new Error(`${label} must be an integer ≥ ${minimum}.`);
  return Number(raw);
}
function numberValue(id, label, minimum = 0) {
  const raw = valueOf(id);
  if (raw === '' || !Number.isFinite(Number(raw)) || Number(raw) < minimum) throw new Error(`${label} must be a number ≥ ${minimum}.`);
  return Number(raw);
}
function rankerOptionsForActiveWorkflow() {
  if (activeRankerWorkflow === 'rank') {
    if (!uploadState.ranker_wordlist || !uploadState.ranker_cracked || !uploadState.ranker_rules) throw new Error('Upload the base wordlist, cracked list and candidate rules file.');
    if (!valueOf('rank_output_name')) throw new Error('Enter a ranking CSV output filename.');
    const options = {
      output_name: valueOf('rank_output_name'), topk: integerOrBlank('rank_topk', 'Top rules', 0), preset: $('rank_preset').value,
      batch_size: integerOrBlank('rank_batch_size', 'GPU batch size', 1),
      global_bits: integerOrBlank('rank_global_bits', 'Global hash-map bits', 1),
      cracked_bits: integerOrBlank('rank_cracked_bits', 'Cracked hash-map bits', 1),
      device: integerOrBlank('rank_device', 'OpenCL device ID', 0),
      legacy: activeRankingMode === 'legacy',
    };
    if (activeRankingMode === 'mab') {
      options.mab_exploration = numberValue('rank_mab_exploration', 'MAB exploration', 0);
      options.mab_screening_trials = integerOrBlank('rank_mab_screening_trials', 'Screening trials', 1);
      options.mab_final_trials = integerOrBlank('rank_mab_final_trials', 'Final trials', 1);
      options.mab_sample_words = integerOrBlank('rank_mab_sample_words', 'Sample words', 1);
      options.mab_zero_eliminate = $('rank_mab_zero_eliminate').checked;
    }
    return options;
  }
  if (activeRankerWorkflow === 'optimize') {
    if (!uploadState.ranker_wordlist || !uploadState.ranker_cracked) throw new Error('Upload the base wordlist and cracked-password list.');
    const source = document.querySelector('input[name="rank_source_type"]:checked').value;
    if (source === 'csv' ? !uploadState.ranker_source_csv : !uploadState.ranker_source_rules) throw new Error(source === 'csv' ? 'Upload a ranking CSV.' : 'Upload the existing .rule file.');
    if (!valueOf('opt_output_name')) throw new Error('Enter an optimized ruleset output filename.');
    const maxWord = integerOrBlank('opt_max_word_len', 'Maximum word length', 1);
    const maxOutput = integerOrBlank('opt_max_output_len', 'Maximum output length', 1);
    if (! $('opt_auto_max_output_len').checked && maxOutput < maxWord) throw new Error('Maximum output length must be ≥ maximum word length, or enable automatic sizing.');
    const budgetText = valueOf('opt_budgets');
    if (budgetText && budgetText.split(',').some((part) => !/^\s*\d+\s*$/.test(part) || Number(part.trim()) < 1)) throw new Error('Budget sweep must contain positive integers separated by commas.');
    return {
      output_name: valueOf('opt_output_name'), source_type: source, candidates: integerOrBlank('opt_candidates', 'Candidate limit', 1),
      budget: integerOrBlank('opt_budget', 'Selection budget', 1), budgets: budgetText,
      rule_batch_size: integerOrBlank('opt_rule_batch_size', 'Rule batch size', 1),
      words_batch_size: integerOrBlank('opt_words_batch_size', 'Words batch size', 1),
      max_word_len: maxWord, max_rule_len: integerOrBlank('opt_max_rule_len', 'Maximum rule length', 1),
      max_output_len: maxOutput, cost_alpha: numberValue('opt_cost_alpha', 'Cost alpha', 0),
      device: integerOrBlank('opt_device', 'OpenCL device ID', 0),
      auto_max_output_len: $('opt_auto_max_output_len').checked,
      print_output_len_estimate: $('opt_print_output_len_estimate').checked,
    };
  }
  if (!uploadState.ranker_analysis_csv) throw new Error('Upload a ranking CSV to analyze.');
  const writeRules = $('an_write_rules').checked;
  const writeScores = $('an_write_scores').checked;
  if (!$('an_rules_only').checked && !$('an_no_stats').checked && !valueOf('an_summary_name')) throw new Error('Enter a summary output filename.');
  if (writeRules && !valueOf('an_rules_output_name')) throw new Error('Enter a clean rules output filename.');
  if (writeScores && !valueOf('an_scores_output_name')) throw new Error('Enter a scored rules output filename.');
  return {
    summary_name: valueOf('an_summary_name'), rules_output_name: valueOf('an_rules_output_name'), scores_output_name: valueOf('an_scores_output_name'),
    top: integerOrBlank('an_top', 'Top rules', 1), console_top: integerOrBlank('an_console_top', 'Console top', 0),
    chunk_size: integerOrBlank('an_chunk_size', 'Chunk size', 1),
    write_rules: writeRules, write_scores: writeScores, rules_only: $('an_rules_only').checked,
    no_stats: $('an_no_stats').checked, parallel: $('an_parallel').checked, no_console: $('an_no_console').checked,
    no_progress: $('an_no_progress').checked,
  };
}
function selectConcentratorMode(mode) {
  const allowed = ['extract', 'combo', 'markov', 'process'];
  activeConcentratorMode = allowed.includes(mode) ? mode : 'extract';
  document.querySelectorAll('.concentrator-mode-tab').forEach((button) => {
    const active = button.dataset.concentratorMode === activeConcentratorMode;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('[data-concentrator-panel]').forEach((panel) => {
    panel.hidden = panel.dataset.concentratorPanel !== activeConcentratorMode;
  });
  const copy = {
    extract: ['Extract top rules', 'Aggregate the uploaded rule files, rank unique rules by frequency and export the top entries.', 'Rule extraction ready', 'Upload at least one rule file, choose the extraction limit and launch the processor.'],
    combo: ['Combinatorial generation', 'Generate valid combinations from the most frequent safe operator tokens in the uploaded corpus.', 'Combinatorial generation ready', 'Set the target count and token length range before launching generation.'],
    markov: ['Markov generation', 'Train the Kneser–Ney token model and generate probable rules with best-first search.', 'Markov generation ready', 'Use the uploaded rules as a corpus, then choose your target and token length range.'],
    process: ['Process & clean rules', 'Apply the selected filters in the original fixed order and export a normalized ruleset.', 'Ruleset processing ready', 'Choose the filters to apply. Leaving all filters off exports the unique normalized rules.'],
  }[activeConcentratorMode];
  $('concentrator-mode-title').textContent = copy[0];
  $('concentrator-mode-description').textContent = copy[1];
  $('concentrator-launch-title').textContent = copy[2];
  $('concentrator-launch-hint').textContent = copy[3];
}
function collectConcentratorOptions() {
  if (!(uploadState.concentrator_files || []).length) throw new Error('Upload at least one rule file for Concentrator.');
  const outputBase = valueOf('conc_output_base');
  if (!outputBase) throw new Error('Enter an output base name.');
  const maxLength = integerOrBlank('conc_max_length', 'Maximum input rule length', 1);
  if (maxLength > 255) throw new Error('Maximum input rule length cannot exceed 255.');
  const options = {
    output_base_name: outputBase, max_length: maxLength, output_format: $('conc_output_format').value,
    no_gpu: !$('conc_use_gpu').checked, in_memory: $('conc_in_memory').checked,
    confirm_large_memory: $('conc_confirm_memory').checked,
  };
  if (activeConcentratorMode === 'extract') {
    options.top_rules = integerOrBlank('conc_top_rules', 'Top rules to extract', 1);
    options.statistical_sort = $('conc_sort_mode').value === 'statistical';
  } else if (activeConcentratorMode === 'combo') {
    options.combo_target = integerOrBlank('conc_combo_target', 'Combinatorial target', 1);
    options.combo_min_len = integerOrBlank('conc_combo_min', 'Combinatorial minimum length', 1);
    options.combo_max_len = integerOrBlank('conc_combo_max', 'Combinatorial maximum length', 1);
    if (options.combo_max_len > 31 || options.combo_min_len > options.combo_max_len) throw new Error('Combinatorial length range must satisfy 1 ≤ minimum ≤ maximum ≤ 31.');
  } else if (activeConcentratorMode === 'markov') {
    options.generate_target = integerOrBlank('conc_markov_target', 'Markov target', 1);
    options.markov_min_len = integerOrBlank('conc_markov_min', 'Markov minimum length', 1);
    options.markov_max_len = integerOrBlank('conc_markov_max', 'Markov maximum length', 1);
    if (options.markov_max_len > 31 || options.markov_min_len > options.markov_max_len) throw new Error('Markov length range must satisfy 1 ≤ minimum ≤ maximum ≤ 31.');
  } else {
    options.filter_min_occ = integerOrBlank('conc_filter_min_occ', 'Minimum occurrence', 1);
    options.filter_max_rules = integerOrBlank('conc_filter_max_rules', 'Maximum rules', 1);
    options.filter_inverse = integerOrBlank('conc_filter_inverse', 'Inverse cutoff', 1);
    options.filter_func_redundancy = $('conc_func_min').checked;
    options.filter_hashcat_cleanup = $('conc_hashcat_cleanup').value;
  }
  return options;
}
async function startConcentratorRun() {
  try {
    const options = collectConcentratorOptions();
    $('start-concentrator-run').disabled = true;
    setActiveTool('concentrator');
    resetLogView('Starting Concentrator', 'Original Concentrator processing output will appear here.');
    lastLogId = 0;
    const started = await apiPost('/api/concentrator/run', { mode: activeConcentratorMode, options });
    trackStartedJob(started);
    toast(`Concentrator ${activeConcentratorMode} workflow launched.`);
    await pollStatus();
  } catch (error) {
    toast(error.message, true);
    $('start-concentrator-run').disabled = false;
  }
}
async function cancelConcentratorRun() {
  if (!window.confirm('Interrupt the active Concentrator process? Any outputs already written will be preserved where possible.')) return;
  $('concentrator-cancel').disabled = true;
  try { await apiPost('/api/concentrator/cancel', {}); toast('Concentrator cancellation requested.'); await pollStatus(); }
  catch (error) { toast(error.message, true); }
}

async function startRankerRun() {
  try {
    const options = rankerOptionsForActiveWorkflow();
    $('ranker-start-run').disabled = true;
    setActiveTool('ranker');
    resetLogView('Starting Rule Ranker', 'Ranker output will appear here as the process begins.');
    lastLogId = 0;
    const started = await apiPost('/api/ranker/run', { mode: activeRankerWorkflow, options });
    trackStartedJob(started);
    toast(`Rule Ranker ${activeRankerWorkflow} workflow launched.`);
    await pollStatus();
  } catch (error) {
    toast(error.message, true);
    $('ranker-start-run').disabled = false;
  }
}
async function cancelRankerRun() {
  if (!window.confirm('Interrupt the active Rule Ranker process? Partial files that have already been written will be preserved.')) return;
  $('ranker-cancel').disabled = true;
  try { await apiPost('/api/ranker/cancel', {}); toast('Ranker cancellation requested.'); await pollStatus(); }
  catch (error) { toast(error.message, true); }
}

function readUtilityNumber(id, label) {
  const raw = $(id).value;
  if (raw === '') return '';
  const value = Number(raw);
  if (!Number.isInteger(value) || value < Number($(id).min || 0) || (id === 'rulestripper-max-depth' && value > 31)) {
    throw new Error(`${label} must be a valid integer in the displayed range.`);
  }
  return value;
}
function utilityOptions(tool) {
  if (tool === 'rulestripper') {
    if (!uploadState.rulestripper_base || !uploadState.rulestripper_target) throw new Error('Upload or select both Rulestripper BASE and TARGET wordlists.');
    return {
      max_depth: readUtilityNumber('rulestripper-max-depth', 'Maximum depth'),
      min_stem: readUtilityNumber('rulestripper-min-stem', 'Minimum stem length'),
      leet_amb: readUtilityNumber('rulestripper-leet-amb', 'Leet ambiguity'),
      workers: readUtilityNumber('rulestripper-workers', 'Worker count'),
      chunk_size: readUtilityNumber('rulestripper-chunk-size', 'Chunk size'),
      ascii_range: readUtilityNumber('rulestripper-ascii-range', 'ASCII range'),
      no_toggle_seeds: !$('rulestripper-toggle-seeds').checked,
      no_new_modes: !$('rulestripper-new-modes').checked,
      debug: $('rulestripper-debug').checked,
      output_name: $('rulestripper-output-name').value,
    };
  }
  if (!uploadState.minimizer_rules) throw new Error('Upload or select a Hashcat rules file first.');
  return {
    workers: readUtilityNumber('minimizer-workers', 'Worker count'),
    probe_words: readUtilityNumber('minimizer-probe-words', 'Probe word count'),
    seed: readUtilityNumber('minimizer-seed', 'Random seed'),
    extra_probes: $('minimizer-extra-probes').value,
    multibyte: $('minimizer-multibyte').checked,
    output_name: $('minimizer-output-name').value,
  };
}
async function startUtilityRun(tool) {
  const title = tool === 'rulestripper' ? 'Rulestripper' : 'Rule Minimizer';
  const startButton = $(`${tool}-start`);
  try {
    const options = utilityOptions(tool);
    startButton.disabled = true;
    setActiveTool(tool);
    resetLogView(`Starting ${title}`, `${title} output will appear here as the process begins.`);
    lastLogId = 0;
    const started = await apiPost('/api/tools/run', { tool, options });
    trackStartedJob(started);
    toast(`${title} started.`);
    await pollStatus();
  } catch (error) {
    toast(error.message, true);
    startButton.disabled = false;
  }
}
async function cancelUtilityRun(tool) {
  const title = tool === 'rulestripper' ? 'Rulestripper' : 'Rule Minimizer';
  if (!window.confirm(`Cancel the active ${title} process? Any output already written will be preserved.`)) return;
  $(`${tool}-cancel`).disabled = true;
  try { await apiPost('/api/tools/cancel', {}); toast(`${title} cancellation requested.`); await pollStatus(); }
  catch (error) { toast(error.message, true); }
}

function initializeApp() {
  initDepthOverrides(); setDefaults(); configureFileInputs(); configureLibrarySelectors();
  const soundToggle = $('completion-sound');
  if (soundToggle) {
    soundToggle.checked = completionSoundEnabled;
    soundToggle.addEventListener('change', () => {
      completionSoundEnabled = soundToggle.checked;
      try { localStorage.setItem('ruleops-completion-sound', completionSoundEnabled ? 'on' : 'off'); } catch {}
      if (completionSoundEnabled) unlockCompletionAudio();
      toast(completionSoundEnabled ? 'Completion sound enabled.' : 'Completion sound muted.');
    });
  }
  $('token_strip').addEventListener('change', e => toggleStage('token', e.target.checked));
  $('genetic').addEventListener('change', e => toggleStage('genetic', e.target.checked));
  $('reset-defaults').addEventListener('click', () => { setDefaults(); toast('All configuration values reset to defaults.'); });
  $('advanced-trigger').addEventListener('click', () => {
    const btn = $('advanced-trigger'), open = btn.getAttribute('aria-expanded') !== 'true';
    btn.setAttribute('aria-expanded', String(open)); $('advanced-content').classList.toggle('open', open);
  });
  $('start-run').addEventListener('click', startRun);
  $('ranker-start-run').addEventListener('click', startRankerRun);
  $('ranker-cancel').addEventListener('click', cancelRankerRun);
  $('start-concentrator-run').addEventListener('click', startConcentratorRun);
  $('concentrator-cancel').addEventListener('click', cancelConcentratorRun);
  $('rulestripper-start').addEventListener('click', () => startUtilityRun('rulestripper'));
  $('rulestripper-cancel').addEventListener('click', () => cancelUtilityRun('rulestripper'));
  $('minimizer-start').addEventListener('click', () => startUtilityRun('minimizer'));
  $('minimizer-cancel').addEventListener('click', () => cancelUtilityRun('minimizer'));
  const navigateTo = (href) => {
    const target = href && href.startsWith('#') ? document.getElementById(href.slice(1)) : null;
    if (!target) return;
    if (href === '#run-storage') setActiveSystemView('storage');
    else if (href === '#about') setActiveSystemView('about');
    else if (href === '#ranker') setActiveTool('ranker');
    else if (href === '#concentrator') setActiveTool('concentrator');
    else if (href === '#rulestripper') setActiveTool('rulestripper');
    else if (href === '#minimizer') setActiveTool('minimizer');
    else if (['#workspace', '#tuning', '#gpu-diagnostic'].includes(href)) setActiveTool('rulest');
    if (['#ranker', '#concentrator', '#rulestripper', '#minimizer', '#run-storage'].includes(href)) setRulestMenuExpanded(false);

    const breadcrumbLabels = {
      '#workspace': 'Run workspace', '#tuning': 'Engine tuning',
      '#gpu-diagnostic': 'GPU diagnostics', '#ranker': 'Rule Ranker',
      '#concentrator': 'Concentrator', '#rulestripper': 'Rulestripper', '#minimizer': 'Rule Minimizer', '#live-log': 'Live activity', '#run-storage': 'Run storage', '#about': 'About',
    };
    const breadcrumb = document.querySelector('.breadcrumb strong');
    if (breadcrumb) breadcrumb.textContent = breadcrumbLabels[href] || 'Workspace';

    if (window.location.hash !== href) history.pushState(null, '', href);
    setActiveNav(href);
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
    target.focus({ preventScroll: true });
    target.classList.add('nav-target-highlight');
    window.setTimeout(() => target.classList.remove('nav-target-highlight'), 1400);
  };

  $('nav-rulest').addEventListener('click', () => {
    if (activeTool !== 'rulest') {
      setActiveTool('rulest');
      setRulestMenuExpanded(true);
      navigateTo('#workspace');
      return;
    }
    setRulestMenuExpanded($('nav-rulest').getAttribute('aria-expanded') !== 'true');
  });

  document.querySelectorAll('[data-nav-tool], [data-nav-section]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      navigateTo(link.getAttribute('href'));
    });
  });
  document.querySelectorAll('.ranker-workflow-tab').forEach((button) => button.addEventListener('click', () => selectRankerWorkflow(button.dataset.workflow)));
  document.querySelectorAll('.rank-mode-tab').forEach((button) => button.addEventListener('click', () => selectRankingMode(button.dataset.rankMode)));
  document.querySelectorAll('.concentrator-mode-tab').forEach((button) => button.addEventListener('click', () => selectConcentratorMode(button.dataset.concentratorMode)));
  document.querySelectorAll('input[name="rank_source_type"]').forEach((radio) => radio.addEventListener('change', updateOptimizeSourceVisibility));
  selectRankerWorkflow('rank');
  let storedRankingMode = 'mab';
  try { storedRankingMode = sessionStorage.getItem('ruleops-ranker-mode') || 'mab'; } catch {}
  selectRankingMode(storedRankingMode);
  selectConcentratorMode('extract');
  let storedTool = 'rulest';
  try { storedTool = sessionStorage.getItem('ruleops-active-tool') || 'rulest'; } catch {}
  const initialTool = window.location.hash === '#ranker' ? 'ranker' : window.location.hash === '#concentrator' ? 'concentrator' : window.location.hash === '#rulestripper' ? 'rulestripper' : window.location.hash === '#minimizer' ? 'minimizer' : ['#workspace', '#tuning', '#gpu-diagnostic'].includes(window.location.hash) ? 'rulest' : storedTool;
  setActiveTool(initialTool);
  if (window.location.hash === '#run-storage') setActiveSystemView('storage');
  if (window.location.hash === '#about') setActiveSystemView('about');
  let storedRulestMenu = 'true';
  try { storedRulestMenu = sessionStorage.getItem('ruleops-rulest-menu-expanded') || 'true'; } catch {}
  setRulestMenuExpanded(storedRulestMenu !== 'false' || initialTool === 'rulest');
  $('pause-run').addEventListener('click', () => controlRun('pause'));
  $('resume-run').addEventListener('click', () => controlRun('resume'));
  $('stop-run').addEventListener('click', () => controlRun('stop'));
  $('detect-devices').addEventListener('click', () => detectDevices(false));
  $('copy-gpu-report').addEventListener('click', copyGpuReport);
  $('logout-button').addEventListener('click', async () => {
    try { await apiPost('/api/auth/logout', {}); window.location.replace('/'); }
    catch (error) { toast(error.message, true); }
  });
  $('change-password-button').addEventListener('click', () => {
    $('password-change-error').textContent = ''; $('password-dialog').showModal();
  });
  $('cancel-password-change').addEventListener('click', () => $('password-dialog').close());
  $('password-form').addEventListener('submit', submitPasswordChange);
  $('download-log').addEventListener('click', downloadLog);
  $('clear-log').addEventListener('click', clearLogHistoryFromUi);
  $('delete-run-directories').addEventListener('click', deleteAllRunDirectories);
  $('wrap-log').addEventListener('click', () => {
    const body = $('log-output');
    const wrapOn = body.classList.toggle('no-wrap') === false;
    $('wrap-log').textContent = `Wrap: ${wrapOn ? 'ON' : 'OFF'}`;
    $('wrap-log').setAttribute('aria-pressed', String(wrapOn));
  });
  $('expand-log').addEventListener('click', () => {
    const expanded = $('terminal-window').classList.toggle('expanded');
    $('expand-log').textContent = expanded ? 'Collapse' : 'Expand';
    $('expand-log').setAttribute('aria-expanded', String(expanded));
  });
  const navLinks = Array.from(document.querySelectorAll('[data-nav-tool], [data-nav-section]'));
  const setActiveNav = (hash) => {
    const wanted = hash || (activeTool === 'ranker' ? '#ranker' : activeTool === 'concentrator' ? '#concentrator' : activeTool === 'rulestripper' ? '#rulestripper' : activeTool === 'minimizer' ? '#minimizer' : '#workspace');
    navLinks.forEach((link) => {
      const active = link.getAttribute('href') === wanted;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    const rulestSectionActive = ['#workspace', '#tuning', '#gpu-diagnostic'].includes(wanted);
    if (rulestSectionActive) {
      const button = $('nav-rulest');
      button.classList.add('active');
      button.setAttribute('aria-current', 'page');
      setRulestMenuExpanded(true);
    }
    const labels = {
      '#workspace': 'Run workspace', '#tuning': 'Engine tuning', '#gpu-diagnostic': 'GPU diagnostics',
      '#ranker': 'Rule Ranker', '#concentrator': 'Concentrator', '#rulestripper': 'Rulestripper', '#minimizer': 'Rule Minimizer', '#live-log': 'Live activity', '#run-storage': 'Run storage', '#about': 'About',
    };
    const breadcrumb = document.querySelector('.breadcrumb strong');
    if (breadcrumb) breadcrumb.textContent = labels[wanted] || (activeTool === 'ranker' ? 'Rule Ranker' : activeTool === 'concentrator' ? 'Concentrator' : activeTool === 'rulestripper' ? 'Rulestripper' : activeTool === 'minimizer' ? 'Rule Minimizer' : 'Run workspace');
  };
  const handleNavigationState = () => {
    const hash = window.location.hash;
    if (hash === '#run-storage') setActiveSystemView('storage');
    else if (hash === '#about') setActiveSystemView('about');
    else if (hash === '#ranker') setActiveTool('ranker');
    else if (hash === '#concentrator') setActiveTool('concentrator');
    else if (hash === '#rulestripper') setActiveTool('rulestripper');
    else if (hash === '#minimizer') setActiveTool('minimizer');
    else if (['#workspace', '#tuning', '#gpu-diagnostic'].includes(hash)) setActiveTool('rulest');
    setActiveNav(hash);
  };
  window.addEventListener('hashchange', handleNavigationState);
  window.addEventListener('popstate', handleNavigationState);
  setActiveNav(window.location.hash);
  detectDevices(true);
  pollStatus(); pollTimer = setInterval(pollStatus, 1000);
}
async function submitPasswordChange(event) {
  event.preventDefault();
  const current = $('current-password').value;
  const next = $('new-password').value;
  const confirm = $('confirm-new-password').value;
  const error = $('password-change-error');
  error.textContent = '';
  if (next.length < 12) { error.textContent = 'New password must contain at least 12 characters.'; return; }
  if (next !== confirm) { error.textContent = 'The new passwords do not match.'; return; }
  $('submit-password-change').disabled = true;
  try {
    await apiPost('/api/auth/change-password', { current_password: current, new_password: next });
    $('password-dialog').close();
    $('password-form').reset();
    toast('Password changed. Other sessions have been signed out.');
  } catch (requestError) {
    error.textContent = requestError.message;
  } finally { $('submit-password-change').disabled = false; }
}

function applyAdminVisibility(auth) {
  const isAdmin = !!(auth && (auth.role === 'admin' || auth.is_admin));
  const userPanel = document.getElementById('about-user-panel');
  if (userPanel) userPanel.hidden = !isAdmin;
}

async function boot() {
  try {
    const response = await fetch('/api/auth/me', { cache: 'no-store' });
    const auth = await response.json();
    if (!auth.authenticated || !auth.csrf_token) { window.location.replace('/'); return; }
    csrfToken = auth.csrf_token;
    window.__csrfToken = auth.csrf_token;
    applyAdminVisibility(auth);
    initializeApp();
  } catch (error) {
    window.location.replace('/');
  }
}
document.addEventListener('DOMContentLoaded', boot);



/* About page: retain the administrator-only regular-user password control. */
function wireAboutAccessControls() {
  const button = document.getElementById('set-user-password-button');
  const input = document.getElementById('user-password-input');
  const feedback = document.getElementById('user-password-feedback');
  if (!button) return;

  button.addEventListener('click', async () => {
    const password = input ? input.value : '';
    button.disabled = true;
    if (feedback) { feedback.hidden = true; feedback.textContent = ''; feedback.classList.remove('error'); }
    try {
      const data = await apiPost('/api/auth/set-user-password', { password });
      if (feedback) { feedback.hidden = false; feedback.textContent = data.message || 'User password updated.'; }
      if (input) input.value = '';
    } catch (error) {
      if (feedback) { feedback.hidden = false; feedback.textContent = error.message; feedback.classList.add('error'); }
      else toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  });
}

document.addEventListener('DOMContentLoaded', wireAboutAccessControls);
