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
let lastStorageIntelligenceAt = 0;
let storageIntelligenceLoading = false;
let lastRunStorageScan = null;
let lastLibraryDuplicateScan = null;
let librarySearchTimer = null;
let librarySearchRequestId = 0;
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
  topn_seeds: false, topn_complementary: true, topn_adaptive: true, topn_n: 400000, topn_max_seeds: 150000, topn_inject_cap: 100000,
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
function estimateStageEta(data) {
  if (data.status === 'completed') return { value: 'Done', note: 'Run completed' };
  if (data.status === 'failed') return { value: '—', note: 'Run failed' };
  if (data.status === 'stopped') return { value: '—', note: 'Run stopped' };
  if (data.status === 'stopping') return { value: 'Stopping', note: 'Waiting for process exit' };
  if (data.status !== 'running') return { value: '—', note: 'No active run' };
  if (data.paused) return { value: 'Paused', note: 'Estimate paused with the job' };

  const completed = Number(data.progress_completed);
  const total = Number(data.progress_total);
  let fraction = null;
  if (Number.isFinite(completed) && Number.isFinite(total) && total > 0 && completed >= 0) {
    fraction = Math.min(1, completed / total);
  } else if (data.progress != null && Number.isFinite(Number(data.progress))) {
    fraction = Math.min(1, Math.max(0, Number(data.progress) / 100));
  }
  const stageElapsed = Number(data.stage_elapsed);
  if (fraction == null || !Number.isFinite(stageElapsed) || stageElapsed < 5 || fraction < 0.02) {
    return { value: 'Estimating…', note: 'Waiting for stable stage progress' };
  }
  if (fraction >= 0.999) return { value: 'Finishing', note: 'Current stage is nearly complete' };

  const remaining = stageElapsed * (1 - fraction) / fraction;
  if (!Number.isFinite(remaining) || remaining < 0 || remaining > 365 * 24 * 3600) {
    return { value: '—', note: 'Stage estimate unavailable' };
  }
  return { value: fmtTime(remaining), note: 'Current stage · recalculated live' };
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
  if (field === 'target') updateTopNFromTargetSize(file && file.size);
}

/** Approximate TARGET line count from byte size (avg ~11 bytes/line for password lists).
 *  Updates Top-N passwords field + hint only — does not touch CELF / GPU memory paths. */
function updateTopNFromTargetSize(sizeBytes) {
  const input = document.getElementById('topn_n');
  const hint = document.getElementById('topn_n_hint');
  if (!input) return;
  const size = Number(sizeBytes) || 0;
  if (size <= 0) {
    if (hint) {
      hint.textContent = 'How many top target passwords to analyse. 0 = unlimited (scan the whole file). After TARGET is selected, shows an approximate line count from the wordlist size.';
    }
    return;
  }
  // Conservative average: password + newline. Prefer slight overestimate vs underestimate.
  const approxLines = Math.max(1, Math.round(size / 11));
  input.value = String(approxLines);
  if (hint) {
    hint.textContent = `≈ ${approxLines.toLocaleString()} lines estimated from TARGET size (${humanSize(size)}). 0 = unlimited (scan the whole file). Adjust if needed.`;
  }
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
      if (field === 'target') updateTopNFromTargetSize(result.size);
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

function renderOutputs(outputs = [], outputTool = 'rulest') {
  const outputViews = {
    rulest: { count: 'output-count', list: 'output-list' },
    ranker: { count: 'ranker-output-count', list: 'ranker-output-list' },
    concentrator: { count: 'concentrator-output-count', list: 'concentrator-output-list' },
    rulestripper: { count: 'rulestripper-output-count', list: 'rulestripper-output-list' },
    minimizer: { count: 'minimizer-output-count', list: 'minimizer-output-list' },
  };
  Object.entries(outputViews).forEach(([tool, ids]) => {
    const ownedOutputs = tool === outputTool ? outputs : [];
    const count = $(ids.count);
    if (count) count.textContent = ownedOutputs.length;
    const root = $(ids.list);
    if (!root) return;
    root.innerHTML = '';
    if (!ownedOutputs.length) {
      const empty = document.createElement('div'); empty.className = 'empty-output';
      empty.innerHTML = '<span>▤</span><b>No outputs yet</b><small>Generated files for this tool will appear here.</small>';
      root.append(empty); return;
    }
    if (ownedOutputs.length > 3) {
      const bundle = document.createElement('a');
      bundle.className = 'download-output-bundle';
      bundle.href = '/api/run-storage/download-outputs.zip';
      bundle.title = `Download all ${ownedOutputs.length} output files as a ZIP archive`;
      bundle.setAttribute('aria-label', `Download all ${ownedOutputs.length} output files as a ZIP archive`);
      bundle.innerHTML = '<span aria-hidden="true">↓</span><span>Download all files <small>ZIP · ' + ownedOutputs.length + '</small></span>';
      root.append(bundle);
    }
    ownedOutputs.forEach((file) => {
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

const TOOL_METRIC_WAITING_STAGES = {
  rulest: 'Waiting for a run',
  ranker: 'Waiting for a Ranker job',
  concentrator: 'Waiting for a Concentrator job',
  rulestripper: 'Waiting for Rulestripper',
  minimizer: 'Waiting for Rule Minimizer',
};

function renderToolMetrics(tool, data) {
  const panel = document.querySelector(`[data-tool-metrics="${tool}"]`);
  if (!panel) return;
  const ownsRun = data.tool === tool;
  const status = ownsRun ? (data.status || 'idle') : 'idle';
  const paused = ownsRun && !!data.paused && status === 'running';
  const running = ownsRun && (status === 'running' || status === 'stopping');
  const outputs = ownsRun && Array.isArray(data.outputs) ? data.outputs.length : 0;
  const labels = {
    idle: 'Idle', running: paused ? 'Paused' : 'Running', stopping: 'Stopping',
    completed: 'Completed', stopped: 'Stopped', failed: 'Failed', offline: 'Offline',
  };
  const notes = {
    idle: 'Ready to configure',
    running: paused ? 'Paused at safe checkpoint' : data.pause_requested ? 'Pause requested · checkpoint pending' : 'Engine process is active',
    stopping: 'Stopping requested · waiting for process exit',
    completed: 'Run finished successfully',
    stopped: 'Run stopped · partial results preserved',
    failed: data.error ? String(data.error) : 'Check engine output below',
    offline: 'Web interface disconnected',
  };
  const value = (name) => panel.querySelector(`[data-metric="${name}"]`);
  const statusValue = value('status');
  const noteValue = value('note');
  const stageValue = value('stage');
  const elapsedValue = value('elapsed');
  const outputValue = value('outputs');
  const etaValue = value('eta');
  const etaNoteValue = value('eta-note');
  const eta = ownsRun ? estimateStageEta(data) : { value: '—', note: 'No active run for this tool' };
  if (etaValue) etaValue.textContent = eta.value;
  if (etaNoteValue) etaNoteValue.textContent = eta.note;
  if (etaValue) etaValue.title = 'Estimated time remaining in the active stage. This is recalculated as progress updates and is not a whole-run guarantee.';
  if (statusValue) statusValue.textContent = labels[status] || 'Idle';
  if (noteValue) noteValue.textContent = notes[status] || notes.idle;
  if (stageValue) {
    const stage = ownsRun && status !== 'idle' && data.stage ? data.stage : TOOL_METRIC_WAITING_STAGES[tool];
    stageValue.textContent = stage;
    stageValue.title = stage;
  }
  if (elapsedValue) elapsedValue.textContent = ownsRun && data.elapsed != null ? fmtTime(data.elapsed) : '00:00';
  if (outputValue) outputValue.textContent = String(outputs);
  panel.dataset.engineState = paused ? 'paused' : running ? 'running' : status;
  const dot = panel.querySelector('[data-metric-dot]');
  if (dot) dot.dataset.state = paused ? 'paused' : status;
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
function storageIntelElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}
function storageIntelPlaceholder(container, message) {
  container.replaceChildren(storageIntelElement('div', 'storage-intel-placeholder', message));
}
function renderStorageIntelligence(data) {
  const totalBytes = Number(data.total_bytes || 0);
  $('storage-intel-total').textContent = formatStorageBytes(totalBytes);
  $('storage-intel-file-total').textContent = `${Number(data.total_files || 0).toLocaleString()} files`;
  $('storage-intel-volume-note').textContent = `${Number(data.run_directories || 0).toLocaleString()} run folders · persistent + temporary data`;
  const filesystem = data.filesystem || null;
  const filesystemPercent = filesystem ? Number(filesystem.used_percent || 0) : null;
  $('storage-intel-disk-percent').textContent = filesystemPercent === null ? '—' : `${filesystemPercent.toFixed(1)}%`;
  $('storage-intel-disk-bar').style.width = filesystemPercent === null
    ? '0%' : `${Math.max(0, Math.min(100, filesystemPercent))}%`;

  // RULEOPS quota and physical filesystem usage are different measurements.
  // The quota uses the same DATA/runs tree as server-side storage preflight.
  const quota = data.quota || {};
  const quotaUsed = Number(quota.used_bytes ?? totalBytes);
  const quotaLimit = Number(quota.limit_bytes || 0);
  const quotaPercent = quotaLimit > 0 ? quotaUsed / quotaLimit * 100 : 0;
  const quotaRemaining = Math.max(0, quotaLimit - quotaUsed);
  $('storage-intel-quota-label').textContent = `${formatStorageBytes(quotaUsed)} / ${formatStorageBytes(quotaLimit)}`;
  $('storage-intel-quota-percent').textContent = `${quotaPercent.toFixed(1)}% used`;
  $('storage-intel-quota-bar').style.width = `${Math.max(0, Math.min(100, quotaPercent))}%`;
  $('storage-intel-quota-progress').classList.toggle('is-over-quota', quotaPercent >= 100);
  $('storage-intel-quota-progress').setAttribute('aria-valuenow', String(Math.max(0, Math.min(100, quotaPercent)).toFixed(1)));
  $('storage-intel-quota-progress').setAttribute('aria-valuetext', `${formatStorageBytes(quotaUsed)} of ${formatStorageBytes(quotaLimit)} used`);
  $('storage-intel-quota-note').textContent = quotaPercent >= 100
    ? `Quota exceeded by ${formatStorageBytes(quotaUsed - quotaLimit)}. Remove stored data or increase RULEOPS_MAX_DATA_STORAGE_BYTES.`
    : `${formatStorageBytes(quotaRemaining)} remaining · includes run outputs, temporary uploads and reusable library files.`;

  const breakdown = $('storage-intel-breakdown');
  breakdown.replaceChildren();
  (data.buckets || []).forEach((bucket) => {
    const row = storageIntelElement('div', 'storage-intel-breakdown-row');
    const label = storageIntelElement('div', 'storage-intel-breakdown-label');
    label.appendChild(storageIntelElement('span', '', bucket.label));
    label.appendChild(storageIntelElement('b', '', formatStorageBytes(bucket.bytes)));
    const track = storageIntelElement('div', 'storage-intel-breakdown-track');
    const bar = document.createElement('span');
    bar.style.width = `${Math.max(0, Math.min(100, Number(bucket.percent || 0)))}%`;
    track.appendChild(bar);
    row.append(label, track);
    breakdown.appendChild(row);
  });
  if (!breakdown.childElementCount) storageIntelPlaceholder(breakdown, 'No storage data found.');

  const cleanup = $('storage-intel-cleanup');
  cleanup.replaceChildren();
  const opportunities = [
    {
      label: 'Empty / logs-only folders',
      count: data.cleanup?.log_only_count,
      bytes: data.cleanup?.log_only_bytes,
      scanned: data.cleanup?.run_scanned_at,
      empty: 'Run the folder scan to find eligible items.',
    },
    {
      label: 'Repeated dataset runs',
      count: data.cleanup?.duplicate_run_count,
      bytes: data.cleanup?.duplicate_run_bytes,
      scanned: data.cleanup?.run_scanned_at,
      empty: 'Scan to find repeated runs using the same input datasets.',
    },
    {
      label: 'Duplicate library / work files',
      count: data.cleanup?.suggested_delete_count,
      bytes: data.cleanup?.suggested_delete_bytes,
      scanned: data.cleanup?.library_scanned_at,
      empty: 'Run the library + work duplicate scan to find exact copies.',
    },
    {
      label: 'Same-name groups to review',
      count: data.cleanup?.same_name_review_groups,
      bytes: null,
      scanned: data.cleanup?.library_scanned_at,
      empty: 'Run the library + work duplicate scan to find filename collisions.',
    },
  ];
  opportunities.forEach((item) => {
    const row = storageIntelElement('div', 'storage-intel-cleanup-row');
    row.appendChild(storageIntelElement('b', '', item.label));
    const detail = item.scanned
      ? `Scanned ${item.scanned}`
      : item.empty;
    row.appendChild(storageIntelElement('small', '', detail));
    const value = item.count === null || item.count === undefined ? '—' : Number(item.count).toLocaleString();
    const strong = storageIntelElement('strong', '', value);
    if (item.bytes !== null && item.bytes !== undefined) {
      strong.appendChild(storageIntelElement('em', '', `${formatStorageBytes(item.bytes)} potential`));
    }
    row.appendChild(strong);
    cleanup.appendChild(row);
  });

  const library = data.library || {};
  $('storage-intel-library-size').textContent = formatStorageBytes(library.bytes || 0);
  const libraryContainer = $('storage-intel-library');
  libraryContainer.replaceChildren();
  [
    ['Wordlists', library.wordlist_files, library.wordlist_bytes],
    ['Rule files', library.rule_files, library.rule_bytes],
  ].forEach(([label, count, bytes]) => {
    const card = storageIntelElement('div', 'storage-intel-library-card');
    card.appendChild(storageIntelElement('b', '', Number(count || 0).toLocaleString()));
    card.appendChild(storageIntelElement('small', '', `${label} · ${formatStorageBytes(bytes || 0)}`));
    libraryContainer.appendChild(card);
  });

  const recentLibrary = $('storage-intel-recent-library');
  recentLibrary.replaceChildren();
  (data.recent_library_files || []).forEach((file) => {
    const row = storageIntelElement('div', 'storage-intel-item');
    const copy = storageIntelElement('div', 'storage-intel-item-copy');
    copy.appendChild(storageIntelElement('b', '', file.name));
    const path = storageIntelElement('small', 'storage-intel-path', file.path);
    path.title = file.path || '';
    copy.appendChild(path);
    const meta = storageIntelElement('div', 'storage-intel-item-meta');
    meta.appendChild(storageIntelElement('b', '', new Date(Number(file.modified || 0) * 1000).toLocaleDateString()));
    meta.appendChild(storageIntelElement('small', '', file.category === 'rules' ? 'RULE FILE' : 'WORDLIST'));
    const download = document.createElement('a');
    download.className = 'storage-intel-download';
    download.href = file.download_url || '#';
    download.title = `Download ${file.name}`;
    download.setAttribute('aria-label', `Download ${file.name}`);
    download.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m0 0 4-4m-4 4-4-4M4 19v2h16v-2"/></svg>';
    row.append(copy, meta, download);
    recentLibrary.appendChild(row);
  });
  if (!recentLibrary.childElementCount) storageIntelPlaceholder(recentLibrary, 'No reusable library files found.');

  const largestFiles = $('storage-intel-largest-files');
  largestFiles.replaceChildren();
  (data.largest_files || []).forEach((file) => {
    const row = storageIntelElement('div', 'storage-intel-item');
    const copy = storageIntelElement('div', 'storage-intel-item-copy');
    copy.appendChild(storageIntelElement('b', '', file.name));
    const path = storageIntelElement('small', 'storage-intel-path', file.path);
    path.title = file.path || '';
    copy.appendChild(path);
    const meta = storageIntelElement('div', 'storage-intel-item-meta');
    meta.appendChild(storageIntelElement('b', '', formatStorageBytes(file.bytes)));
    meta.appendChild(storageIntelElement('small', '', file.source === 'library' ? 'LIBRARY' : 'WORK FILE'));
    const download = document.createElement('a');
    download.className = 'storage-intel-download';
    download.href = file.download_url || '#';
    download.title = `Download ${file.name}`;
    download.setAttribute('aria-label', `Download ${file.name}`);
    download.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m0 0 4-4m-4 4-4-4M4 19v2h16v-2"/></svg>';
    row.append(copy, meta, download);
    largestFiles.appendChild(row);
  });
  if (!largestFiles.childElementCount) storageIntelPlaceholder(largestFiles, 'No downloadable library or work files were found.');

  const largestFolders = $('storage-intel-largest-folders');
  largestFolders.replaceChildren();
  (data.largest_folders || []).forEach((folder) => {
    const row = storageIntelElement('div', 'storage-intel-item');
    const copy = storageIntelElement('div', 'storage-intel-item-copy');
    copy.appendChild(storageIntelElement('b', '', folder.name));
    const path = storageIntelElement('small', 'storage-intel-path', folder.path);
    path.title = folder.path || '';
    copy.appendChild(path);
    const meta = storageIntelElement('div', 'storage-intel-item-meta');
    meta.appendChild(storageIntelElement('b', '', formatStorageBytes(folder.bytes)));
    meta.appendChild(storageIntelElement('small', '', `${Number(folder.files || 0).toLocaleString()} files`));
    row.append(copy, meta);
    largestFolders.appendChild(row);
  });
  if (!largestFolders.childElementCount) storageIntelPlaceholder(largestFolders, 'No storage folders were found.');

  const activity = $('storage-intel-activity');
  activity.replaceChildren();
  (data.activity || []).forEach((event) => {
    const row = storageIntelElement('div', 'storage-intel-event');
    const copy = storageIntelElement('div', 'storage-intel-event-copy');
    copy.appendChild(storageIntelElement('b', '', event.action));
    copy.appendChild(storageIntelElement('small', '', event.detail || 'Storage operation completed.'));
    const timeText = event.bytes_reclaimed
      ? `${event.timestamp} · ${formatStorageBytes(event.bytes_reclaimed)} recovered`
      : event.timestamp;
    copy.appendChild(storageIntelElement('em', '', timeText));
    row.appendChild(copy);
    activity.appendChild(row);
  });
  if (!activity.childElementCount) storageIntelPlaceholder(activity, 'No storage scans or cleanup actions recorded during this server session.');
  $('storage-intel-history-scope').textContent = data.history_scope || 'this session';
  $('storage-intelligence-updated').textContent = `UPDATED ${new Date().toLocaleTimeString()}`;
}
async function loadStorageIntelligence(force = false) {
  const panel = $('storage-intelligence-title');
  if (!panel || storageIntelligenceLoading) return;
  if (!force && Date.now() - lastStorageIntelligenceAt < 30000) return;
  storageIntelligenceLoading = true;
  const button = $('storage-intelligence-refresh');
  if (button) button.disabled = true;
  try {
    const response = await fetch('/api/run-storage/intelligence', { cache: 'no-store' });
    if (response.status === 401) { window.location.replace('/'); return; }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load Storage Intelligence.');
    renderStorageIntelligence(data);
    lastStorageIntelligenceAt = Date.now();
  } catch (error) {
    const target = $('storage-intel-breakdown');
    if (target) storageIntelPlaceholder(target, `Storage Intelligence unavailable: ${error.message}`);
  } finally {
    storageIntelligenceLoading = false;
    if (button) button.disabled = false;
  }
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
    const scanButton = $('scan-run-storage');
    if (scanButton) scanButton.disabled = active;
    if (active) {
      ['delete-log-only-directories', 'delete-duplicate-directories'].forEach((id) => { const item = $(id); if (item) item.disabled = true; });
    } else if (lastRunStorageScan) {
      const logButton = $('delete-log-only-directories');
      const duplicateButton = $('delete-duplicate-directories');
      if (logButton) logButton.disabled = Number(lastRunStorageScan.log_only_count || 0) === 0;
      if (duplicateButton) duplicateButton.disabled = Number(lastRunStorageScan.duplicate_directories || 0) === 0;
    }
    if (feedback && !feedback.textContent) feedback.textContent = data.uploads_preserved ? 'Temporary uploads and the reusable runs/library/ wordlist/rules folders are preserved.' : '';
    loadStorageIntelligence();
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
    lastRunStorageScan = null;
    $('storage-scan-results').hidden = true;
    $('storage-scan-summary').textContent = 'Run a new scan to review targeted cleanup candidates.';
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

function appendStorageCandidateRow(container, title, detail) {
  const row = document.createElement('div');
  row.className = 'storage-candidate-row';
  const heading = document.createElement('b');
  heading.textContent = title;
  const description = document.createElement('small');
  description.textContent = detail;
  row.append(heading, description);
  container.appendChild(row);
}
function renderRunStorageScan(data) {
  lastRunStorageScan = data;
  const results = $('storage-scan-results');
  const summary = $('storage-scan-summary');
  const logList = $('storage-log-only-list');
  const duplicateList = $('storage-duplicate-list');
  logList.replaceChildren();
  duplicateList.replaceChildren();
  const logItems = data.log_only_directories || [];
  const duplicateGroups = data.duplicate_groups || [];
  const duplicateCount = Number(data.duplicate_directories || 0);
  $('storage-log-only-count').textContent = Number(data.log_only_count || 0).toLocaleString();
  $('storage-duplicate-count').textContent = duplicateCount.toLocaleString();
  $('storage-log-only-bytes').textContent = `${formatStorageBytes(data.log_only_bytes)} eligible`;
  $('storage-duplicate-bytes').textContent = `${formatStorageBytes(data.duplicate_reclaimable_bytes)} reclaimable`;

  if (logItems.length) {
    logItems.forEach((item) => {
      const kind = item.empty ? 'Empty folder' : `${Number(item.log_files || 0).toLocaleString()} log file(s)`;
      appendStorageCandidateRow(logList, item.name, `${kind} · ${Number(item.files || 0).toLocaleString()} file(s) · ${formatStorageBytes(item.bytes)}`);
    });
  } else {
    const empty = document.createElement('span'); empty.className = 'storage-candidate-empty';
    empty.textContent = 'No empty or logs-only folders found.'; logList.appendChild(empty);
  }

  if (duplicateGroups.length) {
    duplicateGroups.forEach((group, index) => {
      const copies = group.duplicates || [];
      const toolNames = { rulest: 'RULEST', ranker: 'Rule Ranker', concentrator: 'Concentrator', rulestripper: 'Rulestripper', minimizer: 'Rule Minimizer' };
      const inputNames = (group.inputs || []).map((item) => item.name).filter(Boolean);
      const inputSummary = inputNames.length ? inputNames.join(' + ') : 'Recorded input datasets';
      const sourceNote = group.manifest_source === 'inferred from saved command log' ? ' · inferred from saved command log' : '';
      appendStorageCandidateRow(
        duplicateList,
        `${toolNames[group.tool] || group.tool} · ${group.mode} · keep ${group.keep}`,
        `Same input data: ${inputSummary} · remove: ${copies.join(', ')} · ${formatStorageBytes(group.reclaimable_bytes)} recoverable${sourceNote}`
      );
    });
  } else {
    const empty = document.createElement('span'); empty.className = 'storage-candidate-empty';
    empty.textContent = 'No repeated runs with matching input datasets were identified.'; duplicateList.appendChild(empty);
  }

  const skipped = Number(data.skipped_unsafe_directories || 0);
  const scanText = `Scanned ${Number(data.scanned_directories || 0).toLocaleString()} run folder(s). Found ${Number(data.log_only_count || 0).toLocaleString()} empty/log-only folder(s) and ${duplicateCount.toLocaleString()} older run(s) across ${Number(data.duplicate_group_count || 0).toLocaleString()} repeated-dataset group(s). Groups match tool, workflow and ordered input contents; output files and run settings may differ.`;
  summary.textContent = skipped ? `${scanText} Skipped ${skipped.toLocaleString()} folder(s) containing links, special files or unreadable/changing content.` : scanText;
  results.hidden = false;
  const active = currentStatus === 'running' || currentStatus === 'stopping';
  $('delete-log-only-directories').disabled = active || !logItems.length;
  $('delete-duplicate-directories').disabled = active || duplicateCount === 0;
}
async function scanRunStorage() {
  const button = $('scan-run-storage');
  const feedback = $('storage-scan-feedback');
  if (!button || button.disabled) return;
  button.disabled = true;
  button.textContent = 'Matching input datasets…';
  if (feedback) feedback.textContent = 'Checking recorded input fingerprints and inferring older runs from saved command logs where possible. Large input files may take a while to hash.';
  $('storage-scan-results').hidden = true;
  try {
    const result = await apiPost('/api/run-storage/scan', {});
    renderRunStorageScan(result);
    if (feedback) feedback.textContent = 'Scan complete. Review the folders below before choosing a cleanup action.';
    await loadRunStorageSummary();
    await loadStorageIntelligence(true);
  } catch (error) {
    lastRunStorageScan = null;
    if (feedback) feedback.textContent = `Run storage scan failed: ${error.message}`;
    toast(`Could not scan run storage: ${error.message}`, true);
  } finally {
    button.textContent = '⌕ Scan run folders';
    button.disabled = currentStatus === 'running' || currentStatus === 'stopping';
  }
}
async function deleteLogOnlyRunDirectories() {
  const count = Number(lastRunStorageScan?.log_only_count || 0);
  const button = $('delete-log-only-directories');
  if (!button || button.disabled || !count) return;
  if (!window.confirm(`Permanently delete ${count} empty/log-only run folder(s)? Only folders containing no files or regular .log files will be removed. Folders with outputs or other files are preserved.`)) return;
  button.disabled = true;
  $('storage-scan-feedback').textContent = 'Rechecking and deleting empty/log-only folders…';
  try {
    const result = await apiPost('/api/run-storage/delete-log-only', {});
    lastRunStorageScan = null;
    $('storage-scan-results').hidden = true;
    $('storage-scan-summary').textContent = 'Run a new scan to review remaining cleanup candidates.';
    $('storage-scan-feedback').textContent = `Cleanup complete. Deleted ${Number(result.deleted_directories || 0).toLocaleString()} empty/log-only folder(s). ${result.failures?.length ? `Some folders were skipped: ${result.failures.join('; ')}` : ''}`;
    toast(`Deleted ${result.deleted_directories || 0} empty/log-only folder(s).`);
    await pollStatus();
    await loadRunStorageSummary();
    await loadStorageIntelligence(true);
  } catch (error) {
    $('storage-scan-feedback').textContent = `Could not delete log-only folders: ${error.message}`;
    toast(error.message, true);
    await loadRunStorageSummary();
  }
}
async function deleteDuplicateRunDirectories() {
  const groups = Number(lastRunStorageScan?.duplicate_group_count || 0);
  const copies = Number(lastRunStorageScan?.duplicate_directories || 0);
  const reclaimable = formatStorageBytes(lastRunStorageScan?.duplicate_reclaimable_bytes || 0);
  const button = $('delete-duplicate-directories');
  if (!button || button.disabled || !copies) return;
  if (!window.confirm(`Delete ${copies} older run folder(s) from ${groups} repeated-dataset group(s)? Each group uses the same tool, workflow and ordered input file contents. Output files and run settings may differ, so the removed runs may contain different results. RULEOPS will keep the currently selected run when it belongs to a group; otherwise it keeps the most recently modified run. Estimated space reclaimed: ${reclaimable}. This cannot be undone.`)) return;
  button.disabled = true;
  $('storage-scan-feedback').textContent = 'Rechecking input dataset fingerprints and removing selected older runs…';
  try {
    const result = await apiPost('/api/run-storage/delete-duplicates', {});
    lastRunStorageScan = null;
    $('storage-scan-results').hidden = true;
    $('storage-scan-summary').textContent = 'Run a new scan to review remaining cleanup candidates.';
    $('storage-scan-feedback').textContent = `Cleanup complete. Deleted ${Number(result.deleted_directories || 0).toLocaleString()} older repeated-dataset run folder(s); retained ${Number((result.retained_directories || []).length).toLocaleString()} representative folder(s). ${result.failures?.length ? `Some folders were skipped: ${result.failures.join('; ')}` : ''}`;
    toast(`Deleted ${result.deleted_directories || 0} older repeated-dataset run folder(s).`);
    await pollStatus();
    await loadRunStorageSummary();
    await loadStorageIntelligence(true);
  } catch (error) {
    $('storage-scan-feedback').textContent = `Could not remove older repeated-dataset runs: ${error.message}`;
    toast(error.message, true);
    await loadRunStorageSummary();
  }
}

function libraryDownloadUrl(item) {
  const params = new URLSearchParams({ category: item.category, asset_id: item.id });
  return `/api/library/download?${params.toString()}`;
}
function createLibraryDownloadLink(item) {
  const link = document.createElement('a');
  link.className = 'library-file-download';
  link.href = libraryDownloadUrl(item);
  link.title = `Download ${item.name}`;
  link.setAttribute('aria-label', `Download ${item.name}`);
  link.setAttribute('download', item.name);
  link.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m0 0 4.5-4.5M12 15l-4.5-4.5M4 19v2h16v-2"/></svg>';
  return link;
}
function createSearchResultDownloadLink(item) {
  if (item.source !== 'run') return createLibraryDownloadLink(item);
  const params = new URLSearchParams({ run_id: item.run_id, relative_path: item.relative_path });
  const link = document.createElement('a');
  link.className = 'library-file-download';
  link.href = `/api/run-storage/file-download?${params.toString()}`;
  link.title = `Download ${item.name}`;
  link.setAttribute('aria-label', `Download ${item.name}`);
  link.setAttribute('download', item.name);
  link.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m0 0 4.5-4.5M12 15l-4.5-4.5M4 19v2h16v-2"/></svg>';
  return link;
}
function renderLibrarySearchResults(data) {
  const results = $('library-search-results');
  const summary = $('library-search-summary');
  results.replaceChildren();
  const items = data.results || [];
  summary.textContent = `${Number(data.total || 0).toLocaleString()} file(s) matched filename “${data.query}” across the reusable library and run/work folders. Full paths are shown below.${data.truncated ? ' Showing the first 300 matches; refine the filename to narrow the results.' : ''}`;
  results.hidden = false;
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'library-empty-state';
    empty.textContent = 'No files in the reusable library or work folders match that filename.';
    results.appendChild(empty);
    return;
  }
  items.forEach((item) => {
    const row = document.createElement('article');
    row.className = 'library-file-result';
    const copy = document.createElement('div');
    copy.className = 'library-file-copy';
    const name = document.createElement('b');
    name.textContent = item.name;
    const path = document.createElement('small');
    path.textContent = item.path;
    const meta = document.createElement('small');
    meta.className = 'library-file-meta';
    const sourceLabel = item.source === 'run'
      ? `WORK FOLDER · ${item.run_id}`
      : (item.category === 'wordlists' ? 'LIBRARY WORDLIST' : 'LIBRARY RULE FILE');
    meta.textContent = `${sourceLabel} · ${formatStorageBytes(item.size)} · modified ${new Date(Number(item.modified) * 1000).toLocaleString()}`;
    copy.append(name, path, meta);
    row.append(copy, createSearchResultDownloadLink(item));
    results.appendChild(row);
  });
}
async function searchLibraryFiles() {
  const input = $('library-search-query');
  const query = input.value.trim();
  const summary = $('library-search-summary');
  const results = $('library-search-results');
  if (!query) {
    summary.textContent = 'Enter a filename to search the reusable library and completed work folders.';
    results.replaceChildren();
    results.hidden = true;
    return;
  }
  const requestId = ++librarySearchRequestId;
  $('library-search-submit').disabled = true;
  summary.textContent = 'Searching library filenames…';
  try {
    const response = await fetch(`/api/library/search?q=${encodeURIComponent(query)}`, { cache: 'no-store' });
    const data = await response.json();
    if (response.status === 401) { window.location.replace('/'); return; }
    if (!response.ok) throw new Error(data.error || 'Library search failed.');
    if (requestId === librarySearchRequestId && query === $('library-search-query').value.trim()) renderLibrarySearchResults(data);
  } catch (error) {
    if (requestId !== librarySearchRequestId) return;
    summary.textContent = `Library search failed: ${error.message}`;
    results.hidden = true;
    toast(error.message, true);
  } finally {
    if (requestId === librarySearchRequestId) $('library-search-submit').disabled = false;
  }
}
function appendLibraryDuplicateFile(container, file) {
  const row = document.createElement('label');
  row.className = 'library-duplicate-file';
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.className = 'library-duplicate-checkbox';
  checkbox.dataset.source = file.source || 'library';
  if (file.source === 'run') {
    checkbox.dataset.runId = file.run_id || '';
    checkbox.dataset.relativePath = file.relative_path || file.id || '';
  } else {
    checkbox.dataset.category = file.category || '';
    checkbox.dataset.assetId = file.id || '';
  }
  checkbox.checked = !!file.suggest_delete && file.deletable !== false;
  checkbox.disabled = file.deletable === false;
  if (checkbox.disabled) checkbox.title = file.protected_reason || 'This file is protected.';
  checkbox.addEventListener('change', updateLibraryDeleteSelection);
  const copy = document.createElement('div');
  copy.className = 'library-file-copy';
  const name = document.createElement('b');
  name.textContent = file.name;
  const path = document.createElement('small');
  path.textContent = file.path;
  const match = document.createElement('small');
  match.className = 'library-file-meta';
  const status = file.deletable === false
    ? ` · protected: ${file.protected_reason || 'not safe to delete'}`
    : file.suggest_delete ? ' · suggested redundant copy' : ' · keep/review manually';
  match.textContent = `${file.match || 'Potential duplicate'} · ${formatStorageBytes(file.size)}${status}`;
  copy.append(name, path, match);
  row.append(checkbox, copy, createSearchResultDownloadLink(file));
  container.appendChild(row);
}
function updateLibraryDeleteSelection() {
  const selected = document.querySelectorAll('.library-duplicate-checkbox:checked');
  const count = selected.length;
  $('library-delete-selection-count').textContent = `${count.toLocaleString()} file(s) selected for deletion`;
  $('delete-selected-library-files').disabled = count === 0 || currentStatus === 'running' || currentStatus === 'stopping';
}
function renderLibraryDuplicateScan(data) {
  lastLibraryDuplicateScan = data;
  const container = $('library-duplicate-results');
  container.replaceChildren();
  const groups = data.duplicate_groups || [];
  $('library-duplicate-count').textContent = Number(data.duplicate_group_count || 0).toLocaleString();
  $('library-duplicate-summary').textContent = `Scanned ${Number(data.scanned_library_files || 0).toLocaleString()} reusable library file(s) and ${Number(data.scanned_work_files || 0).toLocaleString()} work-folder file(s). Found ${groups.length.toLocaleString()} potential duplicate group(s); ${Number(data.suggested_delete_count || 0).toLocaleString()} byte-identical redundant copies are suggested for removal. Same-name files with different contents remain unchecked for manual review.`;
  container.hidden = false;
  if (!groups.length) {
    const empty = document.createElement('div');
    empty.className = 'library-empty-state';
    empty.textContent = 'No same-name or identical-content files were found in the reusable library or completed work folders.';
    container.appendChild(empty);
  } else {
    groups.forEach((group, index) => {
      const card = document.createElement('section');
      card.className = 'library-duplicate-group';
      const head = document.createElement('div');
      head.className = 'library-duplicate-group-head';
      const title = document.createElement('b');
      const first = (group.files || [])[0];
      title.textContent = `Group ${index + 1} · ${first?.name || group.category}`;
      const reason = document.createElement('span');
      reason.className = 'library-duplicate-reason';
      reason.textContent = (group.reasons || []).join(' + ');
      head.append(title, reason);
      card.appendChild(head);
      (group.files || []).forEach((file) => appendLibraryDuplicateFile(card, file));
      container.appendChild(card);
    });
  }
  updateLibraryDeleteSelection();
}
async function scanLibraryDuplicates() {
  const button = $('scan-library-duplicates');
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = 'Scanning library + work folders…';
  $('library-cleanup-feedback').textContent = 'Scanning reusable library files and completed work folders. Library checksums are cached; work-folder files are hashed when their filenames collide.';
  $('library-duplicate-results').hidden = true;
  try {
    const result = await apiPost('/api/library/scan-duplicates', {});
    renderLibraryDuplicateScan(result);
    $('library-cleanup-feedback').textContent = 'Scan complete. Review each group and uncheck any file you want to keep before deleting selected files.';
    await loadStorageIntelligence(true);
  } catch (error) {
    lastLibraryDuplicateScan = null;
    $('library-duplicate-summary').textContent = `Library duplicate scan failed: ${error.message}`;
    $('library-cleanup-feedback').textContent = error.message;
    toast(error.message, true);
  } finally {
    button.textContent = '⌕ Scan library + work duplicates';
    button.disabled = currentStatus === 'running' || currentStatus === 'stopping';
  }
}
async function deleteSelectedLibraryFiles() {
  const selected = Array.from(document.querySelectorAll('.library-duplicate-checkbox:checked'));
  if (!selected.length || $('delete-selected-library-files').disabled) return;
  const items = selected.map((checkbox) => checkbox.dataset.source === 'run'
    ? { source: 'run', run_id: checkbox.dataset.runId, relative_path: checkbox.dataset.relativePath }
    : { source: 'library', category: checkbox.dataset.category, asset_id: checkbox.dataset.assetId });
  const names = selected.map((checkbox) => checkbox.closest('.library-duplicate-file')?.querySelector('.library-file-copy small')?.textContent || checkbox.dataset.assetId || checkbox.dataset.relativePath);
  const preview = names.slice(0, 6).join(', ') + (names.length > 6 ? ` and ${names.length - 6} more` : '');
  if (!window.confirm(`Permanently delete ${items.length} selected duplicate file(s) from the library/work folders?\n\n${preview}\n\nFiles mounted in an input and the currently selected run folder are protected. At least one same-name file and one byte-identical copy must remain. This action cannot be undone.`)) return;
  const button = $('delete-selected-library-files');
  button.disabled = true;
  $('library-cleanup-feedback').textContent = 'Rechecking selected library/work files, active inputs and surviving duplicate representatives…';
  try {
    const result = await apiPost('/api/library/delete-selected', { items });
    const skipped = (result.failures || []).length;
    $('library-cleanup-feedback').textContent = `Deleted ${Number(result.deleted_count || 0).toLocaleString()} selected file(s) from library/work folders.${skipped ? ` ${skipped} file(s) could not be deleted; run another scan to inspect them.` : ''} Run another scan to review what remains.`;
    $('library-duplicate-results').hidden = true;
    $('library-duplicate-summary').textContent = 'Library changed. Run a new scan to review remaining duplicate candidates.';
    $('library-duplicate-count').textContent = '0';
    $('library-delete-selection-count').textContent = '0 files selected';
    await loadStorageIntelligence(true);
    lastLibraryDuplicateScan = null;
    toast(`Deleted ${result.deleted_count || 0} duplicate file(s).`);
    const query = $('library-search-query').value.trim();
    if (query) await searchLibraryFiles();
    await refreshLibraryMenus();
  } catch (error) {
    $('library-cleanup-feedback').textContent = `Could not delete selected duplicate files: ${error.message}`;
    toast(error.message, true);
    if (/changed|scan again|no longer exist/i.test(error.message)) await scanLibraryDuplicates();
  } finally {
    updateLibraryDeleteSelection();
  }
}
function configureRunStorageLibrary() {
  const refreshIntelligence = $('storage-intelligence-refresh');
  if (refreshIntelligence) refreshIntelligence.addEventListener('click', () => loadStorageIntelligence(true));
  const form = $('library-search-form');
  if (!form) return;
  form.addEventListener('submit', (event) => { event.preventDefault(); searchLibraryFiles(); });
  $('library-search-clear').addEventListener('click', () => {
    if (librarySearchTimer) clearTimeout(librarySearchTimer);
    librarySearchRequestId += 1;
    $('library-search-submit').disabled = false;
    $('library-search-query').value = '';
    $('library-search-results').replaceChildren();
    $('library-search-results').hidden = true;
    $('library-search-summary').textContent = 'Enter a filename to search the reusable library and completed work folders.';
    $('library-search-query').focus();
  });
  $('library-search-query').addEventListener('input', () => {
    if (librarySearchTimer) clearTimeout(librarySearchTimer);
    const query = $('library-search-query').value.trim();
    if (!query) {
      $('library-search-results').replaceChildren();
      $('library-search-results').hidden = true;
      $('library-search-summary').textContent = 'Enter a filename to search the reusable library and completed work folders.';
      return;
    }
    librarySearchTimer = setTimeout(searchLibraryFiles, 320);
  });
  $('scan-library-duplicates').addEventListener('click', scanLibraryDuplicates);
  $('delete-selected-library-files').addEventListener('click', deleteSelectedLibraryFiles);
}

function renderStatus(data) {
  currentStatus = data.status;
  const running = data.status === 'running' || data.status === 'stopping';
  const libraryScanButton = $('scan-library-duplicates');
  const libraryDeleteButton = $('delete-selected-library-files');
  if (libraryScanButton) libraryScanButton.disabled = running;
  if (libraryDeleteButton && running) libraryDeleteButton.disabled = true;
  else if (libraryDeleteButton) updateLibraryDeleteSelection();
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
  ['rulest', 'ranker', 'concentrator', 'rulestripper', 'minimizer'].forEach((tool) => renderToolMetrics(tool, data));
  renderOutputs(data.outputs || [], data.tool || 'rulest');
  const storageView = $('system-view');
  if (storageView && !storageView.hidden) {
    if (Date.now() - lastStorageSummaryAt > 5000) loadRunStorageSummary();
    const storageState = $('storage-engine-state');
    const storageNote = $('storage-engine-note');
    const deleteButton = $('delete-run-directories');
    if (storageState) storageState.textContent = running ? (data.status === 'stopping' ? 'STOPPING' : paused ? 'PAUSED' : 'RUNNING') : 'READY';
    if (storageNote) storageNote.textContent = running ? 'Cleanup is locked while a job is active' : 'No active run detected';
    if (deleteButton && running) deleteButton.disabled = true;
    if (running) {
      ['scan-run-storage', 'delete-log-only-directories', 'delete-duplicate-directories'].forEach((id) => { const button = $(id); if (button) button.disabled = true; });
    }
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
async function apiGet(path) {
  const response = await fetch(path, { method: 'GET', headers: { 'X-CSRF-Token': csrfToken } });
  const data = await response.json();
  if (response.status === 401 && data.auth_required) { window.location.replace('/'); throw new Error('Your session expired. Please sign in again.'); }
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  if (data.csrf_token) csrfToken = data.csrf_token;
  return data;
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
  if (config.topn_seeds) {
    if (typeof topnPcfgProfilePath !== 'undefined' && topnPcfgProfilePath) config.topn_profile_path = topnPcfgProfilePath;
    else if (typeof topnPcfgProfile !== 'undefined' && topnPcfgProfile) config.topn_profile_json = topnPcfgProfile;
  }
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
    rulest: 'RULEST',
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
      profile: $('opt_profile').checked,
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

    const breadcrumbLabels = {
      '#workspace': 'RULEST', '#tuning': 'Engine tuning',
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
    setActiveTool('rulest');
    navigateTo('#workspace');
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
  $('scan-run-storage').addEventListener('click', scanRunStorage);
  $('delete-log-only-directories').addEventListener('click', deleteLogOnlyRunDirectories);
  $('delete-duplicate-directories').addEventListener('click', deleteDuplicateRunDirectories);
  configureRunStorageLibrary();
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
    }
    const labels = {
      '#workspace': 'RULEST', '#tuning': 'Engine tuning', '#gpu-diagnostic': 'GPU diagnostics',
      '#ranker': 'Rule Ranker', '#concentrator': 'Concentrator', '#rulestripper': 'Rulestripper', '#minimizer': 'Rule Minimizer', '#live-log': 'Live activity', '#run-storage': 'Run storage', '#about': 'About',
    };
    const breadcrumb = document.querySelector('.breadcrumb strong');
    if (breadcrumb) breadcrumb.textContent = labels[wanted] || (activeTool === 'ranker' ? 'Rule Ranker' : activeTool === 'concentrator' ? 'Concentrator' : activeTool === 'rulestripper' ? 'Rulestripper' : activeTool === 'minimizer' ? 'Rule Minimizer' : 'RULEST');
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

/* ---- Top-N Seed Generator (lightweight Stage S helper) -------------------- */

// Parsed `ruleops.pcfg-profile.v1` report, if the user attached one (upload
// or saved reports/ dropdown). Sent with /api/tools/topn-seeds and with
// the main rulest run as topn_profile_json / topn_profile_path.
let topnPcfgProfile = null;
let topnPcfgProfilePath = null; // project-relative path when chosen from reports/

function wireTopNPcfgProfileUpload() {
  const input = document.getElementById('topn-pcfg-profile-file');
  const select = document.getElementById('topn-pcfg-profile-select');
  const stateEl = document.getElementById('topn-pcfg-profile-state');
  if (!stateEl) return;

  async function loadSavedProfiles() {
    if (!select) return;
    try {
      const data = await apiGet('/api/tools/pcfg-profiles');
      const profiles = (data && data.profiles) || [];
      const current = select.value;
      select.innerHTML = '<option value="">Choose saved PCFG profile…</option>';
      profiles.forEach((p) => {
        const opt = document.createElement('option');
        opt.value = p.id;
        const entries = p.profiled_entries ? ` · ${Number(p.profiled_entries).toLocaleString()} entries` : '';
        opt.textContent = `${p.name}${entries}`;
        opt.dataset.path = p.path || '';
        select.appendChild(opt);
      });
      if (current) select.value = current;
    } catch (error) {
      // Non-fatal: upload still works without the dropdown.
    }
  }

  if (input) {
    input.addEventListener('change', async () => {
      const file = input.files && input.files[0];
      if (!file) {
        if (!topnPcfgProfilePath) {
          topnPcfgProfile = null;
          stateEl.textContent = 'No PCFG profile attached';
        }
        return;
      }
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        if (parsed && parsed.schema && String(parsed.schema).indexOf('pcfg-profile') === -1) {
          toast('That JSON does not look like a run_pcfg_profile.py report', true);
        }
        topnPcfgProfile = parsed;
        topnPcfgProfilePath = null;
        if (select) select.value = '';
        stateEl.textContent = `✓ ${file.name} attached (upload)`;
      } catch (error) {
        topnPcfgProfile = null;
        topnPcfgProfilePath = null;
        input.value = '';
        stateEl.textContent = 'No PCFG profile attached';
        toast('Could not parse that file as JSON', true);
      }
    });
  }

  if (select) {
    select.addEventListener('change', async () => {
      const id = select.value;
      if (!id) {
        topnPcfgProfile = null;
        topnPcfgProfilePath = null;
        stateEl.textContent = 'No PCFG profile attached';
        return;
      }
      try {
        const data = await apiGet(`/api/tools/pcfg-profiles/load?id=${encodeURIComponent(id)}`);
        topnPcfgProfile = data.profile;
        topnPcfgProfilePath = data.path || null;
        if (input) input.value = '';
        const entries = data.profile && data.profile.input
          ? Number(data.profile.input.profiled_entries || 0).toLocaleString()
          : '?';
        stateEl.textContent = `✓ ${id} (saved · ${entries} entries)`;
      } catch (error) {
        topnPcfgProfile = null;
        topnPcfgProfilePath = null;
        select.value = '';
        stateEl.textContent = 'No PCFG profile attached';
        toast(error.message || 'Could not load saved profile', true);
      }
    });
  }

  loadSavedProfiles();
}

function wireTopNSeedGenerator() {
  const btn = document.getElementById('topn-generate-btn');
  const stateEl = document.getElementById('topn-seed-state');
  if (!btn || !stateEl) return;

  btn.addEventListener('click', async () => {
    const topN = parseInt((document.getElementById('topn_n') || {}).value || '400000', 10);
    const maxSeeds = parseInt((document.getElementById('topn_max_seeds') || {}).value || '150000', 10);
    const complementary = !!(document.getElementById('topn_complementary') || {}).checked;
    const adaptive = (document.getElementById('topn_adaptive') || {}).checked !== false;

    if (!Number.isFinite(topN) || (topN !== 0 && topN < 10000)) {
      toast('Top-N must be 0 (unlimited) or at least 10 000', true);
      return;
    }
    if (!Number.isFinite(maxSeeds) || maxSeeds < 0) {
      toast('Max seeds must be >= 0 (0 = unlimited)', true);
      return;
    }

    btn.disabled = true;
    stateEl.textContent = 'Generating Top-N seeds…';
    try {
      const body = {
        top_n: topN,
        max_seeds: maxSeeds,
        complementary: complementary,
        adaptive: adaptive,
      };
      if (topnPcfgProfile) body.pcfg_profile = topnPcfgProfile;

      const data = await apiPost('/api/tools/topn-seeds', body);
      let summaryNote = '';
      if (data.pcfg_profile_applied && data.pcfg_profile_summary) {
        const ps = data.pcfg_profile_summary;
        summaryNote = ` · profile: digits ${(ps.digit_share * 100).toFixed(1)}% · symbols ${(ps.symbol_share * 100).toFixed(1)}% · uppercase ${(ps.uppercase_share * 100).toFixed(1)}%`;
      }
      stateEl.textContent = `✓ ${data.seeds_generated.toLocaleString()} seeds · ${data.output_name || 'topn_seeds.rule'}${summaryNote}`;
      if (data.registered_as_seed) {
        const seedState = document.getElementById('seed-state');
        if (seedState) seedState.textContent = `✓ ${data.output_name} · auto-loaded from Top-N generator`;
      }
      toast(`Generated ${data.seeds_generated.toLocaleString()} Top-N seeds`);
    } catch (error) {
      stateEl.textContent = 'Generation failed';
      toast(error.message || 'Top-N seed generation failed', true);
    } finally {
      btn.disabled = false;
    }
  });
}

document.addEventListener('DOMContentLoaded', wireTopNPcfgProfileUpload);
document.addEventListener('DOMContentLoaded', wireTopNSeedGenerator);

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
