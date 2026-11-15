// ----------------------------------------------
// Email Rule Extractor - Client Side Logic
// Supports: plain email, hash:email, trailing digits extraction, domain filter
// Generates Hashcat rule strings: $d$i$g$i$t$s$@$d$o$m$a$i$n
// ----------------------------------------------
(function() {
  let currentFileContent = null;
  let currentFileName = null;
  let lastExtractedRules = [];     // store { pattern, rule, count, example }
  let rawRuleLines = [];           // plain rule strings for download
  let metricStatus = 'idle';
  let metricStage = 'Waiting for a run';
  let metricStartedAt = null;
  let metricElapsedSeconds = 0;
  let metricOutputFiles = 0;
  let metricProgressCompleted = 0;
  let metricProgressTotal = 0;
  let metricTimer = null;

  // DOM elements
  const fileInput = document.getElementById('email-file');
  const uploadArea = document.getElementById('email-upload-area');
  const selectBtn = document.getElementById('select-file-btn');
  const fileInfoDiv = document.getElementById('email-file-info');
  const statusDiv = document.getElementById('status-messages');
  const extractBtn = document.getElementById('extract-btn');
  const clearBtn = document.getElementById('clear-btn');
  const resultsSection = document.getElementById('results-section');
  const resultsContent = document.getElementById('results-content');
  const domainFilterOptions = document.getElementById('domain-filter-options');
  const domainFilterAllButton = document.getElementById('domain-filter-all');
  const domainFilterTotal = document.getElementById('domain-filter-total');
  const domainFilterSearch = document.getElementById('domain-filter-search');
  const domainFilterSummary = document.getElementById('domain-filter-summary');
  let domainCounts = new Map();
  let selectedDomains = new Set();
  let allDomainsSelected = true;
  const extractDigitsCheck = document.getElementById('extract-digits');
  const downloadBtn = document.getElementById('download-rules-btn');

  const emailMetricEls = {
    status: document.getElementById('email-metric-status'),
    note: document.getElementById('email-metric-note'),
    dot: document.getElementById('email-metric-dot'),
    stage: document.getElementById('email-metric-stage'),
    elapsed: document.getElementById('email-metric-elapsed'),
    outputs: document.getElementById('email-metric-outputs'),
    eta: document.getElementById('email-metric-eta'),
    etaNote: document.getElementById('email-metric-eta-note'),
  };

  function formatMetricTime(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const remainder = total % 60;
    return hours
      ? `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`
      : `${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`;
  }

  function renderEmailMetrics() {
    const statusLabels = { idle: 'Idle', running: 'Running', completed: 'Completed', failed: 'Failed' };
    const notes = {
      idle: currentFileContent ? 'Ready to extract' : 'Ready to configure',
      running: 'Analyzing email patterns in this browser',
      completed: rawRuleLines.length ? 'Extraction finished · rules ready to download' : 'Extraction finished · no matching patterns',
      failed: 'Check the extraction message below',
    };
    if (emailMetricEls.status) emailMetricEls.status.textContent = statusLabels[metricStatus] || 'Idle';
    if (emailMetricEls.note) emailMetricEls.note.textContent = notes[metricStatus] || notes.idle;
    if (emailMetricEls.dot) emailMetricEls.dot.dataset.state = metricStatus;
    if (emailMetricEls.stage) emailMetricEls.stage.textContent = metricStage;
    if (emailMetricEls.stage) emailMetricEls.stage.title = metricStage;
    if (emailMetricEls.elapsed) {
      const current = metricStatus === 'running' && metricStartedAt != null
        ? (Date.now() - metricStartedAt) / 1000 : metricElapsedSeconds;
      emailMetricEls.elapsed.textContent = formatMetricTime(current);
    }
    if (emailMetricEls.outputs) emailMetricEls.outputs.textContent = String(metricOutputFiles);

    if (emailMetricEls.eta && emailMetricEls.etaNote) {
      if (metricStatus === 'completed') {
        emailMetricEls.eta.textContent = 'Done';
        emailMetricEls.etaNote.textContent = 'Extraction completed';
      } else if (metricStatus === 'failed') {
        emailMetricEls.eta.textContent = '—';
        emailMetricEls.etaNote.textContent = 'Estimate unavailable';
      } else if (metricStatus !== 'running') {
        emailMetricEls.eta.textContent = '—';
        emailMetricEls.etaNote.textContent = 'Available during extraction';
      } else {
        const elapsed = metricStartedAt == null ? 0 : (Date.now() - metricStartedAt) / 1000;
        const fraction = metricProgressTotal > 0 ? metricProgressCompleted / metricProgressTotal : 0;
        if (fraction >= 0.999) {
          emailMetricEls.eta.textContent = 'Finishing';
          emailMetricEls.etaNote.textContent = 'Finalizing extracted patterns';
        } else if (metricProgressCompleted > 0 && fraction >= 0.015 && elapsed >= 2.5) {
          const remaining = elapsed * (1 - fraction) / fraction;
          emailMetricEls.eta.textContent = formatMetricTime(remaining);
          emailMetricEls.etaNote.textContent = `${Math.round(fraction * 100)}% of input lines · live estimate`;
        } else {
          emailMetricEls.eta.textContent = 'Estimating…';
          emailMetricEls.etaNote.textContent = metricProgressTotal > 0
            ? `${metricProgressCompleted.toLocaleString()} / ${metricProgressTotal.toLocaleString()} lines processed`
            : 'Preparing input';
        }
      }
    }
  }

  function setEmailMetricState(status, stage, { resetElapsed = false } = {}) {
    metricStatus = status;
    metricStage = stage;
    if (resetElapsed) {
      metricElapsedSeconds = 0;
      metricStartedAt = null;
    }
    if (status === 'running') {
      metricStartedAt = Date.now();
      metricElapsedSeconds = 0;
      if (metricTimer) clearInterval(metricTimer);
      metricTimer = setInterval(renderEmailMetrics, 1000);
    } else {
      if (metricStartedAt != null) metricElapsedSeconds = (Date.now() - metricStartedAt) / 1000;
      metricStartedAt = null;
      if (metricTimer) clearInterval(metricTimer);
      metricTimer = null;
    }
    renderEmailMetrics();
  }

  // Helper: show status message
  function showStatus(msg, type = 'info') {
    const className = type === 'error' ? 's-err' : (type === 'success' ? 's-ok' : 's-inf');
    statusDiv.innerHTML = `<div class="${className}" style="margin-bottom:0.75rem">${escapeHtml(msg)}</div>`;
    setTimeout(() => {
      if (statusDiv.innerHTML.includes(msg)) statusDiv.innerHTML = '';
    }, 4000);
  }

  function escapeHtml(str) { return str.replace(/[&<>]/g, function(m){if(m==='&') return '&'; if(m==='<') return '<'; if(m==='>') return '>'; return m;}); }

  // Parse email from line: supports "hash:email" and plain email
  function extractEmailFromLine(line) {
    let trimmed = line.trim();
    if (!trimmed) return null;
    // if contains colon and after colon there is '@', treat as hash:email
    if (trimmed.includes(':')) {
      const parts = trimmed.split(':');
      for (let i = parts.length-1; i >= 0; i--) {
        if (parts[i].includes('@')) {
          return parts[i].trim();
        }
      }
    }
    // plain email check
    if (trimmed.includes('@')) return trimmed;
    return null;
  }

  // validate email structure, return { localPart, domain } or null
  function parseEmail(emailStr) {
    const atIndex = emailStr.lastIndexOf('@');
    if (atIndex === -1) return null;
    const localPart = emailStr.substring(0, atIndex);
    const domain = emailStr.substring(atIndex+1).toLowerCase();
    if (!localPart || !domain) return null;
    // basic domain validation
    if (!domain.includes('.') || domain.length < 3) return null;
    return { localPart, domain };
  }

  // Generate Hashcat rule from a string: each character prefixed with '$'
  function stringToHashcatRule(str) {
    let rule = '';
    for (let i = 0; i < str.length; i++) {
      rule += '$' + str[i];
    }
    return rule;
  }

  function collectDomainCounts(content) {
    const counts = new Map();
    for (const rawLine of content.split(/\r?\n/)) {
      const emailAddr = extractEmailFromLine(rawLine);
      if (!emailAddr) continue;
      const parsed = parseEmail(emailAddr);
      if (!parsed) continue;
      counts.set(parsed.domain, (counts.get(parsed.domain) || 0) + 1);
    }
    return counts;
  }

  function renderDomainFilters() {
    domainFilterOptions.innerHTML = '';
    const entries = Array.from(domainCounts.entries()).sort((a, b) => {
      return b[1] - a[1] || a[0].localeCompare(b[0]);
    });
    const totalEmails = entries.reduce((sum, [, count]) => sum + count, 0);

    domainFilterAllButton.disabled = entries.length === 0;
    domainFilterAllButton.setAttribute('aria-pressed', String(allDomainsSelected));
    domainFilterTotal.textContent = totalEmails.toLocaleString();
    domainFilterSearch.hidden = entries.length <= 8;

    const includedEmailCount = allDomainsSelected
      ? totalEmails
      : entries.reduce((sum, [domain, count]) => sum + (selectedDomains.has(domain) ? count : 0), 0);
    const includedDomainCount = allDomainsSelected ? entries.length : selectedDomains.size;
    if (!entries.length) {
      domainFilterSummary.textContent = 'No valid email domains found';
      const empty = document.createElement('span');
      empty.className = 'domain-filter-empty';
      empty.textContent = currentFileContent
        ? 'No valid email domains found in this file.'
        : 'Upload an email list to see domain groups.';
      domainFilterOptions.appendChild(empty);
      return;
    }

    domainFilterSummary.textContent = allDomainsSelected
      ? `All ${entries.length.toLocaleString()} domains · ${totalEmails.toLocaleString()} emails included`
      : `${includedDomainCount.toLocaleString()} of ${entries.length.toLocaleString()} domains · ${includedEmailCount.toLocaleString()} emails included`;

    const query = domainFilterSearch.value.trim().toLowerCase();
    const visibleEntries = query
      ? entries.filter(([domain]) => domain.includes(query))
      : entries;

    if (!visibleEntries.length) {
      const empty = document.createElement('span');
      empty.className = 'domain-filter-empty';
      empty.textContent = `No domains match “${domainFilterSearch.value.trim()}”.`;
      domainFilterOptions.appendChild(empty);
      return;
    }

    for (const [domain, count] of visibleEntries) {
      const isSelected = allDomainsSelected || selectedDomains.has(domain);
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'domain-filter-chip';
      button.setAttribute('aria-pressed', String(isSelected));
      button.setAttribute('aria-label', `${domain}, ${count.toLocaleString()} email addresses, ${isSelected ? 'included' : 'excluded'}`);
      button.title = `${count.toLocaleString()} email address(es)`;
      button.appendChild(document.createTextNode(domain));

      const countBadge = document.createElement('span');
      countBadge.className = 'domain-count';
      countBadge.textContent = count.toLocaleString();
      countBadge.setAttribute('aria-hidden', 'true');
      button.appendChild(countBadge);

      button.addEventListener('click', () => {
        if (allDomainsSelected) {
          allDomainsSelected = false;
          selectedDomains.clear();
          selectedDomains.add(domain);
          renderDomainFilters();
          return;
        }
        if (selectedDomains.has(domain)) {
          selectedDomains.delete(domain);
        } else {
          selectedDomains.add(domain);
        }
        if (selectedDomains.size === entries.length) {
          allDomainsSelected = true;
          selectedDomains.clear();
        } else if (selectedDomains.size === 0) {
          // An empty selection is treated as All domains, never as an accidental zero-result filter.
          allDomainsSelected = true;
        }
        renderDomainFilters();
      });
      domainFilterOptions.appendChild(button);
    }
  }

  // Process file content and return pattern map: key = patternString (digits+domain OR local+domain)
  // returns Map with { pattern, count, examples, rule }
  async function processEmails(content, domainFilterSet, extractDigitsOnly, onProgress = () => {}) {
    const lines = content.split(/\r?\n/);
    const patternMap = new Map();
    const progressBatchSize = 2500;

    for (let index = 0; index < lines.length; index++) {
      const rawLine = lines[index];
      const emailAddr = extractEmailFromLine(rawLine);
      if (emailAddr) {
        const parsed = parseEmail(emailAddr);
        if (parsed) {
          const { localPart, domain } = parsed;
          if (domainFilterSet.size === 0 || domainFilterSet.has(domain)) {
            let patternValue = null;
            let displayPattern = null;

            if (extractDigitsOnly) {
              const matchDigits = localPart.match(/(\d+)$/);
              if (matchDigits) {
                patternValue = matchDigits[1] + '@' + domain;
                displayPattern = patternValue;
              }
            } else {
              patternValue = localPart + '@' + domain;
              displayPattern = patternValue;
            }

            if (patternValue) {
              if (patternMap.has(patternValue)) {
                const entry = patternMap.get(patternValue);
                entry.count++;
                if (entry.examples.length < 3 && !entry.examples.includes(rawLine)) {
                  entry.examples.push(rawLine);
                }
              } else {
                patternMap.set(patternValue, {
                  pattern: displayPattern,
                  count: 1,
                  examples: [rawLine],
                  rule: stringToHashcatRule(patternValue)
                });
              }
            }
          }
        }
      }

      const processed = index + 1;
      if (processed % progressBatchSize === 0 || processed === lines.length) {
        onProgress(processed, lines.length);
        if (processed < lines.length) {
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      }
    }
    if (lines.length === 0) onProgress(0, 0);
    return patternMap;
  }

  // Update UI after extraction
  function renderResults(patternMap) {
    if (!patternMap || patternMap.size === 0) {
      resultsContent.innerHTML = `<div class="s-inf">⚠️ No matching patterns found. Check domain filter, file format, or trailing digits condition.</div>`;
      resultsSection.style.display = 'block';
      rawRuleLines = [];
      return;
    }

    // Sort by frequency descending
    const sorted = Array.from(patternMap.values()).sort((a,b) => b.count - a.count);
    rawRuleLines = sorted.map(entry => entry.rule);

    // Build stats summary
    const totalUnique = sorted.length;
    const totalOccurrences = sorted.reduce((acc, e) => acc + e.count, 0);
    let html = `<div class="s-ok" style="margin-bottom:1rem">✅ Extracted ${totalUnique} unique pattern(s) from ${totalOccurrences} matching emails.</div>`;
    html += `<div style="max-width:100%; max-height:360px; overflow-y:auto; overflow-x:hidden; border:1px solid var(--b); border-radius:var(--rs); background:rgba(0,0,0,0.2);">`;
    html += `<table style="width:100%; table-layout:fixed; border-collapse:collapse; font-size:0.8rem;">`;
    html += `<thead><tr style="background:var(--sf2);"><th style="padding:8px; text-align:left;">Pattern</th><th style="padding:8px; width:80px;">Count</th><th style="padding:8px;">Example</th></tr></thead><tbody>`;
    for (const entry of sorted.slice(0, 100)) {
      const exampleShort = entry.examples[0]?.length > 45 ? entry.examples[0].substring(0,42)+'...' : entry.examples[0] || '—';
      html += `<tr style="border-bottom:1px solid var(--b);"><td style="padding:8px; font-family:monospace; color:var(--cyan);">${escapeHtml(entry.pattern)}</td><td style="padding:8px;">${entry.count}</td><td style="padding:8px; color:var(--t3); font-size:0.75rem;">${escapeHtml(exampleShort)}</td></tr>`;
    }
    if (sorted.length > 100) html += `<tr><td colspan="3" style="padding:10px; text-align:center; color:var(--t3);">+ ${sorted.length-100} more patterns</td></tr>`;
    html += `</tbody></table></div>`;
    html += `<div class="s-inf" style="margin-top:0.75rem; font-size:0.75rem;">💡 Rule format: each character prefixed with '$' (e.g., "123@gmail.com" → $1$2$3$@$g$m$a$i$l$.$c$o$m)</div>`;
    resultsContent.innerHTML = html;
    resultsSection.style.display = 'block';
  }

  // Main extraction trigger
  function runExtraction() {
    if (!currentFileContent) {
      showStatus('No file loaded. Please upload an email list first.', 'error');
      return;
    }

    // An empty selection means no domain filter; otherwise keep selected domains only.
    const domainSet = allDomainsSelected ? new Set() : new Set(selectedDomains);
    const extractDigitsOnly = extractDigitsCheck.checked;

    metricOutputFiles = 0;
    metricProgressCompleted = 0;
    metricProgressTotal = currentFileContent.split(/\r?\n/).length;
    extractBtn.disabled = true;
    setEmailMetricState('running', 'Analyzing email patterns');
    renderEmailMetrics();
    showStatus(`Processing ${currentFileName || 'file'}...`, 'info');
    // Yield before starting so the running state and ETA card paint immediately.
    setTimeout(async () => {
      try {
        const patternMap = await processEmails(currentFileContent, domainSet, extractDigitsOnly, (processed, total) => {
          metricProgressCompleted = processed;
          metricProgressTotal = total;
          renderEmailMetrics();
        });
        metricProgressCompleted = metricProgressTotal;
        renderResults(patternMap);
        metricOutputFiles = rawRuleLines.length ? 1 : 0;
        if (patternMap.size === 0) {
          setEmailMetricState('completed', 'No matching patterns found');
          showStatus('No patterns extracted. Try adjusting domain filter or disable "trailing digits only" if emails have no numeric suffix.', 'info');
        } else {
          setEmailMetricState('completed', `Extraction complete · ${patternMap.size.toLocaleString()} unique rules`);
          showStatus(`Extraction complete: ${patternMap.size} unique rules generated.`, 'success');
        }
      } catch (err) {
        console.error(err);
        setEmailMetricState('failed', 'Extraction failed');
        showStatus(`Extraction error: ${err.message}`, 'error');
      } finally {
        extractBtn.disabled = !currentFileContent;
      }
    }, 10);
  }

  // Download .rule file
  function downloadRules() {
    if (!rawRuleLines.length) {
      showStatus('No rules to download. Extract rules first.', 'error');
      return;
    }
    const content = rawRuleLines.join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (currentFileName ? currentFileName.replace(/\\.(txt|csv)$/i, '') : 'hashcat_rules') + '.rule';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    metricOutputFiles = 1;
    setEmailMetricState('completed', 'Rules file downloaded');
    showStatus(`Downloaded ${rawRuleLines.length} rules.`, 'success');
  }

  // Read file
  function readFile(file) {
    if (!file) return;
    metricOutputFiles = 0;
    const reader = new FileReader();
    reader.onload = (e) => {
      currentFileContent = e.target.result;
      currentFileName = file.name;
      domainCounts = collectDomainCounts(currentFileContent);
      selectedDomains.clear();
      allDomainsSelected = true;
      domainFilterSearch.value = '';
      renderDomainFilters();
      fileInfoDiv.innerHTML = `<div class="file-info" style="background:var(--sf2); border-radius:var(--rs); padding:0.75rem; font-size:0.85rem;">📄 ${escapeHtml(file.name)} (${(file.size/1024).toFixed(1)} KB) loaded.</div>`;
      extractBtn.disabled = false;
      metricOutputFiles = 0;
      metricProgressCompleted = 0;
      metricProgressTotal = 0;
      setEmailMetricState('idle', 'Email list loaded · ready to extract', { resetElapsed: true });
      showStatus(`File "${file.name}" loaded successfully. Ready to extract.`, 'success');
    };
    reader.onerror = () => {
      showStatus('Error reading file.', 'error');
      currentFileContent = null;
      metricProgressCompleted = 0;
      metricProgressTotal = 0;
      setEmailMetricState('failed', 'Could not read email list');
      extractBtn.disabled = true;
    };
    reader.readAsText(file, 'UTF-8');
  }

  // clear all
  function clearAll() {
    currentFileContent = null;
    currentFileName = null;
    fileInfoDiv.innerHTML = '';
    statusDiv.innerHTML = '';
    resultsSection.style.display = 'none';
    resultsContent.innerHTML = '';
    rawRuleLines = [];
    metricOutputFiles = 0;
    metricProgressCompleted = 0;
    metricProgressTotal = 0;
    setEmailMetricState('idle', 'Waiting for a run', { resetElapsed: true });
    extractBtn.disabled = true;
    fileInput.value = '';
    domainCounts.clear();
    selectedDomains.clear();
    allDomainsSelected = true;
    domainFilterSearch.value = '';
    renderDomainFilters();
    extractDigitsCheck.checked = true;
    showStatus('Cleared. Upload a new email list.', 'info');
  }

  // drag & drop handlers
  function setupDragAndDrop() {
    uploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadArea.classList.add('drag');
    });
    uploadArea.addEventListener('dragleave', () => {
      uploadArea.classList.remove('drag');
    });
    uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('drag');
      const files = e.dataTransfer.files;
      if (files.length > 0) readFile(files[0]);
    });
    uploadArea.addEventListener('click', (e) => {
      if (e.target !== selectBtn && !selectBtn.contains(e.target)) fileInput.click();
    });
    selectBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length) readFile(e.target.files[0]);
    });
  }

  // Event listeners
  extractBtn.addEventListener('click', runExtraction);
  clearBtn.addEventListener('click', clearAll);
  downloadBtn.addEventListener('click', downloadRules);
  domainFilterAllButton.addEventListener('click', () => {
    allDomainsSelected = true;
    selectedDomains.clear();
    renderDomainFilters();
  });
  domainFilterSearch.addEventListener('input', renderDomainFilters);

  // initial state
  setupDragAndDrop();
  extractBtn.disabled = true;
  resultsSection.style.display = 'none';
  renderEmailMetrics();
})();
