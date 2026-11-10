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
  const domainFilterInput = document.getElementById('domain-filter');
  const extractDigitsCheck = document.getElementById('extract-digits');
  const downloadBtn = document.getElementById('download-rules-btn');

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

  // Process file content and return pattern map: key = patternString (digits+domain OR local+domain)
  // returns Map with { pattern, count, examples, rule }
  function processEmails(content, domainFilterSet, extractDigitsOnly) {
    const lines = content.split(/\r?\n/);
    const patternMap = new Map(); // key: patternKey (string), value: { pattern: displayPattern, count, examples, domain, digitsOrLocal }

    for (const rawLine of lines) {
      const emailAddr = extractEmailFromLine(rawLine);
      if (!emailAddr) continue;

      const parsed = parseEmail(emailAddr);
      if (!parsed) continue;

      const { localPart, domain } = parsed;

      // Apply domain filter if specified
      if (domainFilterSet.size > 0 && !domainFilterSet.has(domain)) continue;

      let patternValue = null;
      let displayPattern = null;

      if (extractDigitsOnly) {
        // trailing digits extraction
        const matchDigits = localPart.match(/(\d+)$/);
        if (matchDigits) {
          const digits = matchDigits[1];
          patternValue = digits + '@' + domain;
          displayPattern = patternValue;
        }
      } else {
        // Use full local part (including any digits, separators)
        patternValue = localPart + '@' + domain;
        displayPattern = patternValue;
      }

      if (!patternValue) continue; // no trailing digits and extractDigitsOnly is true -> skip

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
    html += `<div style="max-height:360px; overflow-y:auto; border:1px solid var(--b); border-radius:var(--rs); background:rgba(0,0,0,0.2);">`;
    html += `<table style="width:100%; border-collapse:collapse; font-size:0.8rem;">`;
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

    // parse domain filter
    let domainFilter = domainFilterInput.value.trim();
    let domainSet = new Set();
    if (domainFilter) {
      const parts = domainFilter.split(',').map(s => s.trim().toLowerCase()).filter(s => s);
      for (const p of parts) domainSet.add(p);
    }

    const extractDigitsOnly = extractDigitsCheck.checked;

    showStatus(`Processing ${currentFileName || 'file'}...`, 'info');
    // slight delay to allow UI update
    setTimeout(() => {
      try {
        const patternMap = processEmails(currentFileContent, domainSet, extractDigitsOnly);
        renderResults(patternMap);
        if (patternMap.size === 0) {
          showStatus('No patterns extracted. Try adjusting domain filter or disable "trailing digits only" if emails have no numeric suffix.', 'info');
        } else {
          showStatus(`Extraction complete: ${patternMap.size} unique rules generated.`, 'success');
        }
      } catch (err) {
        console.error(err);
        showStatus(`Extraction error: ${err.message}`, 'error');
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
    showStatus(`Downloaded ${rawRuleLines.length} rules.`, 'success');
  }

  // Read file
  function readFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      currentFileContent = e.target.result;
      currentFileName = file.name;
      fileInfoDiv.innerHTML = `<div class="file-info" style="background:var(--sf2); border-radius:var(--rs); padding:0.75rem; font-size:0.85rem;">📄 ${escapeHtml(file.name)} (${(file.size/1024).toFixed(1)} KB) loaded.</div>`;
      extractBtn.disabled = false;
      showStatus(`File "${file.name}" loaded successfully. Ready to extract.`, 'success');
    };
    reader.onerror = () => {
      showStatus('Error reading file.', 'error');
      currentFileContent = null;
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
    extractBtn.disabled = true;
    fileInput.value = '';
    domainFilterInput.value = '';
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

  // initial state
  setupDragAndDrop();
  extractBtn.disabled = true;
  resultsSection.style.display = 'none';
})();
