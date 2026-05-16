
/* ── PARSE-X · UI Engine ──────────────────────────────────────────────────── */

let allArtifacts   = [];
let activeGroup    = 'all';
let activeTypeKey  = 'all';
let searchQuery    = '';

const TYPE_COLORS = {
  ip:          '#00c8ff',
  ipv6:        '#60a5fa',
  domain:      '#10b981',
  url:         '#06b6d4',
  email:       '#f59e0b',
  mac:         '#a855f7',
  port:        '#3b82f6',
  hash_md5:    '#f59e0b',
  hash_sha1:   '#fb923c',
  hash_sha256: '#ff6b35',
  hash_sha512: '#ef4444',
  registry:    '#f43f5e',
  winpath:     '#84cc16',
  unixpath:    '#65a30d',
  process:     '#a3e635',
  dll:         '#4ade80',
  cve:         '#ff3b5c',
  mitre:       '#e879f9',
};

/* ── Helpers ──────────────────────────────────────────────────────────────── */
function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function showToast(msg, type = 'info') {
  let t = document.getElementById('px-toast');
  if (!t) {
    t = document.createElement('div'); t.id = 'px-toast';
    t.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;padding:11px 18px;font-family:var(--mono);font-size:13px;border:1px solid;border-radius:4px;pointer-events:none;transition:opacity .3s;max-width:360px;';
    document.body.appendChild(t);
  }
  const styles = {
    success: 'background:rgba(0,255,159,.08);border-color:rgba(0,255,159,.4);color:var(--accent)',
    error:   'background:rgba(255,59,92,.08);border-color:rgba(255,59,92,.4);color:var(--red)',
    warning: 'background:rgba(255,214,10,.08);border-color:rgba(255,214,10,.4);color:var(--yellow)',
    info:    'background:rgba(59,130,246,.08);border-color:rgba(59,130,246,.4);color:var(--accent2)',
  };
  t.style.cssText += styles[type] || styles.info;
  t.textContent = msg; t.style.opacity = '1';
  clearTimeout(t._tid);
  t._tid = setTimeout(() => { t.style.opacity = '0'; }, 3000);
}

/* ── Render results ───────────────────────────────────────────────────────── */
function renderResults(artifacts) {
  allArtifacts  = artifacts;
  activeGroup   = 'all';
  activeTypeKey = 'all';
  searchQuery   = '';

  /* Reset filter buttons */
  document.querySelectorAll('.grp-filter').forEach(b => b.classList.remove('active'));
  const allBtn = document.querySelector('.grp-filter[data-grp="all"]');
  if (allBtn) allBtn.classList.add('active');
  const searchEl = document.getElementById('result-search');
  if (searchEl) searchEl.value = '';

  document.getElementById('results-panel').style.display = '';
  buildSummaryStrip();
  applyFilters();
}

function applyFilters() {
  let list = allArtifacts;

  if (activeGroup !== 'all') {
    const types = GROUP_TYPES[activeGroup] || [];
    list = list.filter(a => types.includes(a.type));
  }
  if (activeTypeKey !== 'all') {
    list = list.filter(a => a.type === activeTypeKey);
  }
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    list = list.filter(a => a.value.toLowerCase().includes(q) || a.label.toLowerCase().includes(q));
  }

  renderTable(list);

  const metaEl = document.getElementById('results-meta');
  if (metaEl) {
    if (list.length === allArtifacts.length)
      metaEl.innerHTML = `<span>${allArtifacts.length}</span> artifacts`;
    else
      metaEl.innerHTML = `<span>${list.length}</span> / ${allArtifacts.length} shown`;
  }
}

function renderTable(artifacts) {
  const tbody = document.getElementById('results-body');
  if (!tbody) return;
  if (!artifacts.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">NO ARTIFACTS MATCH FILTER</td></tr>`;
    return;
  }
  tbody.innerHTML = artifacts.map((a, i) => buildRow(a, i + 1)).join('');
}

function buildRow(a, idx) {
  const color = TYPE_COLORS[a.type] || 'var(--muted)';
  const displayVal = a.value.length > 90 ? a.value.slice(0, 90) + '…' : a.value;
  const escapedVal = escapeHtml(a.value);
  const safeVal = escapedVal.replace(/'/g, '&#39;');
  const delay = Math.min(idx * 18, 300);

  return `<tr style="animation-delay:${delay}ms">
    <td class="col-stripe" style="padding:0">
      <span class="col-stripe-cell" style="background:${color};animation-delay:${delay}ms"></span>
    </td>
    <td class="col-num">${idx}</td>
    <td class="col-type">
      <span class="type-badge" style="color:${color};border-color:${color}20;background:${color}10">${escapeHtml(a.label)}</span>
    </td>
    <td class="col-val">
      <span class="artifact-val" title="${escapedVal}" onclick="copyVal('${safeVal}')">${escapeHtml(displayVal)}</span>
    </td>
    <td class="col-copy">
      <button class="btn-copy" onclick="copyVal('${safeVal}')" title="Copy to clipboard">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <rect x="1" y="3" width="8" height="8" rx="1" stroke="currentColor" stroke-width="1.2"/>
          <path d="M3 1h8v8" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
      </button>
    </td>
  </tr>`;
}

function copyVal(val) {
  navigator.clipboard.writeText(val).then(() => showToast('Copied!', 'success'));
}

/* ── Summary strip ────────────────────────────────────────────────────────── */
const TYPE_ORDER = ['ip','ipv6','domain','url','email','mac','port','hash_md5','hash_sha1','hash_sha256','hash_sha512','registry','winpath','unixpath','process','dll','cve','mitre'];

function buildSummaryStrip() {
  const counts = getTypeCounts(allArtifacts);
  const strip  = document.getElementById('summary-strip');
  if (!strip) return;

  strip.innerHTML = TYPE_ORDER.filter(t => counts[t]).map(t => {
    const c   = TYPE_COLORS[t] || 'var(--muted)';
    const lbl = TYPE_LABELS[t] || t;
    return `<div class="summary-card" onclick="filterBySpecificType('${t}')" title="Filter: ${lbl}">
      <div class="sc-dot" style="background:${c}"></div>
      <div>
        <div class="summary-num">${counts[t]}</div>
        <div class="summary-lbl">${lbl}</div>
      </div>
    </div>`;
  }).join('');
}

/* ── Filtering ────────────────────────────────────────────────────────────── */
function filterByGroup(grp, btn) {
  activeGroup   = grp;
  activeTypeKey = 'all';
  document.querySelectorAll('.grp-filter').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
}

function filterBySpecificType(type) {
  activeGroup   = 'all';
  activeTypeKey = type;
  document.querySelectorAll('.grp-filter').forEach(b => b.classList.remove('active'));
  applyFilters();
}

function searchResults(q) {
  searchQuery = q;
  applyFilters();
}

/* ── Export ───────────────────────────────────────────────────────────────── */
function openExportModal() {
  document.getElementById('export-modal').classList.add('open');
}

function closeExportModal(e) {
  if (!e || e.target === document.getElementById('export-modal'))
    document.getElementById('export-modal').classList.remove('open');
}

function doExport() {
  const fmt = document.querySelector('input[name="exp-fmt"]:checked')?.value || 'csv';
  const data = allArtifacts;
  if (!data.length) { showToast('No artifacts to export', 'error'); return; }

  if (fmt === 'csv')  exportCSV(data);
  if (fmt === 'json') exportJSON(data);
  if (fmt === 'md')   exportMD(data);

  document.getElementById('export-modal').classList.remove('open');
}

function exportCSV(artifacts) {
  const rows = ['Type,Value'];
  for (const a of artifacts) rows.push(`"${a.label}","${a.value.replace(/"/g, '""')}"`);
  downloadFile('parse-x-artifacts.csv', rows.join('\n'), 'text/csv');
  showToast(`CSV exported — ${artifacts.length} artifacts`, 'success');
}

function exportJSON(artifacts) {
  const data = artifacts.map(a => ({ type: a.label, group: a.group, value: a.value }));
  downloadFile('parse-x-artifacts.json', JSON.stringify(data, null, 2), 'application/json');
  showToast(`JSON exported — ${artifacts.length} artifacts`, 'success');
}

function exportMD(artifacts) {
  const lines = ['# PARSE-X — Extracted Artifacts', '', '| # | Type | Value |', '|---|------|-------|'];
  artifacts.forEach((a, i) => lines.push(`| ${i + 1} | ${a.label} | \`${a.value}\` |`));
  downloadFile('parse-x-artifacts.md', lines.join('\n'), 'text/markdown');
  showToast(`Markdown exported — ${artifacts.length} artifacts`, 'success');
}

function downloadFile(filename, content, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type: mime }));
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function copyAllArtifacts() {
  if (!allArtifacts.length) { showToast('No artifacts to copy', 'warning'); return; }
  const text = allArtifacts.map(a => `${a.label}\t${a.value}`).join('\n');
  navigator.clipboard.writeText(text).then(() =>
    showToast(`Copied ${allArtifacts.length} artifacts`, 'success')
  );
}

