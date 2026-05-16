
/* ── PARSE-X · App Init ───────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.getElementById('export-modal')?.classList.remove('open');
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const btn = document.getElementById('extract-btn');
      if (!btn?.disabled) extractArtifacts();
    }
  });
});

function extractArtifacts() {
  const raw = document.getElementById('px-input')?.value || '';
  if (!raw.trim()) return;

  const artifacts = parseArtifacts(raw);
  if (!artifacts.length) {
    showToast('No artifacts detected in input', 'warning');
    return;
  }

  renderResults(artifacts);

  const counts = getTypeCounts(artifacts);
  const typeCount = Object.keys(counts).length;
  showToast(`${artifacts.length} artifacts extracted · ${typeCount} type${typeCount > 1 ? 's' : ''}`, 'success');

  setTimeout(() => {
    document.getElementById('results-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 80);
}

function clearAll() {
  const inp = document.getElementById('px-input');
  if (inp) inp.value = '';
  const info = document.getElementById('parsed-info');
  if (info) info.innerHTML = '';
  const btn = document.getElementById('extract-btn');
  if (btn) btn.disabled = true;
  document.getElementById('results-panel').style.display = 'none';
  allArtifacts   = [];
  activeGroup    = 'all';
  activeTypeKey  = 'all';
  searchQuery    = '';
  const badge = document.getElementById('upload-badge');
  if (badge) badge.style.display = 'none';
}

function switchInputTab(tab, btn) {
  document.querySelectorAll('.input-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.getElementById(`tab-${tab}`)?.classList.add('active');
}

/* ── File upload ──────────────────────────────────────────────────────────── */
function handleDragOver(e)  { e.preventDefault(); document.getElementById('upload-zone')?.classList.add('dragover'); }
function handleDragLeave()  { document.getElementById('upload-zone')?.classList.remove('dragover'); }
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('upload-zone')?.classList.remove('dragover');
  const f = e.dataTransfer.files[0];
  if (f) processFile(f);
}
function handleFileUpload(e) {
  const f = e.target.files[0];
  if (f) processFile(f);
  e.target.value = '';
}

function processFile(file) {
  const badge = document.getElementById('upload-badge');
  if (badge) { badge.textContent = file.name; badge.style.display = ''; }

  const r = new FileReader();
  r.onload = e => loadTextIntoInput(e.target.result, file.name);
  r.onerror = () => showToast('Failed to read file', 'error');
  r.readAsText(file);
}

function loadTextIntoInput(text, filename) {
  const firstTab = document.querySelector('.input-pill');
  if (firstTab) switchInputTab('text', firstTab);
  const inp = document.getElementById('px-input');
  if (inp) { inp.value = text; parseRealtime(); }
  showToast(`Loaded: ${filename || 'file'}`, 'success');
}
