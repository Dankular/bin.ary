/* bin.ary — frontend */

// ── Stage definitions ──────────────────────────────────────────────────────
const STAGES = [
  { id: 'upload',   icon: '⬆',  label: 'File Uploaded' },
  { id: 'detect',   icon: '🔍', label: 'Detect Format' },
  { id: 'headers',  icon: '📋', label: 'Parse Headers' },
  { id: 'sections', icon: '📁', label: 'Sections' },
  { id: 'disasm',   icon: '⚙',  label: 'Disassemble' },
  { id: 'report',   icon: '📊', label: 'Report' },
];

// ── DOM refs ───────────────────────────────────────────────────────────────
const uploadPanel    = document.getElementById('upload-panel');
const analysisPanel  = document.getElementById('analysis-panel');
const dropZone       = document.getElementById('drop-zone');
const fileInput      = document.getElementById('file-input');
const uploadError    = document.getElementById('upload-error');
const pipelineEl     = document.getElementById('pipeline');
const resultsWrapper = document.getElementById('results-wrapper');
const newAnalysisBtn = document.getElementById('new-analysis-btn');
const disasmFilter   = document.getElementById('disasm-filter');
const disasmBody     = document.getElementById('disasm-body');
const disasmBadge    = document.getElementById('disasm-badge');
const disasmSection  = document.getElementById('disasm-section-label');
const fileInfoTable  = document.getElementById('file-info-table');
const sectionsTbody  = document.querySelector('#sections-table tbody');

// ── Build pipeline UI ──────────────────────────────────────────────────────
function buildPipeline() {
  pipelineEl.innerHTML = '';
  STAGES.forEach((stage) => {
    const el = document.createElement('div');
    el.className = 'stage pending';
    el.id = `stage-${stage.id}`;
    el.innerHTML = `
      <div class="stage-node" id="node-${stage.id}">${stage.icon}</div>
      <div class="stage-label">${stage.label}</div>
      <div class="stage-result" id="result-${stage.id}"></div>
    `;
    pipelineEl.appendChild(el);
  });
}

function setStage(id, status, result = '') {
  const el = document.getElementById(`stage-${id}`);
  const node = document.getElementById(`node-${id}`);
  const res  = document.getElementById(`result-${id}`);
  if (!el) return;

  el.className = `stage ${status}`;

  const stage = STAGES.find((s) => s.id === id);
  if (status === 'running') {
    node.innerHTML = '<span class="spinner"></span>';
  } else {
    node.innerHTML = stage ? stage.icon : '?';
  }

  res.textContent = result;
}

// ── Upload flow ────────────────────────────────────────────────────────────
function showError(msg) {
  uploadError.textContent = msg;
  uploadError.hidden = false;
}

function clearError() {
  uploadError.hidden = true;
  uploadError.textContent = '';
}

async function handleFile(file) {
  if (!file) return;
  clearError();

  // Switch to analysis view
  uploadPanel.hidden = true;
  analysisPanel.hidden = false;
  resultsWrapper.hidden = true;
  buildPipeline();

  // 1. Upload
  const formData = new FormData();
  formData.append('file', file);

  let jobId, originalName, size;
  try {
    const resp = await fetch('/upload', { method: 'POST', body: formData });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: resp.statusText }));
      throw new Error(err.error || 'Upload failed');
    }
    ({ jobId, originalName, size } = await resp.json());
  } catch (err) {
    uploadPanel.hidden = false;
    analysisPanel.hidden = true;
    showError('Upload failed: ' + err.message);
    return;
  }

  // 2. Stream analysis via SSE
  const url = `/analyze/${encodeURIComponent(jobId)}?name=${encodeURIComponent(originalName)}&size=${size}`;
  const es = new EventSource(url);

  es.addEventListener('stage', (e) => {
    const { id, status, label, result } = JSON.parse(e.data);
    setStage(id, status, result || '');
  });

  es.addEventListener('results', (e) => {
    renderResults(JSON.parse(e.data));
  });

  es.addEventListener('error', (e) => {
    es.close();
    if (e.data) {
      const { message } = JSON.parse(e.data);
      setStage('report', 'error', message);
    }
  });

  es.addEventListener('done', () => {
    es.close();
    resultsWrapper.hidden = false;
  });

  // native SSE error (connection dropped)
  es.onerror = () => {
    if (es.readyState === EventSource.CLOSED) return;
    es.close();
  };
}

// ── Render results ─────────────────────────────────────────────────────────
function renderResults(report) {
  // File info table
  fileInfoTable.innerHTML = '';
  const fileRows = [
    ['Name',         report.file.name],
    ['Size',         report.file.sizeStr],
    ['Format',       report.file.type],
    ['Architecture', report.file.arch],
    ...(report.file.bits         ? [['Bits',       report.file.bits + '-bit']] : []),
    ...(report.file.fileType     ? [['File Type',  report.file.fileType]] : []),
    ...(report.file.entryPoint   ? [['Entry Point',report.file.entryPoint]] : []),
    ...(report.file.imageBase    ? [['Image Base', report.file.imageBase]] : []),
    ...(report.file.subsystem    ? [['Subsystem',  report.file.subsystem]] : []),
    ...(report.file.osabi        ? [['OS ABI',     report.file.osabi]] : []),
    ...(report.file.endian       ? [['Endian',     report.file.endian]] : []),
    ...(report.file.timestamp    ? [['Timestamp',  report.file.timestamp]] : []),
  ];
  fileRows.forEach(([key, val]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(key)}</td><td>${esc(String(val ?? ''))}</td>`;
    fileInfoTable.appendChild(tr);
  });

  // Sections table
  sectionsTbody.innerHTML = '';
  if (report.sections.length === 0) {
    sectionsTbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);padding:.5rem">No sections found</td></tr>';
  } else {
    report.sections.forEach((sec) => {
      const tr = document.createElement('tr');
      const nameClass = sec.isCode ? 'section-code' : 'section-data';
      tr.innerHTML = `
        <td class="${nameClass}">${esc(sec.name)}${sec.isCode ? '<span class="badge-code">code</span>' : ''}</td>
        <td>${esc(sec.virtualAddress)}</td>
        <td>${esc(sec.size)}</td>
        <td style="color:var(--muted);font-size:0.75rem">${esc(sec.flags)}</td>
      `;
      sectionsTbody.appendChild(tr);
    });
  }

  // Disassembly
  disasmBody.innerHTML = '';
  const { fallback, section, instructions } = report.disasm;

  disasmBadge.textContent = fallback ? 'Hex Dump' : 'Assembly';
  disasmBadge.className   = 'badge ' + (fallback ? 'badge-hex' : 'badge-asm');
  disasmSection.textContent = section ? `section: ${section}` : '';

  if (!instructions || instructions.length === 0) {
    disasmBody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);padding:.75rem">No instructions to display</td></tr>';
  } else {
    const frag = document.createDocumentFragment();
    instructions.forEach((inst) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="cell-addr">${esc(inst.address)}</td>
        <td class="cell-bytes">${esc(inst.bytes)}</td>
        <td class="cell-mnem">${esc(inst.mnemonic)}</td>
        <td class="cell-ops">${esc(inst.operands)}</td>
      `;
      frag.appendChild(tr);
    });
    disasmBody.appendChild(frag);
  }

  // Apply any existing filter text
  applyFilter(disasmFilter.value);
}

// ── Disasm filter ──────────────────────────────────────────────────────────
function applyFilter(query) {
  const q = query.trim().toLowerCase();
  const rows = disasmBody.querySelectorAll('tr');
  rows.forEach((tr) => {
    if (!q) {
      tr.classList.remove('hidden', 'match');
      return;
    }
    const text = tr.textContent.toLowerCase();
    if (text.includes(q)) {
      tr.classList.remove('hidden');
      tr.classList.add('match');
    } else {
      tr.classList.add('hidden');
      tr.classList.remove('match');
    }
  });
}

disasmFilter.addEventListener('input', (e) => applyFilter(e.target.value));

// ── Drag & drop ────────────────────────────────────────────────────────────
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
});

dropZone.addEventListener('click', (e) => {
  if (e.target !== fileInput) fileInput.click();
});
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});

fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) handleFile(file);
  fileInput.value = '';
});

// ── New analysis ───────────────────────────────────────────────────────────
newAnalysisBtn.addEventListener('click', () => {
  uploadPanel.hidden = false;
  analysisPanel.hidden = true;
  resultsWrapper.hidden = true;
  clearError();
  disasmFilter.value = '';
});

// ── Helpers ────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
