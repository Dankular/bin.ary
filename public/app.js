/* bin.ary — main frontend */
'use strict';

// ── Pipeline stage definitions ────────────────────────────────────────────
const STAGES = [
  { id: 'upload',   icon: '⬆',  label: 'File Uploaded' },
  { id: 'detect',   icon: '🔍', label: 'Detect Format' },
  { id: 'headers',  icon: '📋', label: 'Parse Headers' },
  { id: 'sections', icon: '📁', label: 'Sections' },
  { id: 'disasm',   icon: '⚙',  label: 'Disassemble' },
  { id: 'refs',     icon: '🔗', label: 'Cross-Refs' },
  { id: 'report',   icon: '📊', label: 'Report' },
];

// ── State ─────────────────────────────────────────────────────────────────
let state = {
  report:       null,
  sim:          null,       // X86Sim instance
  simRunning:   false,
  runTimer:     null,
  prevRegs:     null,
  currentAddr:  null,       // currently selected instruction address
  renames:      {},         // pattern → name (persisted in localStorage)
  bpAddrs:      new Set(),  // breakpoint addresses
  renameTarget: null,       // pattern string being renamed
  currentTab:   'disasm',
};

// ── DOM refs ──────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

const uploadPanel    = $('upload-panel');
const analysisPanel  = $('analysis-panel');
const dropZone       = $('drop-zone');
const fileInput      = $('file-input');
const uploadError    = $('upload-error');
const pipelineEl     = $('pipeline');
const resultsWrapper = $('results-wrapper');
const disasmBody     = $('disasm-body');
const disasmFilter   = $('disasm-filter');
const disasmBadge    = $('disasm-badge');
const disasmSection  = $('disasm-section-label');
const fileInfoTable  = $('file-info-table');
const newAnalysisBtn = $('new-analysis-btn');
const xrefPanel      = $('xref-panel');
const xrefBody       = $('xref-body');
const xrefAddrLabel  = $('xref-addr-label');
const debuggerCard   = $('debugger-card');
const debuggerBody   = $('debugger-body');
const dbgRip         = $('dbg-rip');
const dbgRegs        = $('dbg-regs');
const dbgFlags       = $('dbg-flags');
const dbgStack       = $('dbg-stack');

// ── Pipeline ──────────────────────────────────────────────────────────────
function buildPipeline() {
  pipelineEl.innerHTML = '';
  STAGES.forEach((s) => {
    const el = document.createElement('div');
    el.className = 'stage pending';
    el.id = `stage-${s.id}`;
    el.innerHTML = `
      <div class="stage-node" id="node-${s.id}">${s.icon}</div>
      <div class="stage-label">${s.label}</div>
      <div class="stage-result" id="result-${s.id}"></div>`;
    pipelineEl.appendChild(el);
  });
}

function setStage(id, status, result = '') {
  const el   = $(`stage-${id}`);
  const node = $(`node-${id}`);
  const res  = $(`result-${id}`);
  if (!el) return;
  el.className = `stage ${status}`;
  const s = STAGES.find((x) => x.id === id);
  node.innerHTML = status === 'running' ? '<span class="spinner"></span>' : (s ? s.icon : '?');
  res.textContent = result;
}

// ── Upload ────────────────────────────────────────────────────────────────
function showError(msg) { uploadError.textContent = msg; uploadError.hidden = false; }
function clearError()   { uploadError.hidden = true; uploadError.textContent = ''; }

async function handleFile(file) {
  if (!file) return;
  clearError();
  uploadPanel.hidden    = true;
  analysisPanel.hidden  = false;
  resultsWrapper.hidden = true;
  buildPipeline();

  const fd = new FormData();
  fd.append('file', file);
  let jobId, originalName, size;
  try {
    const r = await fetch('/upload', { method: 'POST', body: fd });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    ({ jobId, originalName, size } = await r.json());
  } catch (e) {
    uploadPanel.hidden = false; analysisPanel.hidden = true;
    showError('Upload failed: ' + e.message); return;
  }

  const url = `/analyze/${encodeURIComponent(jobId)}?name=${encodeURIComponent(originalName)}&size=${size}`;
  const es  = new EventSource(url);
  es.addEventListener('stage',   (e) => { const d = JSON.parse(e.data); setStage(d.id, d.status, d.result || ''); });
  es.addEventListener('results', (e) => { renderResults(JSON.parse(e.data)); });
  es.addEventListener('error',   (e) => { if (e.data) { const d=JSON.parse(e.data); setStage('report','error',d.message); } });
  es.addEventListener('done',    ()  => { es.close(); resultsWrapper.hidden = false; scrollTo(0, analysisPanel.offsetTop); });
  es.onerror = () => { if (es.readyState !== EventSource.CLOSED) es.close(); };
}

// ── Load renames from localStorage ───────────────────────────────────────
function loadRenames(key) {
  try { return JSON.parse(localStorage.getItem('binaryRenames:' + key) || '{}'); } catch { return {}; }
}
function saveRenames(key, map) {
  localStorage.setItem('binaryRenames:' + key, JSON.stringify(map));
}

// ── Render results ────────────────────────────────────────────────────────
function renderResults(report) {
  state.report = report;
  state.renames = loadRenames(report.file.name);

  // File info
  fileInfoTable.innerHTML = '';
  const rows = [
    ['Name',         report.file.name],
    ['Size',         report.file.sizeStr],
    ['Format',       report.file.type],
    ['Architecture', report.file.arch],
    ...(report.file.bits       ? [['Bits',        report.file.bits + '-bit']] : []),
    ...(report.file.fileType   ? [['File Type',   report.file.fileType]]  : []),
    ...(report.file.entryPoint ? [['Entry Point', report.file.entryPoint]] : []),
    ...(report.file.imageBase  ? [['Image Base',  report.file.imageBase]]  : []),
    ...(report.file.subsystem  ? [['Subsystem',   report.file.subsystem]]  : []),
    ...(report.file.osabi      ? [['OS ABI',      report.file.osabi]]     : []),
    ...(report.file.endian     ? [['Endian',      report.file.endian]]    : []),
    ...(report.file.timestamp  ? [['Timestamp',   report.file.timestamp]] : []),
  ];
  rows.forEach(([k, v]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(k)}</td><td>${esc(String(v ?? ''))}</td>`;
    fileInfoTable.appendChild(tr);
  });

  // Sections
  const sTbody = document.querySelector('#sections-table tbody');
  sTbody.innerHTML = '';
  if (!report.sections.length) {
    sTbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted)">None</td></tr>';
  } else {
    report.sections.forEach((s) => {
      const tr = document.createElement('tr');
      const nc = s.isCode ? 'section-code' : 'section-data';
      tr.innerHTML = `<td class="${nc}">${esc(s.name)}${s.isCode ? '<span class="badge-code">code</span>' : ''}</td>
        <td>${esc(s.virtualAddress)}</td><td>${esc(s.size)}</td>
        <td style="color:var(--muted);font-size:.72rem">${esc(s.flags)}</td>`;
      sTbody.appendChild(tr);
    });
  }

  // Signatures
  const sigCard = $('sig-card');
  const sigTbody = document.querySelector('#sig-table tbody');
  const sigs = report.analysis?.byteSigs || [];
  if (sigs.length > 0) {
    sigCard.hidden = false;
    sigTbody.innerHTML = '';
    sigs.forEach((s) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td style="color:var(--accent2)">${esc(s.address)}</td><td style="color:var(--accent)">${esc(s.name)}</td><td style="color:var(--muted)">${esc(s.note)}</td>`;
      sigTbody.appendChild(tr);
    });
  } else { sigCard.hidden = true; }

  // Disassembly
  renderDisasm(report);

  // Debugger setup
  if (!report.disasm.fallback && report.disasm.instructions.length > 0) {
    state.sim = new X86Sim(report.file.bits || 64);
    state.sim.load(report.disasm.instructions);
    updateDebuggerUI();
  }
}

// ── Apply rename patterns to operand text ─────────────────────────────────
function applyRenames(text) {
  for (const [pattern, name] of Object.entries(state.renames)) {
    text = text.replaceAll(pattern, `\x01${name}\x01`);
  }
  return text;
}

// ── Parse operand cell HTML: make addresses clickable ────────────────────
function opsHTML(raw) {
  if (!raw) return '';
  // Replace renamed patterns
  let text = applyRenames(esc(raw));
  // Make hex addresses in operands clickable
  text = text.replace(/\b([0-9a-fA-F]{4,16})h\b/g, (m) => {
    const addr = '0x' + BigInt('0x' + m.slice(0,-1)).toString(16).padStart(16,'0');
    return `<span class="op-addr" data-addr="${addr}">${esc(m)}</span>`;
  });
  text = text.replace(/\x01([^\x01]+)\x01/g, (_, n) =>
    `<span style="color:var(--accent2)">${esc(n)}</span>`);
  return text;
}

// ── Render disassembly table ──────────────────────────────────────────────
function renderDisasm(report) {
  const { fallback, section, instructions } = report.disasm;
  const xrefs      = report.analysis?.xrefs      || {};
  const funcLabels = report.analysis?.funcLabels  || {};

  disasmBadge.textContent = fallback ? 'Hex Dump' : 'Assembly';
  disasmBadge.className   = 'badge ' + (fallback ? 'badge-hex' : 'badge-asm');
  disasmSection.textContent = section ? `section: ${section}` : '';

  disasmBody.innerHTML = '';

  if (!instructions || instructions.length === 0) {
    disasmBody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);padding:.75rem">No instructions</td></tr>';
    return;
  }

  const frag = document.createDocumentFragment();

  instructions.forEach((inst) => {
    // Function label row
    if (funcLabels[inst.address]) {
      const lr = document.createElement('tr');
      lr.className = 'func-label';
      lr.innerHTML = `<td colspan="6">; ── ${esc(funcLabels[inst.address])} ──────────────────────</td>`;
      frag.appendChild(lr);
    }

    const xref    = xrefs[inst.address];
    const xrefTxt = xref ? `▶ ${xref.length}` : '';

    const tr = document.createElement('tr');
    tr.dataset.addr = inst.address;
    if (state.bpAddrs.has(inst.address)) tr.classList.add('has-bp');

    tr.innerHTML = `
      <td class="cell-label">${funcLabels[inst.address] ? esc(funcLabels[inst.address]) : ''}</td>
      <td class="cell-addr">${esc(inst.address)}</td>
      <td class="cell-bytes">${esc(inst.bytes)}</td>
      <td class="cell-mnem">${esc(inst.mnemonic)}</td>
      <td class="cell-ops">${opsHTML(inst.operands)}</td>
      <td class="cell-xref" data-xref="${esc(inst.address)}">${xrefTxt}</td>`;

    frag.appendChild(tr);
  });

  disasmBody.appendChild(frag);

  // Delegate events on the table body
  disasmBody.addEventListener('click', onDisasmClick);
  disasmBody.addEventListener('dblclick', onDisasmDblClick);
}

// ── Click handler for disassembly table ──────────────────────────────────
function onDisasmClick(e) {
  const tr = e.target.closest('tr');
  if (!tr || !tr.dataset.addr) return;

  // Clickable address in operand
  if (e.target.classList.contains('op-addr')) {
    goToAddress(e.target.dataset.addr);
    return;
  }
  // XREF column
  if (e.target.classList.contains('cell-xref') && e.target.dataset.xref) {
    showXrefPanel(e.target.dataset.xref);
    return;
  }

  // Select instruction → identifier highlighting
  selectInstruction(tr);
}

function onDisasmDblClick(e) {
  const td = e.target.closest('td.cell-ops');
  if (!td) return;
  const tr  = td.closest('tr');
  const ops = tr ? tr.dataset.addr : null;
  if (!ops) return;

  // Find the word under the dblclick — check for stack pattern like [rbp-8h]
  const inst = state.report?.disasm.instructions.find(i => i.address === tr.dataset.addr);
  if (!inst) return;
  const pat = extractStackPattern(inst.operands);
  if (!pat) return;
  openRenameModal(pat);
}

// Extract [reg±offset] pattern from operands string
function extractStackPattern(ops) {
  if (!ops) return null;
  const m = ops.match(/\[(?:rbp|ebp|rsp|esp)[+-][^\]]+\]/i);
  return m ? m[0].toLowerCase() : null;
}

// ── Identifier highlighting ───────────────────────────────────────────────
let highlightedId = null;

function selectInstruction(tr) {
  // Deselect old
  document.querySelectorAll('.disasm-table tr.selected').forEach(r => r.classList.remove('selected'));
  document.querySelectorAll('.disasm-table tr.id-highlight').forEach(r => r.classList.remove('id-highlight'));

  if (!tr || !tr.dataset.addr) { highlightedId = null; state.currentAddr = null; return; }

  tr.classList.add('selected');
  state.currentAddr = tr.dataset.addr;

  // Pick identifier token from the clicked cell
  const mnemCell = tr.querySelector('.cell-mnem');
  const opsCell  = tr.querySelector('.cell-ops');
  const token = mnemCell?.textContent.trim().toLowerCase() || '';

  if (token) {
    highlightedId = token;
    highlightIdentifier(token);
  }

  // Update xref graph if on that tab
  if (state.currentTab === 'xrefgraph') showXrefGraph(tr.dataset.addr);
  if (state.currentTab === 'proximity') showProximity(tr.dataset.addr);
  $('xref-graph-addr').value = tr.dataset.addr;
  $('prox-addr').value = tr.dataset.addr;
}

function highlightIdentifier(token) {
  document.querySelectorAll('.disasm-table tbody tr[data-addr]').forEach((tr) => {
    const mnem = tr.querySelector('.cell-mnem')?.textContent.toLowerCase() || '';
    const ops  = tr.querySelector('.cell-ops')?.textContent.toLowerCase()  || '';
    if (mnem === token || ops.includes(token)) {
      tr.classList.add('id-highlight');
    }
  });
}

// ── Alt-Up/Alt-Down search ────────────────────────────────────────────────
function searchIdentifier(direction) {
  if (!highlightedId) return;
  const rows = [...document.querySelectorAll('.disasm-table tbody tr[data-addr]')]
    .filter(r => r.classList.contains('id-highlight'));
  if (!rows.length) return;
  const currentRow = document.querySelector('.disasm-table tr.selected');
  let idx = rows.indexOf(currentRow);
  idx = direction === 'next' ? (idx + 1) % rows.length : (idx - 1 + rows.length) % rows.length;
  selectInstruction(rows[idx]);
  rows[idx].scrollIntoView({ block: 'center' });
}

// ── Go to Address ─────────────────────────────────────────────────────────
function goToAddress(addr) {
  const pad = state.report?.file.bits === 64 ? 16 : 8;
  let norm;
  try { norm = '0x' + BigInt(addr).toString(16).padStart(pad, '0'); }
  catch { return; }

  const tr = document.querySelector(`.disasm-table tr[data-addr="${norm}"]`);
  if (tr) { tr.scrollIntoView({ block: 'center' }); selectInstruction(tr); }
}

// ── XREF Panel ────────────────────────────────────────────────────────────
function showXrefPanel(addr) {
  const xrefs = state.report?.analysis?.xrefs || {};
  const callers = xrefs[addr] || [];

  // Also find what this address calls
  const callees = [];
  for (const [target, refs] of Object.entries(xrefs)) {
    for (const r of refs) if (r.from === addr) callees.push({ addr: target, type: r.type });
  }

  xrefAddrLabel.textContent = addr;
  xrefBody.innerHTML = '';

  if (!callers.length && !callees.length) {
    xrefBody.innerHTML = '<p class="xref-empty">No cross-references found</p>';
  } else {
    if (callers.length) {
      const h = document.createElement('div');
      h.style.cssText = 'font-size:.65rem;text-transform:uppercase;letter-spacing:2px;color:var(--muted);padding:.2rem 0 .4rem';
      h.textContent = 'Called/jumped from';
      xrefBody.appendChild(h);
      callers.forEach(({ from, type }) => {
        const d = document.createElement('div');
        d.className = 'xref-entry';
        d.innerHTML = `<span class="xref-type">${esc(type)}</span><span class="xref-from" data-addr="${esc(from)}">${esc(from)}</span>`;
        d.querySelector('.xref-from').addEventListener('click', () => { goToAddress(from); closeXrefPanel(); });
        xrefBody.appendChild(d);
      });
    }
    if (callees.length) {
      const h = document.createElement('div');
      h.style.cssText = 'font-size:.65rem;text-transform:uppercase;letter-spacing:2px;color:var(--muted);padding:.4rem 0 .4rem';
      h.textContent = 'References to';
      xrefBody.appendChild(h);
      callees.forEach(({ addr: to, type }) => {
        const d = document.createElement('div');
        d.className = 'xref-entry';
        d.innerHTML = `<span class="xref-type">${esc(type)}</span><span class="xref-to">${esc(to)}</span>`;
        xrefBody.appendChild(d);
      });
    }
  }

  xrefPanel.hidden = false;
}

function closeXrefPanel() { xrefPanel.hidden = true; }
$('xref-close').addEventListener('click', closeXrefPanel);

// ── Graph tabs ────────────────────────────────────────────────────────────
function switchTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
  document.querySelectorAll('.tab-pane').forEach(p => p.hidden = p.id !== `tab-${tabId}`);
  document.querySelector(`#tab-${tabId}`).classList.add('active');
  state.currentTab = tabId;

  if (tabId === 'cfg') renderCFGTab();
  if (tabId === 'xrefgraph' && state.currentAddr) showXrefGraph(state.currentAddr);
  if (tabId === 'proximity' && state.currentAddr) showProximity(state.currentAddr);
}

document.querySelectorAll('.tab').forEach(t =>
  t.addEventListener('click', () => switchTab(t.dataset.tab)));

function renderCFGTab() {
  const r = state.report;
  if (!r) return;
  const container = $('cfg-container');
  BinaryGraph.renderCFG(
    container,
    r.disasm.instructions,
    r.file.bits || 64,
    state.currentAddr,
    (addr) => { switchTab('disasm'); goToAddress(addr); }
  );
}

function showXrefGraph(addr) {
  if (!state.report) return;
  BinaryGraph.renderXrefGraph(
    $('xrefgraph-container'),
    addr,
    state.report.analysis?.xrefs || {},
    state.report.analysis?.funcLabels || {},
    state.report.file.bits || 64,
    (a) => { switchTab('disasm'); goToAddress(a); }
  );
}

function showProximity(addr) {
  if (!state.report) return;
  BinaryGraph.renderProximity(
    $('proximity-container'),
    addr,
    state.report.analysis?.xrefs || {},
    state.report.analysis?.funcLabels || {},
    (a) => { switchTab('disasm'); goToAddress(a); }
  );
}

$('xref-graph-btn').addEventListener('click', () => showXrefGraph($('xref-graph-addr').value.trim()));
$('prox-btn').addEventListener('click', () => showProximity($('prox-addr').value.trim()));

// ── Rename modal ──────────────────────────────────────────────────────────
function openRenameModal(pattern) {
  state.renameTarget = pattern;
  $('rename-pattern').textContent = `Pattern: ${pattern}`;
  $('rename-input').value = state.renames[pattern] || '';
  $('modal-rename').hidden = false;
  $('rename-input').focus();
}

function closeRenameModal() { $('modal-rename').hidden = true; state.renameTarget = null; }

$('rename-ok').addEventListener('click', () => {
  const name = $('rename-input').value.trim();
  if (!state.renameTarget || !state.report) return;
  if (name) state.renames[state.renameTarget] = name;
  else delete state.renames[state.renameTarget];
  saveRenames(state.report.file.name, state.renames);
  closeRenameModal();
  renderDisasm(state.report);
});
$('rename-clear').addEventListener('click', () => {
  if (!state.renameTarget || !state.report) return;
  delete state.renames[state.renameTarget];
  saveRenames(state.report.file.name, state.renames);
  closeRenameModal();
  renderDisasm(state.report);
});
$('rename-cancel').addEventListener('click', closeRenameModal);
$('rename-input').addEventListener('keydown', e => { if (e.key==='Enter') $('rename-ok').click(); if (e.key==='Escape') closeRenameModal(); });

// ── Go to Address modal ───────────────────────────────────────────────────
function openGotoModal() {
  $('goto-input').value = state.currentAddr || '';
  $('modal-goto').hidden = false;
  $('goto-input').focus();
  $('goto-input').select();
}
function closeGotoModal() { $('modal-goto').hidden = true; }

$('btn-goto').addEventListener('click', openGotoModal);
$('goto-ok').addEventListener('click', () => {
  const v = $('goto-input').value.trim();
  if (v) {
    // Accept both 0x401000 and 401000h
    const hH = v.match(/^([0-9a-fA-F]+)h$/i);
    const addr = hH ? '0x' + hH[1] : v;
    goToAddress(addr);
  }
  closeGotoModal();
});
$('goto-cancel').addEventListener('click', closeGotoModal);
$('goto-input').addEventListener('keydown', e => { if (e.key==='Enter') $('goto-ok').click(); if (e.key==='Escape') closeGotoModal(); });

// ── Debugger ──────────────────────────────────────────────────────────────
function updateDebuggerUI() {
  if (!state.sim) return;
  const snap = state.sim.stateSnapshot();

  dbgRip.textContent = snap.rip;

  // Registers
  const SHOW_REGS = ['rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','r8','r9','r10','r11','r12','r13','r14','r15'];
  dbgRegs.innerHTML = SHOW_REGS.map(r => {
    const v = snap.regs[r];
    const prev = state.prevRegs?.[r];
    const changed = prev !== undefined && prev !== v;
    return `<div class="dbg-reg"><span class="dbg-reg-name">${r}</span><span class="dbg-reg-val${changed?' changed':''}">${v.toString(16).padStart(16,'0')}</span></div>`;
  }).join('');

  // Flags
  const F = snap.flags;
  dbgFlags.innerHTML = ['cf','zf','sf','of','pf'].map(f =>
    `<span class="dbg-flag${F[f]?' set':''}">${f.toUpperCase()}=${F[f]?1:0}</span>`).join('');

  // Stack
  dbgStack.innerHTML = snap.stack.map(row =>
    `<div class="dbg-stack-row"><span class="dbg-stack-addr">${row.addr}</span><span class="dbg-stack-hex">${row.hex}</span><span class="dbg-stack-asc">${esc(row.asc)}</span></div>`
  ).join('');

  // Highlight current instruction
  document.querySelectorAll('.disasm-table tr.dbg-current').forEach(r => r.classList.remove('dbg-current'));
  const cur = document.querySelector(`.disasm-table tr[data-addr="${snap.rip}"]`);
  if (cur) { cur.classList.add('dbg-current'); cur.scrollIntoView({ block: 'nearest' }); }

  state.prevRegs = { ...snap.regs };
}

function dbgStep() {
  if (!state.sim) return;
  const result = state.sim.step();
  if (result.error) { dbgRip.textContent = result.error; return; }
  updateDebuggerUI();
}

function dbgRun() {
  if (!state.sim || state.simRunning) return;
  state.simRunning = true;
  function tick() {
    if (!state.simRunning) return;
    for (let i = 0; i < 100; i++) {
      const r = state.sim.step();
      if (r.error) { state.simRunning = false; dbgRip.textContent = r.error; updateDebuggerUI(); return; }
      if (state.bpAddrs.has(state.sim.ripAddr())) { state.simRunning = false; updateDebuggerUI(); return; }
    }
    updateDebuggerUI();
    state.runTimer = setTimeout(tick, 16);
  }
  tick();
}

function dbgStop() { state.simRunning = false; clearTimeout(state.runTimer); updateDebuggerUI(); }

function dbgReset() {
  state.simRunning = false; clearTimeout(state.runTimer);
  if (state.sim && state.report) { state.sim.reset(state.report.disasm.instructions); state.prevRegs = null; updateDebuggerUI(); }
}

function dbgToggleBP() {
  const addr = state.currentAddr || state.sim?.ripAddr();
  if (!addr) return;
  if (state.bpAddrs.has(addr)) state.bpAddrs.delete(addr);
  else state.bpAddrs.add(addr);
  // Refresh row class
  const tr = document.querySelector(`.disasm-table tr[data-addr="${addr}"]`);
  if (tr) tr.classList.toggle('has-bp', state.bpAddrs.has(addr));
}

$('dbg-step').addEventListener('click',  dbgStep);
$('dbg-run').addEventListener('click',   dbgRun);
$('dbg-stop').addEventListener('click',  dbgStop);
$('dbg-reset').addEventListener('click', dbgReset);
$('dbg-bp').addEventListener('click',    dbgToggleBP);

$('debugger-collapse').addEventListener('click', (e) => {
  e.stopPropagation();
  debuggerBody.hidden = !debuggerBody.hidden;
  $('debugger-collapse').textContent = debuggerBody.hidden ? '▼' : '▲';
});

// ── Filter ────────────────────────────────────────────────────────────────
disasmFilter.addEventListener('input', (e) => {
  const q = e.target.value.trim().toLowerCase();
  document.querySelectorAll('.disasm-table tbody tr[data-addr]').forEach(tr => {
    tr.classList.toggle('filtered', q ? !tr.textContent.toLowerCase().includes(q) : false);
  });
});

// ── Keyboard shortcuts ────────────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  const modal = !$('modal-goto').hidden || !$('modal-rename').hidden;
  const inInput = e.target.tagName === 'INPUT';

  // Disasm navigation
  const scroll = $('disasm-scroll');

  if (!modal && !inInput) {
    if (e.key === 'g' || e.key === 'G') { e.preventDefault(); openGotoModal(); return; }
    if (e.key === 'Escape') { closeXrefPanel(); highlightedId = null; document.querySelectorAll('.disasm-table tr.id-highlight').forEach(r=>r.classList.remove('id-highlight')); return; }
    if (e.key === 'F7') { e.preventDefault(); dbgStep(); return; }
    if (e.key === 'F9') { e.preventDefault(); state.simRunning ? dbgStop() : dbgRun(); return; }
    if (e.key === 'F2') { e.preventDefault(); dbgToggleBP(); return; }

    // Alt+Up/Down — search identifier
    if (e.altKey && e.key === 'ArrowUp')   { e.preventDefault(); searchIdentifier('prev'); return; }
    if (e.altKey && e.key === 'ArrowDown') { e.preventDefault(); searchIdentifier('next'); return; }

    // Ctrl+Up/Down — scroll
    if (e.ctrlKey && e.key === 'ArrowUp')   { e.preventDefault(); scroll && scroll.scrollBy(0, -80);  return; }
    if (e.ctrlKey && e.key === 'ArrowDown') { e.preventDefault(); scroll && scroll.scrollBy(0,  80);  return; }

    // Up/Down — move selected row
    if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && !e.altKey && !e.ctrlKey) {
      e.preventDefault();
      const rows = [...document.querySelectorAll('.disasm-table tbody tr[data-addr]')];
      const cur  = document.querySelector('.disasm-table tr.selected');
      let idx    = rows.indexOf(cur);
      idx        = e.key === 'ArrowDown' ? Math.min(idx + 1, rows.length - 1) : Math.max(idx - 1, 0);
      if (rows[idx]) { selectInstruction(rows[idx]); rows[idx].scrollIntoView({ block: 'nearest' }); }
      return;
    }
  }

  if (!modal && !inInput && (e.ctrlKey && e.key === 'f')) {
    e.preventDefault(); disasmFilter.focus(); disasmFilter.select();
  }
});

// ── Drag & drop ────────────────────────────────────────────────────────────
dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', ()  => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop',      e  => { e.preventDefault(); dropZone.classList.remove('drag-over'); const f=e.dataTransfer.files[0]; if(f) handleFile(f); });
dropZone.addEventListener('click',     e  => { if(e.target!==fileInput) fileInput.click(); });
dropZone.addEventListener('keydown',   e  => { if(e.key==='Enter'||e.key===' '){e.preventDefault();fileInput.click();} });
fileInput.addEventListener('change',   e  => { const f=e.target.files[0]; if(f) handleFile(f); fileInput.value=''; });

newAnalysisBtn.addEventListener('click', () => {
  uploadPanel.hidden = false; analysisPanel.hidden = true; resultsWrapper.hidden = true;
  state = { ...state, report: null, sim: null, simRunning: false, currentAddr: null, bpAddrs: new Set() };
  clearError(); disasmFilter.value = '';
});

// ── Util ──────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
