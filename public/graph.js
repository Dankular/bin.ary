/* bin.ary — Graph renderer: CFG, Xref Graph, Proximity View */
'use strict';

const JMP_END = new Set(['jmp','ret','retn','retq','retf','ud2','hlt']);
const JCC_ALL = new Set([
  'je','jne','jz','jnz','jg','jge','jl','jle','ja','jae','jb','jbe',
  'jp','jnp','jo','jno','js','jns','jcxz','jecxz','jrcxz',
]);

// ── Parse target address from NASM-style operand ────────────────────────────
function parseTarget(op, bits) {
  if (!op) return null;
  const pad = bits === 64 ? 16 : 8;
  const hH  = (op || '').trim().match(/^([0-9a-fA-F]+)h$/i);
  if (hH) return '0x' + BigInt('0x' + hH[1]).toString(16).padStart(pad, '0');
  const h0  = (op || '').trim().match(/^(0x[0-9a-fA-F]+)$/i);
  if (h0) return '0x' + BigInt(h0[1]).toString(16).padStart(pad, '0');
  return null;
}

// ── CFG builder ──────────────────────────────────────────────────────────────
function buildCFG(instructions, bits) {
  if (!instructions || instructions.length === 0) return { blocks: [], blockMap: new Map() };

  // 1. Mark block-start addresses
  const starts = new Set([instructions[0].address]);
  for (let i = 0; i < instructions.length; i++) {
    const inst = instructions[i];
    const m = inst.mnemonic.toLowerCase().trim();
    if (JMP_END.has(m) || JCC_ALL.has(m) || m === 'call') {
      if (instructions[i + 1]) starts.add(instructions[i + 1].address);
      const t = parseTarget((inst.operands || ''), bits);
      if (t) starts.add(t);
    }
  }

  // 2. Build blocks
  const blocks = [];
  let cur = null;
  for (const inst of instructions) {
    if (starts.has(inst.address)) {
      if (cur) blocks.push(cur);
      cur = { id: inst.address, insts: [inst], succs: [] };
    } else if (cur) {
      cur.insts.push(inst);
    }
  }
  if (cur) blocks.push(cur);

  // 3. Build edges
  const bmap = new Map(blocks.map(b => [b.id, b]));
  for (const block of blocks) {
    const last = block.insts[block.insts.length - 1];
    const m = last.mnemonic.toLowerCase().trim();
    const li = instructions.findIndex(i => i.address === last.address);
    const nextAddr = instructions[li + 1] ? instructions[li + 1].address : null;

    if (JCC_ALL.has(m)) {
      if (nextAddr && bmap.has(nextAddr)) block.succs.push({ to: nextAddr, type: 'fall' });
      const t = parseTarget(last.operands, bits);
      if (t && bmap.has(t)) block.succs.push({ to: t, type: 'jump' });
    } else if (m === 'jmp') {
      const t = parseTarget(last.operands, bits);
      if (t && bmap.has(t)) block.succs.push({ to: t, type: 'jump' });
    } else if (!JMP_END.has(m)) {
      if (nextAddr && bmap.has(nextAddr)) block.succs.push({ to: nextAddr, type: 'fall' });
    }
  }

  return { blocks, blockMap: bmap };
}

// ── Layout: BFS layering, then simple x assignment ──────────────────────────
function layoutCFG(blocks, blockMap) {
  if (blocks.length === 0) return [];

  const layers = new Map(); // id → layer
  const queue  = [{ id: blocks[0].id, layer: 0 }];
  const visited = new Set();

  while (queue.length) {
    const { id, layer } = queue.shift();
    if (visited.has(id)) continue;
    visited.add(id);
    layers.set(id, Math.max(layer, layers.get(id) ?? 0));
    const block = blockMap.get(id);
    if (block) for (const s of block.succs) queue.push({ id: s.to, layer: layer + 1 });
  }

  // Group by layer
  const byLayer = new Map();
  for (const [id, layer] of layers) {
    if (!byLayer.has(layer)) byLayer.set(layer, []);
    byLayer.get(layer).push(id);
  }

  // Assign pixel positions
  const BLOCK_W = 280, BLOCK_GAP_X = 40, BLOCK_GAP_Y = 80;
  const positions = new Map();

  for (const [layer, ids] of [...byLayer.entries()].sort((a,b) => a[0]-b[0])) {
    const totalW = ids.length * BLOCK_W + (ids.length - 1) * BLOCK_GAP_X;
    ids.forEach((id, i) => {
      const h = Math.max(60, Math.min(blockMap.get(id)?.insts.length || 1, 8) * 18 + 28);
      positions.set(id, {
        x: i * (BLOCK_W + BLOCK_GAP_X) - totalW / 2 + BLOCK_W / 2,
        y: layer * (120 + BLOCK_GAP_Y),
        w: BLOCK_W, h,
      });
    });
  }

  // Also position unvisited blocks (orphaned)
  let orphanY = (byLayer.size) * (120 + BLOCK_GAP_Y);
  for (const b of blocks) {
    if (!positions.has(b.id)) {
      positions.set(b.id, { x: 0, y: orphanY, w: BLOCK_W, h: 60 });
      orphanY += 140;
    }
  }

  return positions;
}

// ── SVG helpers ──────────────────────────────────────────────────────────────
function svgEl(tag, attrs, text) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}

function bezierPath(x1,y1, x2,y2) {
  const cy = (y1 + y2) / 2;
  return `M${x1},${y1} C${x1},${cy} ${x2},${cy} ${x2},${y2}`;
}

// ── CFG Renderer ─────────────────────────────────────────────────────────────
function renderCFG(container, instructions, bits, currentAddr, onBlockClick) {
  const { blocks, blockMap } = buildCFG(instructions, bits);
  const positions = layoutCFG(blocks, blockMap);
  container.innerHTML = '';

  if (blocks.length === 0) {
    container.innerHTML = '<p class="graph-empty">No control-flow graph available</p>';
    return;
  }

  // Compute canvas size
  let maxX = 0, maxY = 0;
  for (const p of positions.values()) { maxX = Math.max(maxX, p.x + p.w/2); maxY = Math.max(maxY, p.y + p.h); }

  const W = (maxX + 200) * 2;
  const H = maxY + 200;

  const svg = svgEl('svg', { width: W, height: H, class: 'cfg-svg' });

  // Defs: arrowhead markers
  const defs = svgEl('defs');
  for (const [id, col] of [['arr-fall','#22c55e'],['arr-jump','#f59e0b'],['arr-back','#f43f5e']]) {
    const marker = svgEl('marker', { id, markerWidth: 8, markerHeight: 8, refX: 6, refY: 3, orient: 'auto' });
    marker.appendChild(svgEl('polygon', { points: '0 0, 8 3, 0 6', fill: col }));
    defs.appendChild(marker);
  }
  svg.appendChild(defs);

  const g = svgEl('g', { transform: `translate(${W/2},60)` });

  // Edges
  for (const block of blocks) {
    const sp = positions.get(block.id);
    if (!sp) continue;
    for (const succ of block.succs) {
      const tp = positions.get(succ.to);
      if (!tp) continue;
      const isBack = tp.y <= sp.y;
      const col    = succ.type === 'fall' ? '#22c55e' : isBack ? '#f43f5e' : '#f59e0b';
      const markId = succ.type === 'fall' ? 'arr-fall' : isBack ? 'arr-back' : 'arr-jump';
      const x1 = sp.x + (succ.type === 'jump' ? sp.w * 0.6 : sp.w * 0.4);
      const y1 = sp.y + sp.h;
      const x2 = tp.x + tp.w / 2;
      const y2 = tp.y;
      const path = svgEl('path', {
        d: bezierPath(x1, y1, x2, y2),
        stroke: col, 'stroke-width': 1.5, fill: 'none',
        'marker-end': `url(#${markId})`,
      });
      g.appendChild(path);
    }
  }

  // Blocks
  for (const block of blocks) {
    const p = positions.get(block.id);
    if (!p) continue;
    const isCurrent = block.id === currentAddr;
    const bg = isCurrent ? '#1a2f1a' : '#12151e';
    const border = isCurrent ? '#22c55e' : '#232840';

    const bg_rect = svgEl('rect', { x: p.x - p.w/2, y: p.y, width: p.w, height: p.h, rx: 4,
      fill: bg, stroke: border, 'stroke-width': isCurrent ? 2 : 1, class: 'cfg-block', 'data-addr': block.id });

    bg_rect.addEventListener('click', () => onBlockClick && onBlockClick(block.id));
    g.appendChild(bg_rect);

    // Header
    const hdr = svgEl('text', { x: p.x - p.w/2 + 8, y: p.y + 14, class: 'cfg-hdr', fill: '#4d5a80', 'font-size': 10 },
      block.id);
    g.appendChild(hdr);

    // Instructions (max 8)
    const maxShow = 8;
    block.insts.slice(0, maxShow).forEach((inst, i) => {
      const tx = p.x - p.w/2 + 8;
      const ty = p.y + 26 + i * 16;
      const mn = svgEl('text', { x: tx, y: ty, class: 'cfg-mnem', fill: '#00e5a0', 'font-size': 11 }, inst.mnemonic);
      g.appendChild(mn);
      const op = svgEl('text', { x: tx + 56, y: ty, class: 'cfg-ops', fill: '#c4aa6e', 'font-size': 11 },
        (inst.operands || '').slice(0, 22));
      g.appendChild(op);
    });
    if (block.insts.length > maxShow) {
      const more = svgEl('text', { x: p.x - p.w/2 + 8, y: p.y + 26 + maxShow * 16, fill: '#5a6285', 'font-size': 10 },
        `+${block.insts.length - maxShow} more…`);
      g.appendChild(more);
    }
  }

  svg.appendChild(g);
  container.appendChild(svg);
  attachPanZoom(container, svg, g);
}

// ── Xref Graph Renderer ──────────────────────────────────────────────────────
function renderXrefGraph(container, addr, xrefs, funcLabels, bits, onNodeClick) {
  container.innerHTML = '';

  // Collect callers (who calls addr) and callees (what addr calls — from xrefs[target]=addr)
  const callers = xrefs[addr] || [];
  const callees = [];
  for (const [target, refs] of Object.entries(xrefs)) {
    for (const ref of refs) {
      if (ref.from === addr) callees.push({ addr: target, type: ref.type });
    }
  }

  if (callers.length === 0 && callees.length === 0) {
    container.innerHTML = '<p class="graph-empty">No cross-references for this address</p>';
    return;
  }

  const NODE_W = 180, NODE_H = 36, GAP_Y = 20;
  const CX = 300, CY = Math.max((callers.length + callees.length) / 2 * (NODE_H + GAP_Y) + 60, 120);

  const totalH = Math.max(callers.length, callees.length, 1) * (NODE_H + GAP_Y) + 40;
  const svg = svgEl('svg', { width: 640, height: totalH + 40, class: 'xref-svg' });

  // Arrow defs
  const defs = svgEl('defs');
  for (const [id, col] of [['xa-call','#4af626'],['xa-jmp','#f59e0b'],['xa-jcc','#60a5fa']]) {
    const m = svgEl('marker', { id, markerWidth: 8, markerHeight: 8, refX: 6, refY: 3, orient: 'auto' });
    m.appendChild(svgEl('polygon', { points: '0 0, 8 3, 0 6', fill: col }));
    defs.appendChild(m);
  }
  svg.appendChild(defs);

  function node(x, y, label, kind, targetAddr) {
    const g = svgEl('g', { class: 'xnode', 'data-addr': targetAddr || '' });
    const bg = svgEl('rect', { x: x - NODE_W/2, y: y - NODE_H/2, width: NODE_W, height: NODE_H, rx: 4,
      fill: kind === 'center' ? '#1a2f1a' : '#1a1e2b',
      stroke: kind === 'center' ? '#22c55e' : kind === 'caller' ? '#0088ff' : '#f59e0b',
      'stroke-width': kind === 'center' ? 2 : 1 });
    g.appendChild(bg);
    const txt = svgEl('text', { x, y: y + 5, 'text-anchor': 'middle', fill: '#d4daf0', 'font-size': 11,
      'font-family': 'monospace' }, label.slice(0, 22));
    g.appendChild(txt);
    if (targetAddr) g.style.cursor = 'pointer';
    g.addEventListener('click', () => targetAddr && onNodeClick && onNodeClick(targetAddr));
    return g;
  }

  // Center node
  const centerLabel = funcLabels[addr] ? `${funcLabels[addr]}\n${addr}` : addr;
  svg.appendChild(node(CX, totalH / 2, centerLabel.split('\n')[0], 'center', addr));

  // Caller nodes (left side)
  callers.slice(0, 12).forEach((c, i) => {
    const y = (i + 0.5) * ((totalH) / Math.max(callers.length, 1));
    const lbl = funcLabels[c.from] || c.from;
    svg.appendChild(node(90 + NODE_W/2, y, lbl, 'caller', c.from));
    const col = c.type === 'call' ? '#4af626' : '#60a5fa';
    const mId = c.type === 'call' ? 'xa-call' : 'xa-jcc';
    svg.appendChild(svgEl('path', { d: `M${90+NODE_W},${y} L${CX-NODE_W/2},${totalH/2}`,
      stroke: col, 'stroke-width': 1.5, fill: 'none', 'marker-end': `url(#${mId})` }));
  });

  // Callee nodes (right side)
  callees.slice(0, 12).forEach((c, i) => {
    const y = (i + 0.5) * ((totalH) / Math.max(callees.length, 1));
    const lbl = funcLabels[c.addr] || c.addr;
    svg.appendChild(node(640 - 90 - NODE_W/2, y, lbl, 'callee', c.addr));
    const col = c.type === 'call' ? '#4af626' : '#f59e0b';
    const mId = c.type === 'call' ? 'xa-call' : 'xa-jmp';
    svg.appendChild(svgEl('path', { d: `M${CX+NODE_W/2},${totalH/2} L${640-90-NODE_W},${y}`,
      stroke: col, 'stroke-width': 1.5, fill: 'none', 'marker-end': `url(#${mId})` }));
  });

  container.appendChild(svg);
  attachPanZoom(container, svg, svg);
}

// ── Proximity View ────────────────────────────────────────────────────────────
function renderProximity(container, addr, xrefs, funcLabels, onNodeClick) {
  // Show addr and up to 2 hops of relationships
  container.innerHTML = '';

  const center = addr;
  const callers = (xrefs[addr] || []).slice(0, 6).map(r => r.from);
  const calleeMap = {};
  for (const [target, refs] of Object.entries(xrefs)) {
    for (const ref of refs) {
      if (ref.from === addr) calleeMap[target] = true;
    }
  }
  const callees = Object.keys(calleeMap).slice(0, 6);

  if (callers.length === 0 && callees.length === 0) {
    container.innerHTML = '<p class="graph-empty">No proximity data for this address</p>';
    return;
  }

  const NODE_W = 160, NODE_H = 32;
  const rows = Math.max(callers.length, callees.length, 1);
  const H = rows * 52 + 80;
  const svg = svgEl('svg', { width: 560, height: H, class: 'prox-svg' });

  function pnode(x, y, label, color, taddr) {
    const g = svgEl('g');
    g.appendChild(svgEl('rect', { x: x-NODE_W/2, y: y-NODE_H/2, width: NODE_W, height: NODE_H, rx: 4,
      fill: '#12151e', stroke: color, 'stroke-width': 1 }));
    g.appendChild(svgEl('text', { x, y: y+4, 'text-anchor': 'middle', fill: '#d4daf0', 'font-size': 10,
      'font-family': 'monospace' }, label.slice(0,20)));
    if (taddr) { g.style.cursor='pointer'; g.addEventListener('click', ()=>onNodeClick&&onNodeClick(taddr)); }
    svg.appendChild(g);
    return g;
  }

  const cy = H / 2;
  pnode(280, cy, funcLabels[center]||center, '#22c55e', center);
  callers.forEach((c, i) => {
    const y = (i+0.5)*(H/Math.max(callers.length,1));
    pnode(80, y, funcLabels[c]||c, '#0088ff', c);
    svg.appendChild(svgEl('line',{x1:80+NODE_W/2,y1:y,x2:280-NODE_W/2,y2:cy,stroke:'#0088ff','stroke-width':1}));
  });
  callees.forEach((c, i) => {
    const y = (i+0.5)*(H/Math.max(callees.length,1));
    pnode(480, y, funcLabels[c]||c, '#f59e0b', c);
    svg.appendChild(svgEl('line',{x1:280+NODE_W/2,y1:cy,x2:480-NODE_W/2,y2:y,stroke:'#f59e0b','stroke-width':1}));
  });

  container.appendChild(svg);
}

// ── Pan/Zoom ─────────────────────────────────────────────────────────────────
function attachPanZoom(container, svg, content) {
  let zoom = 1, px = 0, py = 0, dragging = false, lx = 0, ly = 0;
  const update = () => content.setAttribute('transform', `translate(${px},${py}) scale(${zoom})`);

  svg.addEventListener('wheel', e => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 0.88;
    zoom = Math.min(4, Math.max(0.1, zoom * factor));
    update();
  }, { passive: false });

  svg.addEventListener('mousedown', e => { dragging=true; lx=e.clientX; ly=e.clientY; svg.style.cursor='grabbing'; });
  window.addEventListener('mouseup',  () => { dragging=false; svg.style.cursor=''; });
  window.addEventListener('mousemove', e => {
    if (!dragging) return;
    px += e.clientX - lx; py += e.clientY - ly;
    lx = e.clientX; ly = e.clientY; update();
  });

  // Touch
  let lastDist = 0;
  svg.addEventListener('touchstart', e => {
    if (e.touches.length === 1) { dragging=true; lx=e.touches[0].clientX; ly=e.touches[0].clientY; }
    if (e.touches.length === 2) lastDist = Math.hypot(e.touches[0].clientX-e.touches[1].clientX, e.touches[0].clientY-e.touches[1].clientY);
  });
  svg.addEventListener('touchmove', e => {
    e.preventDefault();
    if (e.touches.length === 1 && dragging) {
      px+=e.touches[0].clientX-lx; py+=e.touches[0].clientY-ly;
      lx=e.touches[0].clientX; ly=e.touches[0].clientY; update();
    }
    if (e.touches.length === 2) {
      const d = Math.hypot(e.touches[0].clientX-e.touches[1].clientX, e.touches[0].clientY-e.touches[1].clientY);
      zoom = Math.min(4, Math.max(0.1, zoom * (d/lastDist))); lastDist=d; update();
    }
  }, { passive: false });
  svg.addEventListener('touchend', ()=>dragging=false);
}

window.BinaryGraph = { renderCFG, renderXrefGraph, renderProximity };
