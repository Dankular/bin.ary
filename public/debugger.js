/* bin.ary — client-side x86/x64 simulator */
'use strict';

// ── Register tables ─────────────────────────────────────────────────────────
const R64  = ['rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','r8','r9','r10','r11','r12','r13','r14','r15','rip'];
const R32  = ['eax','ebx','ecx','edx','esi','edi','esp','ebp','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d','eip'];
const R16  = ['ax','bx','cx','dx','si','di','sp','bp','r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w','ip'];
const R8L  = ['al','bl','cl','dl','sil','dil','spl','bpl','r8b','r9b','r10b','r11b','r12b','r13b','r14b','r15b'];
const R8H  = ['ah','bh','ch','dh'];

const REG_MAP   = {};  // sub-reg → parent 64-bit name
const REG_BITS  = {};  // reg → bit width
const REG_SHIFT = {};  // reg → shift amount

R64.forEach((r, i) => {
  REG_MAP[r] = r; REG_BITS[r] = 64; REG_SHIFT[r] = 0;
  REG_MAP[R32[i]] = r; REG_BITS[R32[i]] = 32; REG_SHIFT[R32[i]] = 0;
  REG_MAP[R16[i]] = r; REG_BITS[R16[i]] = 16; REG_SHIFT[R16[i]] = 0;
  if (R8L[i]) { REG_MAP[R8L[i]] = r; REG_BITS[R8L[i]] = 8; REG_SHIFT[R8L[i]] = 0; }
});
R8H.forEach((r, i) => {
  const parents = ['rax','rbx','rcx','rdx'];
  REG_MAP[r] = parents[i]; REG_BITS[r] = 8; REG_SHIFT[r] = 8;
});

const JCC_SET = new Set([
  'jo','jno','js','jns','je','jne','jz','jnz',
  'jb','jnae','jc','jnb','jae','jnc','jbe','jna',
  'ja','jnbe','jl','jnge','jge','jnl','jle','jng',
  'jg','jnle','jp','jpe','jnp','jpo','jcxz','jecxz','jrcxz',
]);

// ── Memory ──────────────────────────────────────────────────────────────────
class Memory {
  constructor() { this._pages = new Map(); }
  _page(addr) {
    const pa = BigInt(addr) & ~0xFFFn;
    if (!this._pages.has(pa)) this._pages.set(pa, new Uint8Array(4096));
    return this._pages.get(pa);
  }
  r8(addr)   { addr = BigInt(addr); return BigInt(this._page(addr)[Number(addr & 0xFFFn)]); }
  w8(addr, v){ addr = BigInt(addr); this._page(addr)[Number(addr & 0xFFFn)] = Number(BigInt(v) & 0xFFn); }
  readLE(addr, bytes) {
    addr = BigInt(addr);
    let v = 0n;
    for (let i = 0; i < bytes; i++) v |= this.r8(addr + BigInt(i)) << BigInt(i * 8);
    return v;
  }
  writeLE(addr, val, bytes) {
    addr = BigInt(addr); val = BigInt(val);
    for (let i = 0; i < bytes; i++) this.w8(addr + BigInt(i), (val >> BigInt(i * 8)) & 0xFFn);
  }
  load(addr, data) {
    addr = BigInt(addr);
    for (let i = 0; i < data.length; i++) this.w8(addr + BigInt(i), data[i]);
  }
  // Dump 8 lines of 16 bytes around addr
  dump(addr, lines = 8) {
    addr = BigInt(addr) & ~0xFn;
    const rows = [];
    for (let i = 0; i < lines; i++) {
      const base = addr + BigInt(i * 16);
      const hex = [];
      const asc = [];
      for (let j = 0; j < 16; j++) {
        const b = Number(this.r8(base + BigInt(j)));
        hex.push(b.toString(16).padStart(2, '0'));
        asc.push(b >= 32 && b < 127 ? String.fromCharCode(b) : '.');
      }
      rows.push({ addr: '0x' + base.toString(16).padStart(16, '0'), hex: hex.join(' '), asc: asc.join('') });
    }
    return rows;
  }
}

// ── Registers ───────────────────────────────────────────────────────────────
class Registers {
  constructor() { this._r = {}; R64.forEach(r => { this._r[r] = 0n; }); }
  get(name) {
    name = name.toLowerCase();
    const p = REG_MAP[name]; if (!p) return 0n;
    const shift = BigInt(REG_SHIFT[name] || 0);
    const mask  = (1n << BigInt(REG_BITS[name] || 64)) - 1n;
    return (this._r[p] >> shift) & mask;
  }
  set(name, val) {
    name = name.toLowerCase(); val = BigInt(val);
    const p = REG_MAP[name]; if (!p) return;
    const shift = BigInt(REG_SHIFT[name] || 0);
    const mask  = (1n << BigInt(REG_BITS[name] || 64)) - 1n;
    const clr   = ~(mask << shift);
    this._r[p]  = (this._r[p] & clr) | ((val & mask) << shift);
    // 32-bit writes zero-extend in 64-bit mode
    if (REG_BITS[name] === 32) this._r[p] &= 0xFFFFFFFFn;
  }
  all() { return { ...this._r }; }
}

// ── Flags ────────────────────────────────────────────────────────────────────
class Flags {
  constructor() { this.cf = this.zf = this.sf = this.of = this.pf = this.af = false; }
  parity(n) {
    n = Number(BigInt(n) & 0xFFn);
    n ^= n >> 4; n ^= n >> 2; n ^= n >> 1;
    return !(n & 1);
  }
  setArith(result, a, b, bits, isSub) {
    const mask = (1n << BigInt(bits)) - 1n;
    const sign = 1n << BigInt(bits - 1);
    const r = BigInt.asUintN(bits, result);
    this.zf = r === 0n;
    this.sf = !!(r & sign);
    this.cf = result > mask || result < 0n;
    const sa = !!(BigInt(a) & sign), sb = !!(BigInt(b) & sign), sr = !!(r & sign);
    this.of = isSub ? (sa !== sb && sr !== sa) : (sa === sb && sr !== sa);
    this.pf = this.parity(r);
  }
  check(code) {
    switch (code) {
      case 'o':   return this.of;
      case 'no':  return !this.of;
      case 's':   return this.sf;
      case 'ns':  return !this.sf;
      case 'e': case 'z':   return this.zf;
      case 'ne': case 'nz': return !this.zf;
      case 'b': case 'nae': case 'c':  return this.cf;
      case 'nb': case 'ae': case 'nc': return !this.cf;
      case 'be': case 'na': return this.cf || this.zf;
      case 'a': case 'nbe': return !this.cf && !this.zf;
      case 'l': case 'nge': return this.sf !== this.of;
      case 'ge': case 'nl': return this.sf === this.of;
      case 'le': case 'ng': return this.zf || (this.sf !== this.of);
      case 'g': case 'nle': return !this.zf && (this.sf === this.of);
      case 'p': case 'pe':  return this.pf;
      case 'np': case 'po': return !this.pf;
      default: return false;
    }
  }
}

// ── Operand parser ───────────────────────────────────────────────────────────
function parseImm(str) {
  str = (str || '').trim().toLowerCase();
  const neg = str.startsWith('-'); if (neg) str = str.slice(1);
  let v = null;
  const hH = str.match(/^([0-9a-f]+)h$/);   if (hH) v = BigInt('0x' + hH[1]);
  const h0 = str.match(/^0x([0-9a-f]+)$/);  if (h0) v = BigInt('0x' + h0[1]);
  const d  = str.match(/^\d+$/);             if (d)  v = BigInt(str);
  return v !== null ? (neg ? -v : v) : null;
}

function evalAddr(expr, regs) {
  // Tokenise on '+' and '-' (keep sign)
  const toks = expr.replace(/-/g, '+-').split('+').map(t => t.trim()).filter(Boolean);
  let result = 0n;
  for (const tok of toks) {
    const neg = tok.startsWith('-');
    const t   = neg ? tok.slice(1) : tok;
    // scaled: reg*N
    const sc = t.match(/^([a-z][a-z0-9]*)[\*×](\d+)$/i);
    if (sc) { result += (neg ? -1n : 1n) * (regs.get(sc[1]) * BigInt(sc[2])); continue; }
    // register
    if (REG_MAP[t.toLowerCase()]) { result += (neg ? -1n : 1n) * regs.get(t); continue; }
    // immediate
    const iv = parseImm((neg ? '-' : '') + t);
    if (iv !== null) { result += iv; continue; }
  }
  return BigInt.asUintN(64, result);
}

function parseOp(str, regs, mem, defaultBytes) {
  str = (str || '').trim().toLowerCase();
  let bytes = defaultBytes;
  str = str.replace(/^(qword|dword|word|byte)\s+/, (_, s) => {
    bytes = { qword: 8, dword: 4, word: 2, byte: 1 }[s]; return '';
  });

  if (str.startsWith('[') && str.endsWith(']')) {
    const addr = evalAddr(str.slice(1, -1).trim(), regs);
    return { type: 'mem', bytes, addr,
      read:  ()  => mem.readLE(addr, bytes),
      write: (v) => mem.writeLE(addr, v, bytes) };
  }
  if (REG_MAP[str]) {
    const b = (REG_BITS[str] || 64) >> 3;
    return { type: 'reg', name: str, bytes: b,
      read:  ()  => regs.get(str),
      write: (v) => regs.set(str, v) };
  }
  const iv = parseImm(str);
  if (iv !== null) return { type: 'imm', bytes, read: () => iv, write: () => {} };
  return { type: 'unknown', bytes, read: () => 0n, write: () => {} };
}

function splitOps(str) {
  const parts = []; let depth = 0, cur = '';
  for (const ch of (str || '')) {
    if (ch === '[') depth++;
    else if (ch === ']') depth--;
    if (ch === ',' && depth === 0) { parts.push(cur.trim()); cur = ''; }
    else cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

// ── Simulator ────────────────────────────────────────────────────────────────
class X86Sim {
  constructor(bits) {
    this.bits       = bits || 64;
    this.regs       = new Registers();
    this.mem        = new Memory();
    this.flags      = new Flags();
    this.breakpoints = new Set();
    this._map       = new Map();  // normalised address → instruction
    this._list      = [];
    this._maxSteps  = 50000;
  }

  load(instructions) {
    this._list = instructions;
    this._map.clear();
    for (const inst of instructions) this._map.set(inst.address.toLowerCase(), inst);

    // Set RIP to first instruction
    if (instructions.length > 0) {
      this.regs.set('rip', BigInt(parseInt(instructions[0].address, 16)));
    }
    // Stack
    this.regs.set('rsp', 0x7fff0000n);
    for (let i = 0; i < 16; i++) this.mem._page(0x7fff0000n - BigInt(i * 0x1000));
  }

  ripAddr() {
    const pad = this.bits === 64 ? 16 : 8;
    return '0x' + this.regs.get('rip').toString(16).padStart(pad, '0');
  }

  currentInst() { return this._map.get(this.ripAddr()) || null; }

  step() {
    const inst = this.currentInst();
    if (!inst) return { error: 'RIP at unmapped address: ' + this.ripAddr() };
    try { this._exec(inst); return { ok: true, inst }; }
    catch (e) { return { error: e.message, inst }; }
  }

  _exec(inst) {
    const mnem = inst.mnemonic.toLowerCase().trim();
    const ops  = splitOps(inst.operands);
    const db   = this.bits >> 3; // default bytes

    // Advance RIP (default; jumps override)
    const idx  = this._list.findIndex(i => i.address === inst.address);
    const next = this._list[idx + 1];
    const nextRip = next ? BigInt(parseInt(next.address, 16)) : this.regs.get('rip');
    this.regs.set('rip', nextRip);

    const op = (i) => parseOp(ops[i], this.regs, this.mem, db);
    const jmp = (addr) => { if (addr !== null) this.regs.set('rip', addr); };

    const resolveTarget = (s) => {
      s = (s || '').trim().toLowerCase();
      if (REG_MAP[s]) return this.regs.get(s);
      const iv = parseImm(s); if (iv !== null) return iv;
      if (s.startsWith('[') && s.endsWith(']'))
        return this.mem.readLE(evalAddr(s.slice(1,-1), this.regs), db);
      return null;
    };

    switch (mnem) {
      case 'nop': case 'int3': case 'endbr64': case 'endbr32': case 'pause': break;

      case 'mov': case 'movq': case 'movl': {
        const d = op(0), s = op(1); d.write(s.read()); break;
      }
      case 'movzx': {
        const d = op(0), s = op(1);
        d.write(BigInt.asUintN(d.bytes * 8, s.read())); break;
      }
      case 'movsx': case 'movsxd': {
        const d = op(0), s = op(1);
        const sb = s.bytes * 8; const sv = s.read();
        const sign = 1n << BigInt(sb - 1);
        const ext = sv & sign ? sv | (~((1n << BigInt(sb)) - 1n)) : sv;
        d.write(BigInt.asUintN(d.bytes * 8, ext)); break;
      }
      case 'push': {
        const v = op(0).read();
        const rsp = this.regs.get('rsp') - BigInt(db);
        this.regs.set('rsp', rsp);
        this.mem.writeLE(rsp, v, db); break;
      }
      case 'pop': {
        const rsp = this.regs.get('rsp');
        op(0).write(this.mem.readLE(rsp, db));
        this.regs.set('rsp', rsp + BigInt(db)); break;
      }
      case 'add': {
        const d = op(0), s = op(1); const bits = d.bytes * 8;
        const a = d.read(), b = s.read(), r = a + b;
        this.flags.setArith(r, a, b, bits, false);
        d.write(BigInt.asUintN(bits, r)); break;
      }
      case 'sub': {
        const d = op(0), s = op(1); const bits = d.bytes * 8;
        const a = d.read(), b = s.read(), r = a - b;
        this.flags.setArith(r, a, b, bits, true);
        d.write(BigInt.asUintN(bits, r)); break;
      }
      case 'xor': {
        const d = op(0), s = op(1); const bits = d.bytes * 8;
        const r = d.read() ^ s.read();
        this.flags.cf = this.flags.of = false;
        this.flags.zf = r === 0n; this.flags.sf = !!(r & (1n << BigInt(bits-1)));
        this.flags.pf = this.flags.parity(r);
        d.write(BigInt.asUintN(bits, r)); break;
      }
      case 'and': {
        const d = op(0), s = op(1); const bits = d.bytes * 8;
        const r = d.read() & s.read();
        this.flags.cf = this.flags.of = false;
        this.flags.zf = r === 0n; this.flags.sf = !!(r & (1n << BigInt(bits-1)));
        this.flags.pf = this.flags.parity(r);
        d.write(r); break;
      }
      case 'or': {
        const d = op(0), s = op(1); const bits = d.bytes * 8;
        const r = d.read() | s.read();
        this.flags.cf = this.flags.of = false;
        this.flags.zf = r === 0n; this.flags.sf = !!(r & (1n << BigInt(bits-1)));
        d.write(r); break;
      }
      case 'not': { const d=op(0); const b=d.bytes*8; d.write(BigInt.asUintN(b,~d.read())); break; }
      case 'neg': {
        const d=op(0); const bits=d.bytes*8; const v=d.read();
        const r=-v; this.flags.cf=v!==0n;
        this.flags.zf=(BigInt.asUintN(bits,r))===0n;
        this.flags.sf=!!(BigInt.asUintN(bits,r)&(1n<<BigInt(bits-1)));
        this.flags.of=v===(1n<<BigInt(bits-1));
        d.write(BigInt.asUintN(bits,r)); break;
      }
      case 'inc': {
        const d=op(0); const bits=d.bytes*8; const a=d.read();
        const r=a+1n; d.write(BigInt.asUintN(bits,r));
        this.flags.zf=BigInt.asUintN(bits,r)===0n;
        this.flags.sf=!!(BigInt.asUintN(bits,r)&(1n<<BigInt(bits-1)));
        this.flags.of=a===((1n<<BigInt(bits-1))-1n); break;
      }
      case 'dec': {
        const d=op(0); const bits=d.bytes*8; const a=d.read();
        const r=a-1n; d.write(BigInt.asUintN(bits,r));
        this.flags.zf=BigInt.asUintN(bits,r)===0n;
        this.flags.sf=!!(BigInt.asUintN(bits,r)&(1n<<BigInt(bits-1)));
        this.flags.of=a===(1n<<BigInt(bits-1)); break;
      }
      case 'cmp': {
        const d=op(0), s=op(1); const bits=d.bytes*8;
        const a=d.read(), b=s.read();
        this.flags.setArith(a-b, a, b, bits, true); break;
      }
      case 'test': {
        const d=op(0), s=op(1); const bits=d.bytes*8;
        const r=d.read()&s.read();
        this.flags.cf=this.flags.of=false;
        this.flags.zf=r===0n; this.flags.sf=!!(r&(1n<<BigInt(bits-1)));
        this.flags.pf=this.flags.parity(r); break;
      }
      case 'lea': {
        const d=op(0); const s=(ops[1]||'').trim().toLowerCase().replace(/^(qword|dword|word|byte)\s+/,'');
        if (s.startsWith('[') && s.endsWith(']'))
          d.write(evalAddr(s.slice(1,-1).trim(), this.regs));
        break;
      }
      case 'shl': case 'sal': {
        const d=op(0),s=op(1); const bits=d.bytes*8;
        const sh=Number(s.read()&0x3Fn)%bits; const v=d.read();
        if (sh>0) this.flags.cf=!!(v&(1n<<BigInt(bits-sh)));
        const r=BigInt.asUintN(bits, v<<BigInt(sh));
        this.flags.zf=r===0n; this.flags.sf=!!(r&(1n<<BigInt(bits-1)));
        d.write(r); break;
      }
      case 'shr': {
        const d=op(0),s=op(1); const bits=d.bytes*8;
        const sh=Number(s.read()&0x3Fn)%bits; const v=d.read();
        if (sh>0) this.flags.cf=!!(v&(1n<<BigInt(sh-1)));
        const r=v>>BigInt(sh);
        this.flags.zf=r===0n; this.flags.sf=!!(r&(1n<<BigInt(bits-1)));
        d.write(r); break;
      }
      case 'sar': {
        const d=op(0),s=op(1); const bits=d.bytes*8;
        const sh=Number(s.read()&0x3Fn)%bits;
        let v=d.read(); const sign=1n<<BigInt(bits-1);
        if (v&sign) v|=~((1n<<BigInt(bits))-1n);
        const r=BigInt.asUintN(bits, v>>BigInt(sh));
        this.flags.zf=r===0n; this.flags.sf=!!(r&sign);
        d.write(r); break;
      }
      case 'call': {
        this.mem.writeLE(this.regs.get('rsp') - BigInt(db), nextRip, db);
        this.regs.set('rsp', this.regs.get('rsp') - BigInt(db));
        jmp(resolveTarget(ops[0])); break;
      }
      case 'ret': case 'retn': case 'retq': {
        const rsp=this.regs.get('rsp');
        const ret=this.mem.readLE(rsp, db);
        this.regs.set('rsp', rsp+BigInt(db));
        jmp(ret); break;
      }
      case 'jmp': { jmp(resolveTarget(ops[0])); break; }
      default: {
        // Jcc
        if (mnem.startsWith('j')) {
          const code = mnem.slice(1);
          if (this.flags.check(code)) jmp(resolveTarget(ops[0]));
        }
      }
    }
  }

  stateSnapshot() {
    return {
      regs:  this.regs.all(),
      flags: { cf: this.flags.cf, zf: this.flags.zf, sf: this.flags.sf,
               of: this.flags.of, pf: this.flags.pf },
      stack: this.mem.dump(this.regs.get('rsp'), 6),
      rip:   this.ripAddr(),
      inst:  this.currentInst(),
    };
  }

  reset(instructions) { this.regs = new Registers(); this.mem = new Memory(); this.flags = new Flags(); this.load(instructions); }
}

window.X86Sim = X86Sim;
