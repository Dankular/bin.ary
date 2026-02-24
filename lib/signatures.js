'use strict';

// Detect function boundaries and match known byte signatures

const END_MNEMS = new Set(['ret', 'retn', 'retq', 'retf', 'ud2', 'hlt']);

function detectFunctions(instructions) {
  // Returns Map<address, label>
  const funcs = new Map();
  let atBoundary = true;

  for (let i = 0; i < instructions.length; i++) {
    const inst = instructions[i];
    const mnem = inst.mnemonic.toLowerCase().trim();

    if (atBoundary && mnem !== 'int3') {
      const short = inst.address.replace(/^0x0*/, '') || '0';
      funcs.set(inst.address, `sub_${short}`);
      atBoundary = false;
    }

    if (END_MNEMS.has(mnem) || mnem === 'int3') {
      atBoundary = true;
    }
  }

  return funcs;
}

// Well-known byte-level patterns
const BYTE_SIGS = [
  { bytes: [0xf3, 0xaa],             name: 'rep stosb',   note: 'byte memset' },
  { bytes: [0xf3, 0xab],             name: 'rep stosd',   note: 'dword memset' },
  { bytes: [0xf3, 0xa4],             name: 'rep movsb',   note: 'byte memcpy' },
  { bytes: [0xf3, 0xa5],             name: 'rep movsd',   note: 'dword memcpy' },
  { bytes: [0x0f, 0x05],             name: 'syscall',     note: 'Linux syscall' },
  { bytes: [0xcd, 0x80],             name: 'int 80h',     note: 'Linux int 0x80' },
  { bytes: [0xff, 0x25],             name: 'jmp [IAT]',   note: 'Indirect jump (import)' },
  { bytes: [0xff, 0x15],             name: 'call [IAT]',  note: 'Indirect call (import)' },
];

function matchByteSignatures(codeBuffer, baseVA, bits) {
  const pad = bits === 64 ? 16 : 8;
  const results = [];
  const limit = Math.min(codeBuffer.length, 1024 * 1024);

  for (const sig of BYTE_SIGS) {
    for (let i = 0; i < limit - sig.bytes.length; i++) {
      let ok = true;
      for (let j = 0; j < sig.bytes.length; j++) {
        if (codeBuffer[i + j] !== sig.bytes[j]) { ok = false; break; }
      }
      if (ok) {
        const va = Number(baseVA) + i;
        results.push({
          address: '0x' + va.toString(16).padStart(pad, '0'),
          name: sig.name,
          note: sig.note,
        });
        i += sig.bytes.length - 1;
      }
    }
  }

  return results;
}

module.exports = { detectFunctions, matchByteSignatures };
