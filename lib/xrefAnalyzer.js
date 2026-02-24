'use strict';

// Cross-reference analyzer — maps call/jmp targets to their sources

const CALL_SET = new Set(['call']);
const JMP_SET  = new Set(['jmp']);
const JCC_SET  = new Set([
  'jo','jno','js','jns','je','jne','jz','jnz',
  'jb','jnae','jc','jnb','jae','jnc','jbe','jna',
  'ja','jnbe','jl','jnge','jge','jnl','jle','jng',
  'jg','jnle','jp','jpe','jnp','jpo',
  'jcxz','jecxz','jrcxz','loop','loope','loopne',
]);

// Parse a direct target address from a FastFormatter NASM operand string.
// Returns a normalized '0xNNN...' string, or null for indirect/register targets.
function parseTarget(operands, bits) {
  if (!operands) return null;
  const pad = bits === 64 ? 16 : 8;

  // NASM hex: 401000h  (iced-x86 FastFormatter default)
  const hexH = operands.match(/^([0-9a-fA-F]+)h$/i);
  if (hexH) {
    return '0x' + BigInt('0x' + hexH[1]).toString(16).padStart(pad, '0');
  }

  // 0x-prefix style
  const hex0x = operands.match(/^(0x[0-9a-fA-F]+)$/i);
  if (hex0x) {
    return '0x' + BigInt(hex0x[1]).toString(16).padStart(pad, '0');
  }

  return null; // indirect / register target — can't resolve statically
}

function buildXrefs(instructions, bits) {
  // target_address → [{from: address, type: 'call'|'jmp'|'jcc'}]
  const xrefs = Object.create(null);

  for (const inst of instructions) {
    const mnem = inst.mnemonic.toLowerCase().trim();
    let type = null;
    if (CALL_SET.has(mnem)) type = 'call';
    else if (JMP_SET.has(mnem)) type = 'jmp';
    else if (JCC_SET.has(mnem)) type = 'jcc';
    if (!type) continue;

    const target = parseTarget((inst.operands || '').trim(), bits);
    if (!target) continue;

    if (!xrefs[target]) xrefs[target] = [];
    xrefs[target].push({ from: inst.address, type });
  }

  return xrefs;
}

module.exports = { buildXrefs };
