// Disassembly wrapper — uses iced-x86 (WASM, no native compilation needed)
// Falls back to hex dump if unavailable.

const MAX_INSTRUCTIONS = 10000;
const MAX_BYTES = 2 * 1024 * 1024; // 2 MB cap

let icedX86 = null;
try {
  icedX86 = require('iced-x86');
} catch {
  console.warn('[disasm] iced-x86 not available — using hex dump fallback');
}

function disassemble(buffer, virtualAddress, bits) {
  const data = buffer.length > MAX_BYTES ? buffer.slice(0, MAX_BYTES) : buffer;

  if (!icedX86) {
    return { instructions: hexDump(data, virtualAddress), fallback: true };
  }

  try {
    const { Decoder, FastFormatter, DecoderOptions } = icedX86;

    const bitMode = bits === 64 ? 64 : bits === 16 ? 16 : 32;
    const decoder = new Decoder(bitMode, data, DecoderOptions.None);
    decoder.ip = BigInt(virtualAddress);

    const formatter = new FastFormatter();
    const instructions = [];
    let offset = 0;

    while (decoder.canDecode && instructions.length < MAX_INSTRUCTIONS) {
      const instr = decoder.decode();
      const ip = instr.ip;
      const size = instr.length;

      const addrStr = '0x' + ip.toString(16).padStart(bits === 64 ? 16 : 8, '0');
      const bytesHex = Array.from(data.slice(offset, offset + size))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');

      const formatted = formatter.format(instr);
      const spaceIdx = formatted.indexOf(' ');
      const mnemonic = spaceIdx < 0 ? formatted : formatted.slice(0, spaceIdx);
      const operands  = spaceIdx < 0 ? '' : formatted.slice(spaceIdx + 1).trim();

      instructions.push({ address: addrStr, bytes: bytesHex, mnemonic, operands });
      offset += size;

      instr.free();
    }

    formatter.free();
    decoder.free();

    return { instructions, fallback: false };
  } catch (err) {
    console.error('[disasm] Error:', err.message);
    return { instructions: hexDump(data, virtualAddress), fallback: true };
  }
}

function hexDump(buffer, startOffset = 0) {
  const rows = [];
  const limit = Math.min(buffer.length, 512);
  for (let i = 0; i < limit; i += 16) {
    const chunk = buffer.slice(i, Math.min(i + 16, limit));
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    const ascii = Array.from(chunk)
      .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.'))
      .join('');
    rows.push({
      address: '0x' + (startOffset + i).toString(16).padStart(8, '0'),
      bytes: hex,
      mnemonic: ascii,
      operands: '',
    });
  }
  return rows;
}

module.exports = { disassemble };
