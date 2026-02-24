const fs = require('fs');
const { parsePE } = require('./peParser');
const { parseELF } = require('./elfParser');
const { disassemble } = require('./disassembler');

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function detectFormat(buffer) {
  if (buffer.length < 4) return { type: 'raw', description: 'Raw binary (too small to identify)' };

  // MZ (PE)
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
    return { type: 'pe', description: 'PE (Portable Executable)' };
  }

  // ELF
  if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
    return { type: 'elf', description: 'ELF (Executable and Linkable Format)' };
  }

  // Mach-O (fat or thin)
  const magic32 = buffer.readUInt32BE(0);
  if (magic32 === 0xfeedface || magic32 === 0xcefaedfe) {
    return { type: 'macho', description: 'Mach-O (32-bit)' };
  }
  if (magic32 === 0xfeedfacf || magic32 === 0xcffaedfe) {
    return { type: 'macho', description: 'Mach-O (64-bit)' };
  }
  if (magic32 === 0xcafebabe) {
    return { type: 'macho', description: 'Mach-O FAT binary' };
  }

  // Java class file
  if (buffer[0] === 0xca && buffer[1] === 0xfe && buffer[2] === 0xba && buffer[3] === 0xbe) {
    return { type: 'class', description: 'Java class file' };
  }

  return { type: 'raw', description: 'Raw binary / unknown format' };
}

function findCodeSection(sections, bits) {
  // Prefer .text section
  const text = sections.find((s) => s.name === '.text' || s.name === '__text');
  if (text) return text;
  // Fall back to any executable section
  const exec = sections.find((s) => s.isCode && s.rawSize > 0);
  if (exec) return exec;
  // Last resort: first section with data
  return sections.find((s) => s.rawSize > 0) || null;
}

async function analyzeFile(filePath, originalName, fileSize, emit) {
  // Stage 0: mark upload done
  emit('stage', {
    id: 'upload',
    status: 'done',
    label: 'File Uploaded',
    result: `${originalName}  (${formatSize(fileSize)})`,
  });

  // ── Stage 1: Detect format ──────────────────────────────────────────────
  emit('stage', { id: 'detect', status: 'running', label: 'Detecting Format' });
  await delay(80);

  const buffer = fs.readFileSync(filePath);
  const fmt = detectFormat(buffer);

  emit('stage', { id: 'detect', status: 'done', label: 'Detecting Format', result: fmt.description });

  // ── Stage 2: Parse headers ─────────────────────────────────────────────
  emit('stage', { id: 'headers', status: 'running', label: 'Parsing Headers' });
  await delay(120);

  let parsed;
  try {
    if (fmt.type === 'pe') parsed = parsePE(buffer);
    else if (fmt.type === 'elf') parsed = parseELF(buffer);
    else {
      parsed = {
        format: fmt.type.toUpperCase(),
        type: fmt.description,
        arch: 'unknown',
        bits: 32,
        sections: [],
        numSections: 0,
        summary: fmt.description,
        info: {},
      };
    }
  } catch (err) {
    emit('stage', { id: 'headers', status: 'error', label: 'Parsing Headers', result: err.message });
    throw err;
  }

  emit('stage', {
    id: 'headers',
    status: 'done',
    label: 'Parsing Headers',
    result: parsed.summary,
  });

  // ── Stage 3: Extract sections ──────────────────────────────────────────
  emit('stage', { id: 'sections', status: 'running', label: 'Extracting Sections' });
  await delay(80);

  const sections = parsed.sections || [];
  emit('stage', {
    id: 'sections',
    status: 'done',
    label: 'Extracting Sections',
    result: `${sections.length} section${sections.length !== 1 ? 's' : ''} found`,
  });

  // ── Stage 4: Disassemble ───────────────────────────────────────────────
  emit('stage', { id: 'disasm', status: 'running', label: 'Disassembling Code' });
  await delay(60);

  let instructions = [];
  let disasmFallback = false;
  let disasmSection = null;

  const codeSection = findCodeSection(sections, parsed.bits);
  if (codeSection && codeSection.rawSize > 0 && codeSection.rawOffset > 0) {
    const rawEnd = Math.min(codeSection.rawOffset + codeSection.rawSize, buffer.length);
    if (rawEnd > codeSection.rawOffset) {
      const codeBuffer = buffer.slice(codeSection.rawOffset, rawEnd);
      const va =
        typeof codeSection.virtualAddress === 'number'
          ? codeSection.virtualAddress
          : Number(codeSection.virtualAddress);

      const result = disassemble(codeBuffer, va, parsed.bits);
      instructions = result.instructions;
      disasmFallback = result.fallback;
      disasmSection = codeSection.name;
    }
  } else if (sections.length === 0) {
    // Raw binary — try to disassemble from byte 0
    const result = disassemble(buffer, 0, 32);
    instructions = result.instructions;
    disasmFallback = result.fallback;
  }

  emit('stage', {
    id: 'disasm',
    status: 'done',
    label: 'Disassembling Code',
    result: disasmFallback
      ? `${instructions.length} hex rows (no disassembler)`
      : `${instructions.length} instructions`,
  });

  // ── Stage 5: Build report ──────────────────────────────────────────────
  emit('stage', { id: 'report', status: 'running', label: 'Building Report' });
  await delay(60);

  const report = {
    file: {
      name: originalName,
      size: fileSize,
      sizeStr: formatSize(fileSize),
      format: parsed.format,
      type: parsed.type,
      arch: parsed.arch,
      bits: parsed.bits,
      ...parsed.info,
    },
    sections: sections.map((s) => ({
      name: s.name,
      virtualAddress: '0x' + Number(s.virtualAddress).toString(16).padStart(8, '0'),
      size: formatSize(s.rawSize || s.virtualSize || 0),
      rawSize: s.rawSize || 0,
      flags: s.flagsStr || '',
      isCode: s.isCode,
      type: s.typeStr || '',
    })),
    disasm: {
      section: disasmSection,
      fallback: disasmFallback,
      instructions,
    },
  };

  emit('stage', { id: 'report', status: 'done', label: 'Report Ready' });
  emit('results', report);

  return report;
}

module.exports = { analyzeFile };
