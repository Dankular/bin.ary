const fs = require('fs');
const { parsePE }           = require('./peParser');
const { parseELF }          = require('./elfParser');
const { disassemble }       = require('./disassembler');
const { buildXrefs }        = require('./xrefAnalyzer');
const { detectFunctions, matchByteSignatures } = require('./signatures');

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function detectFormat(buffer) {
  if (buffer.length < 4) return { type: 'raw', description: 'Raw binary (too small)' };
  if (buffer[0] === 0x4d && buffer[1] === 0x5a)
    return { type: 'pe', description: 'PE (Portable Executable)' };
  if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46)
    return { type: 'elf', description: 'ELF (Executable and Linkable Format)' };
  const m = buffer.readUInt32BE(0);
  if (m === 0xfeedface || m === 0xcefaedfe) return { type: 'macho', description: 'Mach-O (32-bit)' };
  if (m === 0xfeedfacf || m === 0xcffaedfe) return { type: 'macho', description: 'Mach-O (64-bit)' };
  if (m === 0xcafebabe) return { type: 'macho', description: 'Mach-O FAT binary' };
  return { type: 'raw', description: 'Raw binary / unknown format' };
}

function findCodeSection(sections) {
  return (
    sections.find((s) => s.name === '.text' || s.name === '__text') ||
    sections.find((s) => s.isCode && s.rawSize > 0) ||
    sections.find((s) => s.rawSize > 0) ||
    null
  );
}

async function analyzeFile(filePath, originalName, fileSize, emit) {
  emit('stage', { id: 'upload',   status: 'done',    label: 'File Uploaded',    result: `${originalName}  (${formatSize(fileSize)})` });

  // ── 1. Format ─────────────────────────────────────────────────────────────
  emit('stage', { id: 'detect',   status: 'running', label: 'Detecting Format' });
  await delay(80);
  const buffer = fs.readFileSync(filePath);
  const fmt = detectFormat(buffer);
  emit('stage', { id: 'detect',   status: 'done',    label: 'Detecting Format',    result: fmt.description });

  // ── 2. Headers ────────────────────────────────────────────────────────────
  emit('stage', { id: 'headers',  status: 'running', label: 'Parsing Headers' });
  await delay(100);
  let parsed;
  try {
    if (fmt.type === 'pe')  parsed = parsePE(buffer);
    else if (fmt.type === 'elf') parsed = parseELF(buffer);
    else parsed = { format: fmt.type.toUpperCase(), type: fmt.description, arch: 'unknown', bits: 32, sections: [], numSections: 0, summary: fmt.description, info: {} };
  } catch (err) {
    emit('stage', { id: 'headers', status: 'error', label: 'Parsing Headers', result: err.message });
    throw err;
  }
  emit('stage', { id: 'headers',  status: 'done',    label: 'Parsing Headers',     result: parsed.summary });

  // ── 3. Sections ───────────────────────────────────────────────────────────
  emit('stage', { id: 'sections', status: 'running', label: 'Extracting Sections' });
  await delay(60);
  const sections = parsed.sections || [];
  emit('stage', { id: 'sections', status: 'done',    label: 'Extracting Sections', result: `${sections.length} section${sections.length !== 1 ? 's' : ''}` });

  // ── 4. Disassemble ────────────────────────────────────────────────────────
  emit('stage', { id: 'disasm',   status: 'running', label: 'Disassembling Code' });
  await delay(50);

  let instructions = [], disasmFallback = false, disasmSection = null, codeBaseVA = 0;
  const codeSection = findCodeSection(sections);

  if (codeSection && codeSection.rawSize > 0 && codeSection.rawOffset > 0) {
    const rawEnd = Math.min(codeSection.rawOffset + codeSection.rawSize, buffer.length);
    if (rawEnd > codeSection.rawOffset) {
      const codeBuffer = buffer.slice(codeSection.rawOffset, rawEnd);
      codeBaseVA = Number(codeSection.virtualAddress);
      const result = disassemble(codeBuffer, codeBaseVA, parsed.bits);
      instructions     = result.instructions;
      disasmFallback   = result.fallback;
      disasmSection    = codeSection.name;
    }
  } else if (sections.length === 0) {
    const result = disassemble(buffer, 0, 32);
    instructions = result.instructions;
    disasmFallback = result.fallback;
  }

  emit('stage', { id: 'disasm',   status: 'done',    label: 'Disassembling Code',  result: disasmFallback ? `${instructions.length} hex rows` : `${instructions.length} instructions` });

  // ── 5. References + Signatures ────────────────────────────────────────────
  emit('stage', { id: 'refs',     status: 'running', label: 'Cross-References' });
  await delay(60);

  const xrefs = disasmFallback ? {} : buildXrefs(instructions, parsed.bits);
  const funcLabels = disasmFallback ? {} : Object.fromEntries(detectFunctions(instructions));

  let byteSigs = [];
  if (codeSection && codeSection.rawOffset > 0 && codeSection.rawSize > 0) {
    const rawEnd = Math.min(codeSection.rawOffset + codeSection.rawSize, buffer.length);
    const codeBuf = buffer.slice(codeSection.rawOffset, rawEnd);
    byteSigs = matchByteSignatures(codeBuf, codeBaseVA, parsed.bits);
  }

  const xrefCount = Object.keys(xrefs).length;
  const funcCount = Object.keys(funcLabels).length;
  emit('stage', { id: 'refs',     status: 'done',    label: 'Cross-References',    result: `${xrefCount} xrefs, ${funcCount} functions` });

  // ── 6. Report ─────────────────────────────────────────────────────────────
  emit('stage', { id: 'report',   status: 'running', label: 'Building Report' });
  await delay(40);

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
      baseVA: codeBaseVA,
    },
    analysis: { xrefs, funcLabels, byteSigs },
  };

  emit('stage', { id: 'report',   status: 'done',    label: 'Report Ready' });
  emit('results', report);
  return report;
}

module.exports = { analyzeFile };
