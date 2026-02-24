// PE (Portable Executable) file format parser

const MACHINE_TYPES = {
  0x014c: { name: 'x86', bits: 32 },
  0x8664: { name: 'AMD64', bits: 64 },
  0xaa64: { name: 'ARM64', bits: 64 },
  0x01c0: { name: 'ARM', bits: 32 },
  0x0200: { name: 'IA64', bits: 64 },
  0x01c4: { name: 'ARMv7', bits: 32 },
  0x0166: { name: 'MIPS16', bits: 32 },
};

const SUBSYSTEMS = {
  1: 'Native',
  2: 'Windows GUI',
  3: 'Windows CUI',
  7: 'POSIX CUI',
  9: 'Windows CE GUI',
  10: 'EFI Application',
  11: 'EFI Boot Driver',
  12: 'EFI Runtime Driver',
  14: 'Xbox',
  16: 'Windows Boot App',
};

const SECTION_FLAGS = {
  0x00000020: 'CODE',
  0x00000040: 'INIT_DATA',
  0x00000080: 'UNINIT_DATA',
  0x20000000: 'EXEC',
  0x40000000: 'READ',
  0x80000000: 'WRITE',
};

function parseSectionFlags(flags) {
  return Object.entries(SECTION_FLAGS)
    .filter(([mask]) => flags & Number(mask))
    .map(([, name]) => name)
    .join('|') || '0x' + flags.toString(16);
}

function parsePE(buffer) {
  if (buffer.length < 0x40) throw new Error('File too small to be a PE');

  const e_magic = buffer.readUInt16LE(0);
  if (e_magic !== 0x5a4d) throw new Error('Not a PE file (no MZ signature)');

  const e_lfanew = buffer.readUInt32LE(0x3c);
  if (e_lfanew + 24 > buffer.length) throw new Error('Invalid PE header offset');

  const peSig = buffer.readUInt32LE(e_lfanew);
  if (peSig !== 0x00004550) throw new Error('Invalid PE signature');

  const coffBase = e_lfanew + 4;
  const machine = buffer.readUInt16LE(coffBase);
  const numSections = buffer.readUInt16LE(coffBase + 2);
  const timestamp = buffer.readUInt32LE(coffBase + 4);
  const sizeOfOptHeader = buffer.readUInt16LE(coffBase + 16);
  const characteristics = buffer.readUInt16LE(coffBase + 18);

  const arch = MACHINE_TYPES[machine] || { name: `0x${machine.toString(16)}`, bits: 32 };

  const optBase = coffBase + 20;
  const magic = buffer.readUInt16LE(optBase);
  const isPE32Plus = magic === 0x20b;

  const entryPoint = buffer.readUInt32LE(optBase + 16);
  const baseOfCode = buffer.readUInt32LE(optBase + 20);

  let imageBase;
  if (isPE32Plus) {
    imageBase = Number(buffer.readBigUInt64LE(optBase + 24));
  } else {
    imageBase = buffer.readUInt32LE(optBase + 28);
  }

  const subsystemOffset = isPE32Plus ? optBase + 68 : optBase + 68;
  const subsystem = buffer.readUInt16LE(subsystemOffset);

  const isDLL = !!(characteristics & 0x2000);
  const isExe = !!(characteristics & 0x0002);

  // Parse sections
  const sectionTableBase = optBase + sizeOfOptHeader;
  const sections = [];

  for (let i = 0; i < numSections; i++) {
    const off = sectionTableBase + i * 40;
    if (off + 40 > buffer.length) break;

    const nameBytes = buffer.slice(off, off + 8);
    const name = nameBytes.toString('ascii').replace(/\0+$/, '');
    const virtualSize = buffer.readUInt32LE(off + 8);
    const virtualAddress = buffer.readUInt32LE(off + 12);
    const sizeOfRawData = buffer.readUInt32LE(off + 16);
    const pointerToRawData = buffer.readUInt32LE(off + 20);
    const flags = buffer.readUInt32LE(off + 36);

    sections.push({
      name,
      virtualAddress,
      virtualSize,
      rawOffset: pointerToRawData,
      rawSize: sizeOfRawData,
      flags,
      flagsStr: parseSectionFlags(flags),
      isCode: !!(flags & 0x20000020), // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
    });
  }

  const fileType = isDLL ? 'DLL' : isExe ? 'EXE' : 'OBJ';

  return {
    format: 'PE',
    type: `PE (${arch.name})`,
    arch: arch.name,
    bits: arch.bits,
    machine,
    isPE32Plus,
    entryPoint: '0x' + entryPoint.toString(16),
    imageBase: '0x' + imageBase.toString(16),
    baseOfCode: '0x' + baseOfCode.toString(16),
    subsystem: SUBSYSTEMS[subsystem] || `0x${subsystem.toString(16)}`,
    fileType,
    timestamp: new Date(timestamp * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    characteristics: '0x' + characteristics.toString(16),
    numSections,
    sections,
    summary: `${fileType}, ${arch.name}, ${numSections} sections`,
    info: {
      entryPoint: '0x' + entryPoint.toString(16),
      imageBase: '0x' + imageBase.toString(16),
      subsystem: SUBSYSTEMS[subsystem] || `Unknown (${subsystem})`,
      fileType,
      timestamp: new Date(timestamp * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    },
  };
}

module.exports = { parsePE };
