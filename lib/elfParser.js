// ELF (Executable and Linkable Format) parser

const ELF_MACHINES = {
  0x00: 'None',
  0x02: 'SPARC',
  0x03: 'x86',
  0x08: 'MIPS',
  0x14: 'PowerPC',
  0x16: 'S390',
  0x28: 'ARM',
  0x2a: 'SuperH',
  0x32: 'IA-64',
  0x3e: 'AMD64',
  0xb7: 'AArch64',
  0xf3: 'RISC-V',
};

const ELF_TYPES = {
  0: 'None',
  1: 'Relocatable',
  2: 'Executable',
  3: 'Shared Object',
  4: 'Core',
};

const ELF_OSABI = {
  0: 'System V',
  1: 'HP-UX',
  2: 'NetBSD',
  3: 'Linux',
  6: 'Solaris',
  9: 'FreeBSD',
  12: 'OpenBSD',
};

const SHT = {
  0: 'NULL',
  1: 'PROGBITS',
  2: 'SYMTAB',
  3: 'STRTAB',
  4: 'RELA',
  5: 'HASH',
  6: 'DYNAMIC',
  7: 'NOTE',
  8: 'NOBITS',
  9: 'REL',
  11: 'DYNSYM',
};

const ARCH_BITS = {
  'x86': 32,
  'AMD64': 64,
  'ARM': 32,
  'AArch64': 64,
  'MIPS': 32,
  'RISC-V': 64,
  'PowerPC': 32,
  'IA-64': 64,
};

function parseELF(buffer) {
  if (buffer.length < 16) throw new Error('File too small to be an ELF');

  if (buffer[0] !== 0x7f || buffer[1] !== 0x45 || buffer[2] !== 0x4c || buffer[3] !== 0x46) {
    throw new Error('Not an ELF file');
  }

  const is64 = buffer[4] === 2;
  const isLE = buffer[5] === 1;
  const osabi = buffer[7];

  const read16 = (off) => isLE ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off);
  const read32 = (off) => isLE ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off);
  const read64 = (off) => {
    const lo = isLE ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off + 4);
    const hi = isLE ? buffer.readUInt32LE(off + 4) : buffer.readUInt32BE(off);
    return hi * 0x100000000 + lo;
  };
  const readAddr = is64 ? read64 : read32;
  const readOff = is64 ? read64 : read32;

  const e_type = read16(0x10);
  const e_machine = read16(0x12);
  const e_entry = readAddr(is64 ? 0x18 : 0x18);
  const e_shoff = readOff(is64 ? 0x28 : 0x20);
  const e_shentsize = read16(is64 ? 0x3a : 0x2e);
  const e_shnum = read16(is64 ? 0x3c : 0x30);
  const e_shstrndx = read16(is64 ? 0x3e : 0x32);

  const machName = ELF_MACHINES[e_machine] || `0x${e_machine.toString(16)}`;
  const bits = ARCH_BITS[machName] || (is64 ? 64 : 32);

  // Parse section headers
  const sections = [];
  let shstrBuf = null;

  if (e_shoff && e_shnum && e_shstrndx < e_shnum) {
    // Get string table section header
    const strShOff = e_shoff + e_shstrndx * e_shentsize;
    if (strShOff + e_shentsize <= buffer.length) {
      const strOffset = is64 ? readOff(strShOff + 24) : read32(strShOff + 16);
      const strSize = is64 ? readOff(strShOff + 32) : read32(strShOff + 20);
      if (strOffset + strSize <= buffer.length) {
        shstrBuf = buffer.slice(strOffset, strOffset + strSize);
      }
    }
  }

  function readCStr(buf, offset) {
    if (!buf || offset >= buf.length) return '';
    const end = buf.indexOf(0, offset);
    return buf.slice(offset, end < 0 ? buf.length : end).toString('ascii');
  }

  for (let i = 0; i < e_shnum; i++) {
    const off = e_shoff + i * e_shentsize;
    if (off + e_shentsize > buffer.length) break;

    const sh_name = read32(off);
    const sh_type = read32(off + 4);
    const sh_flags = is64 ? readOff(off + 8) : read32(off + 8);
    const sh_addr = readAddr(is64 ? off + 16 : off + 12);
    const sh_offset = readOff(is64 ? off + 24 : off + 16);
    const sh_size = readOff(is64 ? off + 32 : off + 20);

    const name = readCStr(shstrBuf, sh_name) || `section_${i}`;
    const isCode = !!(sh_flags & 0x4); // SHF_EXECINSTR
    const typeStr = SHT[sh_type] || `0x${sh_type.toString(16)}`;

    const flagParts = [];
    if (sh_flags & 0x1) flagParts.push('WRITE');
    if (sh_flags & 0x2) flagParts.push('ALLOC');
    if (sh_flags & 0x4) flagParts.push('EXEC');

    sections.push({
      name,
      virtualAddress: sh_addr,
      virtualSize: sh_size,
      rawOffset: sh_offset,
      rawSize: sh_size,
      flags: sh_flags,
      flagsStr: flagParts.join('|') || 'NONE',
      typeStr,
      isCode,
    });
  }

  const fileType = ELF_TYPES[e_type] || `Type ${e_type}`;
  const endian = isLE ? 'Little-endian' : 'Big-endian';

  return {
    format: 'ELF',
    type: `ELF (${machName})`,
    arch: machName,
    bits,
    machine: e_machine,
    is64,
    isLE,
    entryPoint: '0x' + e_entry.toString(16),
    sections,
    numSections: sections.length,
    summary: `${fileType}, ${machName}, ${sections.length} sections`,
    info: {
      fileType,
      arch: machName,
      bits: `${bits}-bit`,
      endian,
      osabi: ELF_OSABI[osabi] || `0x${osabi.toString(16)}`,
      entryPoint: '0x' + e_entry.toString(16),
    },
  };
}

module.exports = { parseELF };
