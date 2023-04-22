import os
from .ElfDef.ElfDyn import *
from .ElfDef.ElfEhdr import *
from .ElfDef.ElfPhdr import *
from .ElfDef.ElfShdr import *
from .ElfDef.ElfSym import *

class ELFParser(object):
    """docstring for ELF"""
    def __init__(self, file):
        super(ELFParser, self).__init__()
        self.f = file
        self.elf32_Ehdr = Elf32_Ehdr()

        # section header table
        self.sectionHeaderTable = []
        # section name table
        self.sectionNameTable = None

        # program header table
        self.programHeaderTable = []

        #program load table
        self.programLoadTable = []

        # dynamic symbol table
        self.symbolTable = []  # .dynsym
        self.dynstrTable = None # .dynstr

        # dynamic link table
        self.dynamicLinkTable = [] # .dynamic

        #========normal way==============#
        #self.parseELFHeader()
        #self.parseSectionHeaderTable()
        #self.staticParseDynSymbolTalbe()
        #self.staticParseDynamicLinkTable()
        #================================#

        #=========dynamic way=============#
        self.parseELFHeader()
        self.parseProgramHeaderTable()
        self.parseProgramLoadTable()
        self.dynParseDynamicLinkTable()
        self.dynParseDynSymbolTalbe()
        #================================#

    def parseELFHeader(self):
        self.f.seek(0, os.SEEK_SET)
        # unsigned char	e_ident[EI_NIDENT];
        self.elf32_Ehdr.e_ident = e_ident()
        self.elf32_Ehdr.e_ident.file_identification = int.from_bytes(self.f.read(4), byteorder='little')
        self.elf32_Ehdr.e_ident.ei_class = int.from_bytes(self.f.read(1), byteorder='little')
        self.elf32_Ehdr.e_ident.ei_data = int.from_bytes(self.f.read(1), byteorder='little')
        self.elf32_Ehdr.e_ident.ei_version = int.from_bytes(self.f.read(1), byteorder='little')
        self.elf32_Ehdr.e_ident.ei_osabi = int.from_bytes(self.f.read(1), byteorder='little')
        self.elf32_Ehdr.e_ident.ei_abiversion = int.from_bytes(self.f.read(1), byteorder='little')
        self.elf32_Ehdr.e_ident.ei_pad = int.from_bytes(self.f.read(6), byteorder='little')
        self.elf32_Ehdr.e_ident.ei_nident = int.from_bytes(self.f.read(1), byteorder='little')

        self.f.seek(16, os.SEEK_SET)
        # Elf32_Half	e_type;
        self.elf32_Ehdr.e_type = int.from_bytes(self.f.read(2), byteorder='little')
        # Elf32_Half	e_machine;
        self.elf32_Ehdr.e_machine = int.from_bytes(self.f.read(2), byteorder='little')
        # Elf32_Word	e_version;
        self.elf32_Ehdr.e_version = int.from_bytes(self.f.read(4), byteorder='little')
        # Elf32_Addr	e_entry;
        self.elf32_Ehdr.e_entry = int.from_bytes(self.f.read(4), byteorder='little')
        # Elf32_Off	e_phoff;
        self.elf32_Ehdr.e_phoff = int.from_bytes(self.f.read(4), byteorder='little')
        # Elf32_Off	e_shoff;
        self.elf32_Ehdr.e_shoff = int.from_bytes(self.f.read(4), byteorder='little')
        # Elf32_Word	e_flags;
        self.elf32_Ehdr.e_flags = int.from_bytes(self.f.read(4), byteorder='little')
        # Elf32_Half	e_ehsize;
        self.elf32_Ehdr.e_ehsize = int.from_bytes(self.f.read(2), byteorder='little')
        # Elf32_Half	e_phentsize;
        self.elf32_Ehdr.e_phentsize = int.from_bytes(self.f.read(2), byteorder='little')
        # Elf32_Half	e_phnum;
        self.elf32_Ehdr.e_phnum = int.from_bytes(self.f.read(2), byteorder='little')
        # Elf32_Half	e_shentsize;
        self.elf32_Ehdr.e_shentsize = int.from_bytes(self.f.read(2), byteorder='little')
        # Elf32_Half	e_shnum;
        self.elf32_Ehdr.e_shnum = int.from_bytes(self.f.read(2), byteorder='little')
        # Elf32_Half	e_shstrndx;
        self.elf32_Ehdr.e_shstrndx = int.from_bytes(self.f.read(2), byteorder='little')

    def parseSectionHeaderTable(self):
        if self.elf32_Ehdr.e_shnum == 0:
            return

        for i in range(self.elf32_Ehdr.e_shnum):
            self.sectionHeaderTable.append(self.parseSectionHeader(self.elf32_Ehdr.e_shoff + i * self.elf32_Ehdr.e_shentsize))

        # init section name table
        size = self.sectionHeaderTable[self.elf32_Ehdr.e_shstrndx].sh_size
        self.f.seek(self.sectionHeaderTable[self.elf32_Ehdr.e_shstrndx].sh_offset, os.SEEK_SET)
        self.sectionNameTable = self.f.read(size)

        for i in range(self.elf32_Ehdr.e_shnum):
            idx = self.sectionHeaderTable[i].sh_name
            name = []
            while True:
                if self.sectionNameTable[idx] != 0x00:
                    name.append(chr(self.sectionNameTable[idx]))     #append char one by one
                else:
                    break
                idx += 1
            self.sectionHeaderTable[i].section_name = "".join(name)

    def parseSectionHeader(self, offset):
        self.f.seek(offset, os.SEEK_SET)
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_type = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_flags = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_addr = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_offset = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_size = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_link = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_info = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_addralign = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Shdr.sh_entsize = int.from_bytes(self.f.read(4), byteorder='little')
        return elf32_Shdr

    def parseProgramHeaderTable(self):
        for i in range(self.elf32_Ehdr.e_phnum):
            self.programHeaderTable.append(self.parseProgramHeader(self.elf32_Ehdr.e_phoff + i * self.elf32_Ehdr.e_phentsize))

    def parseProgramHeader(self, offset):
        '''
        typedef struct elf32_phdr{
          Elf32_Word	p_type;
          Elf32_Off	p_offset;
          Elf32_Addr	p_vaddr;
          Elf32_Addr	p_paddr;
          Elf32_Word	p_filesz;
          Elf32_Word	p_memsz;
          Elf32_Word	p_flags;
          Elf32_Word	p_align;
        } Elf32_Phdr;
        '''
        self.f.seek(offset, os.SEEK_SET)
        elf32_Phdr = Elf32_Phdr()
        elf32_Phdr.p_type = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Phdr.p_offset = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Phdr.p_vaddr = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Phdr.p_paddr = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Phdr.p_filesz = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Phdr.p_memsz = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Phdr.p_flags = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Phdr.p_align = int.from_bytes(self.f.read(4), byteorder='little')
        return elf32_Phdr

    def parseProgramLoadTable(self):
        for phdr in self.programHeaderTable:
            if phdr.p_type == PType.LOAD:
                self.programLoadTable.append(phdr)

    def getOffsetByVa(self, va):
       for load in self.programLoadTable:
            start_addr = load.p_vaddr
            end_addr = load.p_vaddr + load.p_memsz
            if va >= start_addr and va < end_addr:
                return va - (load.p_vaddr - load.p_offset)

    def getSegmentSections(self, elf32_Phdr):
        start = elf32_Phdr.p_offset
        end = elf32_Phdr.p_offset + elf32_Phdr.p_filesz

        sections = []
        for index in range(len(self.sectionHeaderTable)):
            elf32_Shdr = self.sectionHeaderTable[index]
            section_start = elf32_Shdr.sh_offset
            section_end = elf32_Shdr.sh_offset + elf32_Shdr.sh_size
            if section_start >= start and section_end <= end:
                sections.append(elf32_Shdr)

        return sections

    def staticParseDynSymbolTalbe(self):
        # init dynsym
        elf32_Shdr = self.getSectionByName('.dynsym')
        if elf32_Shdr != None:
            for i in range(int(elf32_Shdr.sh_size / elf32_Shdr.sh_entsize)):
                self.symbolTable.append(self.parseDynSymbol(elf32_Shdr.sh_offset + i * elf32_Shdr.sh_entsize))

        # init dynstr
        dynstr_elf32_Shdr = self.getSectionByName('.dynstr')
        self.f.seek(dynstr_elf32_Shdr.sh_offset, os.SEEK_SET)

        self.dynstrTable = self.f.read(dynstr_elf32_Shdr.sh_size)

        for i in range(len(self.symbolTable)):
            idx = self.symbolTable[i].st_name
            name = []
            while True:
                if self.dynstrTable[idx] != 0x00:
                    name.append(chr(self.dynstrTable[idx]))
                else:
                    break
                idx += 1
            self.symbolTable[i].symbol_name = "".join(name)

    def create_null_dynsym(self):
        sym = Elf32_Sym()
        sym.st_name = 0
        sym.st_value = 0
        sym.st_size = 0
        sym.st_info = 0
        sym.st_other = 0
        sym.st_shndx = 0
        return sym

    def dynParseDynSymbolTalbe(self):
        dynstr_off = None
        dynsym_off = None
        dynstr_size = None
        for dyn in self.dynamicLinkTable:
            if dyn.d_tag == DTag.STRTAB:    #STRTAB
                dynstr_off = self.getOffsetByVa(dyn.d_un)
            if dyn.d_tag == DTag.SYMTAB:    #SYMTAB
                dynsym_off = self.getOffsetByVa(dyn.d_un)
            if dyn.d_tag == DTag.STRSZ:     #STRSZ
                dynstr_size = dyn.d_un
        if dynstr_off != None and dynstr_size != None and dynsym_off != None:
            #get dynstr
            self.f.seek(dynstr_off, os.SEEK_SET)
            self.dynstrTable = self.f.read(dynstr_size)
            #get dynsym table
            i = 1     #the first symbol is null in general,so we just appen it
            self.symbolTable.append(self.create_null_dynsym())
            while True:
                sym = self.parseDynSymbol(dynsym_off + i * Elf32_Sym.size())
                if sym.st_name > dynstr_size:
                    break
                if sym.st_name < dynstr_size:
                    if self.dynstrTable[sym.st_name] == 0x00:
                        break
                i += 1 
                self.symbolTable.append(sym)

            for i in range(len(self.symbolTable)):
                idx = self.symbolTable[i].st_name
                name = []
                while True:
                    if self.dynstrTable[idx] != 0x00:
                        name.append(chr(self.dynstrTable[idx]))
                    else:
                        break
                    idx += 1
                self.symbolTable[i].symbol_name = "".join(name)

    def findStringIdxInDynStr(self, str):
        idx = 0
        for i in range(len(self.dynstrTable)):
            if self.dynstrTable[i] == 0x00:
                name = self.dynstrTable[idx : i + 1]
                idx = i + 1
                if name.decode() == str:
                    return idx

    def parseDynSymbol(self, offset):
        '''
            typedef struct elf32_sym{
              Elf32_Word	st_name;
              Elf32_Addr	st_value;
              Elf32_Word	st_size;
              unsigned char	st_info;
              unsigned char	st_other;
              Elf32_Half	st_shndx;
            } Elf32_Sym;
        '''
        self.f.seek(offset, os.SEEK_SET)
        elf32_Sym = Elf32_Sym()
        elf32_Sym.st_name = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Sym.st_value = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Sym.st_size = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Sym.st_info = int.from_bytes(self.f.read(1), byteorder='little')
        elf32_Sym.st_other = int.from_bytes(self.f.read(1), byteorder='little')
        elf32_Sym.st_shndx = int.from_bytes(self.f.read(2), byteorder='little')
        return elf32_Sym

    def staticParseDynamicLinkTable(self):
        # init dynamic
        elf32_Shdr = self.getSectionByName('.dynamic')
        if elf32_Shdr != None:
            for i in range(int(elf32_Shdr.sh_size / elf32_Shdr.sh_entsize)):
                self.dynamicLinkTable.append(self.parseDynamicLink(elf32_Shdr.sh_offset + i * elf32_Shdr.sh_entsize))
                if self.dynamicLinkTable[i].d_tag == 0:     #dynamic table end with NULL one
                        break

    def dynParseDynamicLinkTable(self):
        for phdr in self.programHeaderTable:
            if phdr.p_type == PType.DYNAMIC:
                for i in range(int(phdr.p_filesz / Elf32_Dyn.size())):
                    self.dynamicLinkTable.append(self.parseDynamicLink(phdr.p_offset + i * Elf32_Dyn.size()))
                    if self.dynamicLinkTable[i].d_tag == 0:
                        break

    def parseDynamicLink(self, offset):
        '''
        typedef struct dynamic{
          Elf32_Sword d_tag;
          union{
            Elf32_Sword	d_val;
            Elf32_Addr	d_ptr;
          } d_un;
        } Elf32_Dyn;
        '''
        self.f.seek(offset, os.SEEK_SET)
        elf32_Dyn = Elf32_Dyn()
        elf32_Dyn.d_tag = int.from_bytes(self.f.read(4), byteorder='little')
        elf32_Dyn.d_un = int.from_bytes(self.f.read(4), byteorder='little')
        return elf32_Dyn

    def getElf32_Dyn_TypeInfo(self, elf32_Dyn):
        if elf32_Dyn.d_tag == DTag.NEEDED: # DT_NEEDED
            idx = self.dynstrTable.find('\0'.encode(), elf32_Dyn.d_un)
            return 'Shared library: [%s]' % self.dynstrTable[elf32_Dyn.d_un: idx]
        elif elf32_Dyn.d_tag == 0xe: # DT_SONAME
            idx = self.dynstrTable.find('\0'.encode(), elf32_Dyn.d_un)
            return 'Library soname: [%s]' % self.dynstrTable[elf32_Dyn.d_un: idx]

        return hex(elf32_Dyn.d_un)

    def getSectionByName(self, name):
        for elf32_Shdr in self.sectionHeaderTable:
            if elf32_Shdr.section_name == name:
                return elf32_Shdr
        return None

    def displayELFHeader(self):
        print( '[+] ELF Header:')
        print( 'e_ident:\t%s' % self.elf32_Ehdr.e_ident)
        print( 'e_type: \t%s' % self.elf32_Ehdr.e_type)
        print( 'e_machine:\t%s' % self.elf32_Ehdr.e_machine)
        print( 'e_version:\t%s' % self.elf32_Ehdr.e_version)
        print( 'e_entry:\t%s' % self.elf32_Ehdr.e_entry)
        print( 'e_phoff:\t%s\t//Program header offset' % hex(self.elf32_Ehdr.e_phoff))
        print( 'e_shoff:\t%s\t//Section header offset' % hex(self.elf32_Ehdr.e_shoff))
        print( 'e_flags:\t%s' % self.elf32_Ehdr.e_flags)
        print( 'e_ehsize:\t%s\t//ELF header size' % self.elf32_Ehdr.e_ehsize)
        print( 'e_phentsize:\t%s\t//Program header entry size' % self.elf32_Ehdr.e_phentsize)
        print( 'e_phnum:\t%s\t//Program header number' % self.elf32_Ehdr.e_phnum)
        print( 'e_shentsize:\t%s\t//Section header entry size' % self.elf32_Ehdr.e_shentsize)
        print( 'e_shnum:\t%s\t//Section header number' % self.elf32_Ehdr.e_shnum)
        print( 'e_shstrndx:\t%s\t//Section header string index' % self.elf32_Ehdr.e_shstrndx)
        print( '')

    def displaySectionHeader(self):
        print( '[+] Section Header Table:')
        print( '  #      %-32s%-16s%-16s%-16s%-8s%-8s%-8s%-8s%-8s%-8s' % ('Name', 'Type', 'Addr', 'Offset', 'Size', 'ES', 'Flg', 'Lk', 'Inf', 'Al'))
        for index in range(len(self.sectionHeaderTable)):
            elf32_Shdr = self.sectionHeaderTable[index]
            if elf32_Shdr.sh_type in SH_TYPE_MAP_LIST:
                print( '  [%4d] %-32s%-16s%-16s%-16s%-8s%-8d%-8d%-8d%-8d%-8d' % \
                      (index,
                       self.sectionHeaderTable[index].section_name,
                       SH_TYPE_MAP_LIST[elf32_Shdr.sh_type].strip(),
                       hex(elf32_Shdr.sh_addr),
                       hex(elf32_Shdr.sh_offset),
                       hex(elf32_Shdr.sh_size),
                       elf32_Shdr.sh_entsize,
                       elf32_Shdr.sh_flags,
                       elf32_Shdr.sh_link,
                       elf32_Shdr.sh_info,
                       elf32_Shdr.sh_addralign,
                       ))
            else:
                print( '  [%4d] %-32s%-16d%-16s%-16s%-8s%-8d%-8d%-8d%-8d%-8d' % \
                      (index,
                       self.sectionHeaderTable[index].section_name,
                       elf32_Shdr.sh_type,
                       hex(elf32_Shdr.sh_addr),
                       hex(elf32_Shdr.sh_offset),
                       hex(elf32_Shdr.sh_size),
                       elf32_Shdr.sh_entsize,
                       elf32_Shdr.sh_flags,
                       elf32_Shdr.sh_link,
                       elf32_Shdr.sh_info,
                       elf32_Shdr.sh_addralign,
                       ))
        print('')
    
    def displaySecToSegMapping(self):
        for index in range(len(self.programHeaderTable)):
            elf32_Phdr = self.programHeaderTable[index]
            sections = self.getSegmentSections(elf32_Phdr)

            sections_str = ''
            for elf32_Shdr in sections:
                sections_str = elf32_Shdr.section_name
            print( '  [%4d] %s' % (index, sections_str))
        print( '')

    def displayProgramHeader(self):
        print( '[+] Program Header Table:')
        print( '  #      %-16s%-16s%-16s%-16s%-8s%-8s%-8s%-8s' % (
            'Type', 'offset', 'VirtAddr', 'PhysAddr', 'FileSiz', 'MemSiz', 'Flg', 'Align'))
        for index in range(len(self.programHeaderTable)):
            elf32_Phdr = self.programHeaderTable[index]

            if elf32_Phdr.p_type in PT_TYPE_MAP_LIST:
                print( '  [%4d] %-16s%-16s%-16s%-16s%-8s%-8s%-8d%-8s' % (
                    index,
                    PT_TYPE_MAP_LIST[elf32_Phdr.p_type],
                    hex(elf32_Phdr.p_offset),
                    hex(elf32_Phdr.p_vaddr),
                    hex(elf32_Phdr.p_paddr),
                    hex(elf32_Phdr.p_filesz),
                    hex(elf32_Phdr.p_memsz),
                    elf32_Phdr.p_flags,
                    hex(elf32_Phdr.p_align),
                ))
            else:
                print( '  [%4d] %-16d%-16s%-16s%-16s%-8s%-8s%-8d%-8s' % (
                    index,
                    elf32_Phdr.p_type,
                    hex(elf32_Phdr.p_offset),
                    hex(elf32_Phdr.p_vaddr),
                    hex(elf32_Phdr.p_paddr),
                    hex(elf32_Phdr.p_filesz),
                    hex(elf32_Phdr.p_memsz),
                    elf32_Phdr.p_flags,
                    hex(elf32_Phdr.p_align),
                ))
        #print( '\n[+] Section to segment mapping:')
        #self.displaySecToSegMapping()

    def displaySymbolTable(self):
        print( '[+] Dynamic Symbol Table:')
        print( '  #      %-10s%-8s%-8s%-8s%-8s%-8s%-8s' % (
            'Value', 'Size', 'Type', 'Bind', 'Other', 'Ndx', 'Name'))

        BIND_TYPE = {0:'LOCAL', 1:'GLOBAL', 2:'WEAK', 13:'LOPROC', 15:'HIPROC'}
        ELF32_ST_TYPE = {0:'NOTYPE', 1:'OBJECT', 2:'FUNC', 3:'SECTION', 4:'FILE', 13:'LOPROC', 15:'HIPROC'}
        SHN_TYPE = {0:'UNDEF', 0xfff1:'ABS',  0xfff2:'COMMON',}

        for index in range(len(self.symbolTable)):
            elf32_Sym = self.symbolTable[index]
            bind = elf32_Sym.st_info >> 4
            type = elf32_Sym.st_info & 0xf

            if elf32_Sym.st_shndx == 0 or elf32_Sym.st_shndx == 0xfff1 or elf32_Sym.st_shndx == 0xfff2:
                shn_type = SHN_TYPE[elf32_Sym.st_shndx]
            else:
                shn_type = str(elf32_Sym.st_shndx)
            print( '  [%4d] %-10s%-8d%-8s%-8s%-8d%-8s%-8s' % (
                index,
                hex(elf32_Sym.st_value),
                elf32_Sym.st_size,
                ELF32_ST_TYPE[type],
                BIND_TYPE[bind],
                elf32_Sym.st_other,
                shn_type,
                elf32_Sym.symbol_name
            ))
        print( '')

    def displayDynamicLinkTable(self):
        print( '[+] Dynamic Link Table:')
        print( '  #      %-16s%-16s%-8s' % ('Tag', 'Type', 'Name/Value'))

        for index in range(len(self.dynamicLinkTable)):
            elf32_Dyn = self.dynamicLinkTable[index]
            print( '  [%4d] %-16s%-16s%-16s' % (
                index,
                hex(elf32_Dyn.d_tag),
                DYNAMIC_TYPE[int(elf32_Dyn.d_tag)],
                self.getElf32_Dyn_TypeInfo(elf32_Dyn),

            ))
