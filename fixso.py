#!/usr/bin/env python
#coding:utf-8

from io import SEEK_SET
import sys
import os
from shutil import copyfile
from struct import *
from ELF.ELF32.ELFParser import ELFParser
from ELF.ELF32.ElfDef.ElfShdr import *
from ELF.ELF32.ElfDef.ElfDyn import DTag
from ELF.ELF32.ElfDef.ElfSym import Elf32_Sym
from ELF.ELF32.ElfDef.ElfPhdr import PType

shstrtab_byteArray = None
dyn_sym = None
dyn_strtab = None
dyn_strsz = None

dyn_relplt = None
relplt_size = None
rel_entsize = None

plt_sh_addr = None
plt_size = None

def create_shstrtab_byteArray():
    buf = '\0'.encode()
    buf += ".dynsym\0".encode()
    buf += ".dynstr\0".encode()
    buf += ".hash\0".encode()
    buf += ".rel.dyn\0".encode()
    buf += ".rel.plt\0".encode()
    buf += ".text\0".encode()
    buf += ".init_array\0".encode()
    buf += ".dynamic\0".encode()
    buf += ".got\0".encode()
    buf += ".data\0".encode()
    buf += ".bss\0".encode()
    buf += ".shstrtab\0".encode()
    buf += ".plt\0".encode()
    buf += ".bss\0".encode()
    buf += ".fini_array\0".encode()
    return buf

def find_str_idx_in_shstrtab_byteArray(str):
    idx = 0
    for i in range(len(shstrtab_byteArray)):
        if shstrtab_byteArray[i] == 0x00:
            name = shstrtab_byteArray[idx : i]
            if name.decode() == str:
                return idx
            idx = i + 1     #skip \x00

def create_section_undef(elf):
    elf32_Shdr = Elf32_Shdr()   
    elf32_Shdr.sh_name = 0
    elf32_Shdr.sh_type = int(ShType.SHT_NULL)
    elf32_Shdr.sh_flags = int(ShFlags.SHT_NULL)
    elf32_Shdr.sh_addr = 0
    elf32_Shdr.sh_offset = 0
    elf32_Shdr.sh_size = 0
    elf32_Shdr.sh_link = 0
    elf32_Shdr.sh_info = 0
    elf32_Shdr.sh_addralign = 0
    elf32_Shdr.sh_entsize = 0
    return elf32_Shdr

def create_section_dynstr(elf):
    global dyn_strtab
    global dyn_strsz
    for dyn in elf.dynamicLinkTable:
        if dyn.d_tag == DTag.STRTAB:
            dyn_strtab = dyn
        elif dyn.d_tag == DTag.STRSZ:
            dyn_strsz = dyn
    if dyn_strtab != None and dyn_strsz != None:
        elf32_Shdr = Elf32_Shdr()   
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".dynstr")
        elf32_Shdr.sh_type = int(ShType.SHT_STRTAB)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC)
        elf32_Shdr.sh_addr = dyn_strtab.d_un
        elf32_Shdr.sh_offset = elf.getOffsetByVa(dyn_strtab.d_un)
        elf32_Shdr.sh_size = dyn_strsz.d_un
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if dyn_strtab.d_un % 4 != 0 else 4
        elf32_Shdr.sh_entsize = 0
        return elf32_Shdr

def create_section_dynsym(elf):
    global dyn_sym
    dyn_syment = None
    for dyn in elf.dynamicLinkTable:
        if dyn.d_tag == DTag.SYMTAB:
            dyn_sym = dyn
        elif dyn.d_tag == DTag.SYMENT:
            dyn_syment = dyn
    if dyn_sym != None and dyn_syment != None:
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".dynsym")
        elf32_Shdr.sh_type = int(ShType.SHT_DYNSYM)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC)
        elf32_Shdr.sh_addr = dyn_sym.d_un
        elf32_Shdr.sh_offset = elf.getOffsetByVa(dyn_sym.d_un)
        elf32_Shdr.sh_size = len(elf.symbolTable) * Elf32_Sym.size()
        elf32_Shdr.sh_link = 1    #1 is .dynstr section index
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if dyn_sym.d_un % 4 != 0 else 4
        elf32_Shdr.sh_entsize = dyn_syment.d_un
        return elf32_Shdr

def create_section_hash(file, elf):
    dyn_hash = None
    for dyn in elf.dynamicLinkTable:
        if dyn.d_tag == DTag.HASH:
            dyn_hash = dyn
    if dyn_hash != None:
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".hash")
        elf32_Shdr.sh_type = int(ShType.SHT_HASH)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC)
        elf32_Shdr.sh_addr = dyn_hash.d_un
        elf32_Shdr.sh_offset = elf.getOffsetByVa(dyn_hash.d_un)
        elf32_Shdr.sh_size = calc_hash_table_size(file, elf32_Shdr.sh_offset)
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if dyn_hash.d_un % 4 != 0 else 4
        elf32_Shdr.sh_entsize = 4   #int
        return elf32_Shdr

def create_section_reldyn(elf):
    global rel_entsize
    dyn_reldyn = None
    rel_size = 0
    for dyn in elf.dynamicLinkTable:
        if dyn.d_tag == DTag.REL:
            dyn_reldyn = dyn
        elif dyn.d_tag == DTag.RELSZ:
            rel_size = dyn.d_un
        elif dyn.d_tag == DTag.RELENT:
            rel_entsize = dyn.d_un
    if dyn_reldyn != None and rel_size != 0 and rel_entsize != None:
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".rel.dyn")
        elf32_Shdr.sh_type = int(ShType.SHT_REL)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC)
        elf32_Shdr.sh_addr = dyn_reldyn.d_un
        elf32_Shdr.sh_offset = elf.getOffsetByVa(dyn_reldyn.d_un)
        elf32_Shdr.sh_size = rel_size
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if dyn_reldyn.d_un % 4 != 0 else 4
        elf32_Shdr.sh_entsize = rel_entsize
        return elf32_Shdr

def create_section_relplt(elf):
    global dyn_relplt
    global relplt_size
    global rel_entsize
    for dyn in elf.dynamicLinkTable:
        if dyn.d_tag == DTag.JMPREL:
            dyn_relplt = dyn
        elif dyn.d_tag == DTag.PLTRELSZ:
            relplt_size = dyn.d_un
        elif dyn.d_tag == DTag.RELENT:
            rel_entsize = dyn.d_un
    if dyn_relplt != None and relplt_size != None and rel_entsize != None:
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".rel.plt")
        elf32_Shdr.sh_type = int(ShType.SHT_REL)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC)
        elf32_Shdr.sh_addr = dyn_relplt.d_un
        elf32_Shdr.sh_offset = elf.getOffsetByVa(dyn_relplt.d_un)
        elf32_Shdr.sh_size = relplt_size
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if dyn_relplt.d_un % 4 != 0 else 4
        elf32_Shdr.sh_entsize = rel_entsize
        return elf32_Shdr

def create_section_plt(elf):
    #relplt followed by plt
    global dyn_relplt
    global relplt_size
    global rel_entsize
    global plt_sh_addr
    global plt_size
    if dyn_relplt != None and relplt_size != None and rel_entsize != None:
        plt_sh_addr = dyn_relplt.d_un + relplt_size
        plt_size = 20 + int(relplt_size/rel_entsize) * 12        #20 bytes fixed header,  followed by a table has same counts of entry as relplt, each one is 12 bytes 
        
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".plt")
        elf32_Shdr.sh_type = int(ShType.SHT_PROGBITS)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC) | int(ShFlags.SHF_EXECINSTR)
        elf32_Shdr.sh_addr = plt_sh_addr
        elf32_Shdr.sh_offset = elf.getOffsetByVa(plt_sh_addr)
        elf32_Shdr.sh_size = plt_size     
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if plt_sh_addr % 4 != 0 else 4
        elf32_Shdr.sh_entsize = 0
        return elf32_Shdr

def create_section_fini_array(elf):
    dyn_finit_array = None
    dyn_finit_arraysz = None
    for dyn in elf.dynamicLinkTable:
        if dyn.d_tag == DTag.FINIT_ARRAY:
            dyn_finit_array = dyn
        elif dyn.d_tag == DTag.FINIT_ARRAYSZ:
            dyn_finit_arraysz = dyn.d_un
    if dyn_finit_array != None and dyn_finit_arraysz != None:
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".fini_array")
        elf32_Shdr.sh_type = int(ShType.SHT_FINI_ARRAY)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC) | int(ShFlags.SHF_WRITE)
        elf32_Shdr.sh_addr = dyn_finit_array.d_un
        elf32_Shdr.sh_offset = elf.getOffsetByVa(dyn_finit_array.d_un)
        elf32_Shdr.sh_size = dyn_finit_arraysz     
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if dyn_finit_array.d_un % 4 != 0 else 4
        elf32_Shdr.sh_entsize = 4
        return elf32_Shdr

def create_section_text(elf):
    global plt_sh_addr
    global plt_size
    if plt_sh_addr != None and plt_size != None:
        end_of_plt_vaddr = plt_sh_addr + plt_size

        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".text")
        elf32_Shdr.sh_type = int(ShType.SHT_PROGBITS)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC) | int(ShFlags.SHF_EXECINSTR)
        elf32_Shdr.sh_addr = end_of_plt_vaddr
        elf32_Shdr.sh_offset = elf.getOffsetByVa(end_of_plt_vaddr)
        elf32_Shdr.sh_size = (elf.programLoadTable[0].p_offset + elf.programLoadTable[0].p_filesz) - elf32_Shdr.sh_offset  #between plt and the end of first load segment 
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if end_of_plt_vaddr % 4 != 0 else 4
        elf32_Shdr.sh_entsize = 0
        return elf32_Shdr

def create_section_init_array(elf):
    dyn_init_array = None
    dyn_init_arraysz = None
    for dyn in elf.dynamicLinkTable:
        if dyn.d_tag == DTag.INIT_ARRAY:
            dyn_init_array = dyn
        elif dyn.d_tag == DTag.INIT_ARRAYSZ:
            dyn_init_arraysz = dyn.d_un
    if dyn_init_array != None and dyn_init_arraysz != None:
        elf32_Shdr = Elf32_Shdr()
        elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".init_array")
        elf32_Shdr.sh_type = int(ShType.SHT_INIT_ARRAY)
        elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC) | int(ShFlags.SHF_WRITE)
        elf32_Shdr.sh_addr = dyn_init_array.d_un
        elf32_Shdr.sh_offset = elf.getOffsetByVa(dyn_init_array.d_un)
        elf32_Shdr.sh_size = dyn_init_arraysz     
        elf32_Shdr.sh_link = 0
        elf32_Shdr.sh_info = 0
        elf32_Shdr.sh_addralign = 1 if dyn_init_array.d_un % 4 != 0 else 4
        elf32_Shdr.sh_entsize = 4
        return elf32_Shdr

def create_section_dynamic(elf):
    for phdr in elf.programHeaderTable:
        if phdr.p_type == PType.DYNAMIC:
            elf32_Shdr = Elf32_Shdr()
            elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".dynamic")
            elf32_Shdr.sh_type = int(ShType.SHT_DYNAMIC)
            elf32_Shdr.sh_flags = int(ShFlags.SHF_ALLOC) | int(ShFlags.SHF_WRITE)
            elf32_Shdr.sh_addr = phdr.p_vaddr
            elf32_Shdr.sh_offset = phdr.p_offset
            elf32_Shdr.sh_size = phdr.p_filesz 
            elf32_Shdr.sh_link = 0
            elf32_Shdr.sh_info = 0
            elf32_Shdr.sh_addralign = 1 if phdr.p_vaddr % 4 != 0 else 4
            elf32_Shdr.sh_entsize = 8
            return elf32_Shdr

def create_section_shstrtab(elf, sh_offset):
    elf32_Shdr = Elf32_Shdr()
    elf32_Shdr.sh_name = find_str_idx_in_shstrtab_byteArray(".shstrtab")
    elf32_Shdr.sh_type = int(ShType.SHT_STRTAB)
    elf32_Shdr.sh_flags = int(ShFlags.SHT_NULL)
    elf32_Shdr.sh_addr = 0
    elf32_Shdr.sh_offset = sh_offset
    elf32_Shdr.sh_size = len(shstrtab_byteArray)
    elf32_Shdr.sh_link = 0
    elf32_Shdr.sh_info = 0
    elf32_Shdr.sh_addralign = 1
    elf32_Shdr.sh_entsize = 0
    return elf32_Shdr

def calc_hash_table_size(file, offset):
    '''
    struct hash_table{
        int n_bucket;
        int n_chain;
        int buckets[n_bucket];
        int chains[n_chain];
    }
    '''
    file.seek(offset, os.SEEK_SET)
    n_bucket = int.from_bytes(file.read(4), byteorder='little')
    n_chain = int.from_bytes(file.read(4), byteorder='little')
    total_size = (n_bucket + n_chain + 2) * 4   
    return total_size

#return append position
def append_bytes_to_file(file, bytes):
    file.seek(0, os.SEEK_END)
    offset = file.tell()
    file.write(bytes)
    return offset    

if __name__ == '__main__':
    so_name = "xxx.so"      # 这里写要修复的so
    try:
        print('[+]Try to backup %s'%so_name)
        copyfile(so_name, so_name + "_bak")
    except:
        print("[-]Backup failed for Unexpected error:", sys.exc_info())
        exit(1)
    f = open(so_name, "rb+")
    elf = ELFParser(f)
    #elf.displaySectionHeader()
    #elf.displayProgramHeader()
    #elf.displaySymbolTable()
    #elf.displayDynamicLinkTable()
    
    shstrtab_byteArray = create_shstrtab_byteArray()
    shstrtab_offset = append_bytes_to_file(f, shstrtab_byteArray)

    shdr_undef = create_section_undef(elf)
    shdr_dynstr = create_section_dynstr(elf)
    shdr_dynsym = create_section_dynsym(elf)
    shdr_hash = create_section_hash(f, elf)
    shdr_reldyn = create_section_reldyn(elf)
    shdr_relplt = create_section_relplt(elf)
    shdr_plt = create_section_plt(elf)
    shdr_fini_array = create_section_fini_array(elf)
    shdr_text = create_section_text(elf)
    shdr_init_array = create_section_init_array(elf)
    shdr_dynamic = create_section_dynamic(elf)
    shdr_shstrtab = create_section_shstrtab(elf, shstrtab_offset)

    #fix sh_link
    shdr_dynsym.sh_link = 1     #1 is .dynstr section index
    shdr_hash.sh_link = 2       #2 is .dynsym section index
    shdr_reldyn.sh_link = 2     
    shdr_relplt.sh_link = 2
    shdr_dynamic.sh_link = 1

    section_start_off = append_bytes_to_file(f, shdr_undef.serialize())
    append_bytes_to_file(f, shdr_dynstr.serialize())
    append_bytes_to_file(f, shdr_dynsym.serialize())
    append_bytes_to_file(f, shdr_hash.serialize())
    append_bytes_to_file(f, shdr_reldyn.serialize())
    append_bytes_to_file(f, shdr_relplt.serialize())
    append_bytes_to_file(f, shdr_plt.serialize())
    append_bytes_to_file(f, shdr_text.serialize())
    append_bytes_to_file(f, shdr_fini_array.serialize())
    append_bytes_to_file(f, shdr_init_array.serialize())
    append_bytes_to_file(f, shdr_dynamic.serialize())
    append_bytes_to_file(f, shdr_shstrtab.serialize())

    #fix section info in elf header
    f.seek(32, os.SEEK_SET)
    f.write(pack('I', section_start_off)) #fix e_shoff
    f.seek(46, os.SEEK_SET)
    f.write(pack('H', 40))
    f.seek(48, os.SEEK_SET)
    f.write(pack('H', 12)) #fix e_shnum
    f.seek(50, os.SEEK_SET)
    f.write(pack('H', 11)) #fix e_shtrndx(idx of shstrtab)

    

    


    






