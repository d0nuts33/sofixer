from enum import IntEnum

class Elf32_Dyn(object):
    """docstring for Elf32_dyn"""
    def __init__(self):
        super(Elf32_Dyn, self).__init__()
        '''
        typedef struct dynamic{
          Elf32_Sword d_tag;
          union{
            Elf32_Sword	d_val;
            Elf32_Addr	d_ptr;
          } d_un;
        } Elf32_Dyn;
        '''
        self.d_tag = None
        self.d_un = None
    def size():
        return 8

    def __str__(self):
        return 'Elf32_Dyn=[d_tag=%d, d_un=%d]' % \
               (self.d_tag, self.d_un)

class DTag(IntEnum):
    NULL = 0,
    NEEDED = 1,
    PLTRELSZ = 2,
    PLTGOT = 3,
    HASH = 4,
    STRTAB = 5,
    SYMTAB = 6,
    RELA = 7,
    RELASZ = 8,
    RELAENT = 9,
    STRSZ = 10,
    SYMENT = 11,
    INIT = 12,
    FINIT = 13,
    SONAME = 14,
    RPATH = 15,
    SYMBOLIC = 16,
    REL = 17,
    RELSZ = 18,
    RELENT = 19,
    PLTREL = 20,
    DEBUG = 21,
    TEXTREL = 22,
    JMPREL = 23,
    INIT_ARRAY = 25,
    FINIT_ARRAY = 26,
    INIT_ARRAYSZ = 27,
    FINIT_ARRAYSZ = 28,

'''
Elf32_Dyn.d_tag
'''
DYNAMIC_TYPE = {
    0: 'NULL',
    1: 'NEEDED',
    2: 'PLTRELSZ',
    3: 'PLTGOT',
    4: 'HASH',
    5: 'STRTAB',
    6: 'SYMTAB',
    7: 'RELA',
    8: 'RELASZ',
    9: 'RELAENT',
    10: 'STRSZ',
    11: 'SYMENT',
    12: 'INIT',
    13: 'FINIT',
    14: 'SONAME',
    15: 'RPATH',
    16: 'SYMBOLIC',
    17: 'REL',
    18: 'RELSZ',
    19: 'RELENT',
    20: 'PLTREL',
    21: 'DEBUG',
    22: 'TEXTREL',
    23: 'JMPREL',
    26: 'FINIT_ARRAY',
    28: 'FINIT_ARRAYSZ',
    25: 'INIT_ARRAY',
    27: 'INIT_ARRAYSZ',
    30: 'FLAGS',
    0x6FFFFEF5: 'GNU_HASH',
    0x6FFFFFF0: 'VERSYM',
    0x6FFFFFFA: 'RELCOUNT',
    0x6FFFFFFB: 'FLAGS_1',
    0x6FFFFFFE: 'VERNEED',
    0x6FFFFFFF: 'VERNEEDNUM',
    0x70000000: 'LOPROC',
    0x7fffffff: 'HIPROC',
    0x70000001: 'MIPS_RLD_VERSION',
    0x70000002: 'MIPS_TIME_STAMP',
    0x70000003: 'MIPS_ICHECKSUM',
    0x70000004: 'MIPS_IVERSION',
    0x70000005: 'MIPS_FLAGS',
    0x70000006: 'MIPS_BASE_ADDRESS',
    0x70000008: 'MIPS_CONFLICT',
    0x70000009: 'MIPS_LIBLIST',
    0x7000000a: 'MIPS_LOCAL_GOTNO',
    0x7000000b: 'MIPS_CONFLICTNO',
    0x70000010: 'MIPS_LIBLISTNO',
    0x70000011: 'MIPS_SYMTABNO',
    0x70000012: 'MIPS_UNREFEXTNO',
    0x70000013: 'MIPS_GOTSYM',
    0x70000014: 'MIPS_HIPAGENO',
    0x70000016: 'MIPS_RLD_MAP',
}