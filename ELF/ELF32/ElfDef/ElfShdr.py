from struct import *
from enum import IntEnum

class Elf32_Shdr(object):
    """docstring for Elf32_Shdr"""
    def __init__(self):
        super(Elf32_Shdr, self).__init__()
        '''
        typedef struct Elf32_Shdr {
          Elf32_Word	sh_name;
          Elf32_Word	sh_type;
          Elf32_Word	sh_flags;
          Elf32_Addr	sh_addr;
          Elf32_Off	sh_offset;
          Elf32_Word	sh_size;
          Elf32_Word	sh_link;
          Elf32_Word	sh_info;
          Elf32_Word	sh_addralign;
          Elf32_Word	sh_entsize;
        } Elf32_Shdr;
        '''
        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None

        self.section_name = None
    
    def size():
        return 40

    def serialize(self):
        packed = pack('IIIIIIIIII', \
            self.sh_name, \
            self.sh_type, \
            self.sh_flags, \
            self.sh_addr, \
            self.sh_offset, \
            self.sh_size, \
            self.sh_link, \
            self.sh_info, \
            self.sh_addralign, \
            self.sh_entsize)
        return packed

    def __str__(self):
        return 'Elf32_Shdr=[sh_name=%s, sh_type=%d, sh_flags=%d, sh_addr=%s, sh_sh_offset=%s, sh_size=%d, sh_link=%d, sh_info=%d, sh_addralign=%d, sh_entsize=%d]' % \
               (hex(self.sh_name), self.sh_type, self.sh_flags, hex(self.sh_addr), hex(self.sh_offset), self.sh_size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize)

'''
# sh_type 
SHT_NULL	0
SHT_PROGBITS	1
SHT_SYMTAB	2
SHT_STRTAB	3
SHT_RELA	4
SHT_HASH	5
SHT_DYNAMIC	6
SHT_NOTE	7
SHT_NOBITS	8
SHT_REL	9
SHT_SHLIB	10
SHT_DYNSYM	11
SHT_NUM	12
SHT_LOPROC	0x70000000
SHT_HIPROC	0x7fffffff
SHT_LOUSER	0x80000000
SHT_HIUSER	0xffffffff
SHT_MIPS_LIST	0x70000000
SHT_MIPS_CONFLICT	0x70000002
SHT_MIPS_GPTAB	0x70000003
SHT_MIPS_UCODE	0x70000004
'''
class ShType(IntEnum):
      SHT_NULL = 0
      SHT_PROGBITS = 1
      SHT_SYMTAB = 2
      SHT_STRTAB = 3
      SHT_RELA = 4
      SHT_HASH = 5
      SHT_DYNAMIC = 6
      SHT_NOTE = 7
      SHT_NOBITS = 8
      SHT_REL = 9
      SHT_SHLIB = 10
      SHT_DYNSYM = 11
      SHT_NUM = 12
      SHT_INIT_ARRAY = 14
      SHT_FINI_ARRAY = 15
      SHT_LOPROC = 0x70000000
      SHT_HIPROC = 0x7fffffff
      SHT_LOUSER = 0x80000000
      SHT_HIUSER = 0xffffffff
      SHT_MIPS_LIST =	0x70000000
      SHT_MIPS_CONFLICT =	0x70000002
      SHT_MIPS_GPTAB =	0x70000003
      SHT_MIPS_UCODE =	0x70000004

class ShFlags(IntEnum):
      SHT_NULL = 0
      SHF_WRITE = (1 << 0)	# Writable 
      SHF_ALLOC = (1 << 1)	# Occupies memory during execution 
      SHF_EXECINSTR = (1 << 2)	# Executable 
      SHF_MERGE = (1 << 4)	# Might be merged 
      SHF_STRINGS = (1 << 5)	# Contains nul-terminated strings 
      SHF_INFO_LINK = (1 << 6)	# `sh_info' contains SHT index 
      SHF_LINK_ORDER = (1 << 7)	# Preserve order after combining 
      SHF_OS_NONCONFORMING = (1 << 8)	# Non-standard OS specific handling required 
      SHF_GROUP = (1 << 9)	# Section is member of a group.  
      SHF_TLS	 = (1 << 10)	# Section hold thread-local data.  
      SHF_MASKOS = 0x0ff00000	# OS-specific.  
      SHF_MASKPROC = 0xf0000000	# Processor-specific 
      SHF_ORDERED = (1 << 30)	# Special ordering requirement(Solaris).  
      SHF_EXCLUDE = (1 << 31)	# Section is excluded unlessreferenced or allocated (Solaris).

SH_TYPE_MAP_LIST = {0:'SHT_NULL',
                    1:'SHT_PROGBITS',
                    2:'SHT_SYMTAB',
                    3:'SHT_STRTAB',
                    4:'SHT_RELA',
                    5:'SHT_HASH',
                    6:'SHT_DYNAMIC',
                    7:'SHT_NOTE',
                    8:'SHT_NOBITS',
                    9:'SHT_REL',
                    10:'SHT_SHLIB',
                    11:'SHT_DYNSYM',
                    15:'SHF_INIT_ARRAY',
                    15:'SHT_FINI_ARRAY',
                    # 0x60000000:'SHT_LOOS',
                    0x6fffffff:'SHT_HIOS',
                    0x70000000:'SHT_LOPROC',
                    0x7FFFFFFF:'SHT_HIPROC',
                    0x80000000:'SHT_LOUSER',
                    0x8FFFFFFF:'SHT_HIUSER',
                    0x70000000:'SHT_MIPS_LIST',
                    0x70000002:'SHT_MIPS_CONFLICT',
                    0x70000003:'SHT_MIPS_GPTAB',
                    0x70000004:'SHT_MIPS_UCODE',
                    }