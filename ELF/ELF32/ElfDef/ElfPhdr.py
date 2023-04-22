from enum import IntEnum

class Elf32_Phdr(object):
    """docstring for Elf32_Phdr"""
    def __init__(self):
        super(Elf32_Phdr, self).__init__()
        '''
            /* 32-bit ELF base types. */
            typedef uint32_t Elf32_Addr;
            typedef uint16_t Elf32_Half;
            typedef uint32_t Elf32_Off;
            typedef int32_t  Elf32_Sword;
            typedef uint32_t Elf32_Word;
        '''
        self.p_type = None # Elf32_Word
        self.p_offset = None # Elf32_Off
        self.p_vaddr = None # Elf32_Addr
        self.p_paddr = None # Elf32_Addr
        self.p_filesz = None # Elf32_word
        self.p_memsz = None # Elf32_Word
        self.p_flags = None # Elf32_Word
        self.p_align = None # Elf32_Word

    def size():
        return 32
        
class PType(IntEnum):
    NULL = 0,
    LOAD = 1,
    DYNAMIC = 2,
    INTERP = 3,
    NOTE = 4,
    SHLIB = 5,
    PHDR = 6,
    TLS = 7,
    LOPROC = 0x70000000,
    HIPROC = 0x70000001,
    GNU_STACK = 0x6474E551,
    GNU_RELRO = 0x6474E552

PT_TYPE_MAP_LIST = {
    0:'NULL',
    1:'LOAD',
    2:'DYNAMIC',
    3:'INTERP',
    4:'NOTE',
    5:'SHLIB',
    6:'PHDR',
    7:'TLS',
    0x70000000:'LOPROC',
    0x70000001:'HIPROC',
    0x6474E551:'GNU_STACK',
    0x6474E552:'GNU_RELRO',
}