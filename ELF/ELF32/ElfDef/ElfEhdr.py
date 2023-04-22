'''
typedef struct elf32_hdr{
  unsigned char	e_ident[EI_NIDENT];
  Elf32_Half	e_type;
  Elf32_Half	e_machine;
  Elf32_Word	e_version;
  Elf32_Addr	e_entry;  /* Entry point */
  Elf32_Off	e_phoff;
  Elf32_Off	e_shoff;
  Elf32_Word	e_flags;
  Elf32_Half	e_ehsize;
  Elf32_Half	e_phentsize;
  Elf32_Half	e_phnum;
  Elf32_Half	e_shentsize;
  Elf32_Half	e_shnum;
  Elf32_Half	e_shstrndx;
} Elf32_Ehdr;
'''
class Elf32_Ehdr(object):
    """docstring for Elf32_Ehdr"""
    def __init__(self):
        super(Elf32_Ehdr, self).__init__()
        self.e_ident = None
        self.e_type = None
        self.e_machine = None
        self.e_version = None
        self.e_entry = None
        self.e_phoff = None
        self.e_shoff = None
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shstrndx = None

class e_ident(object):
    """docstring for e_ident"""
    def __init__(self):
        super(e_ident, self).__init__()
        self.file_identification = None
        self.ei_class = None
        self.ei_data = None
        self.ei_version = None
        self.ei_osabi = None
        self.ei_abiversion = None
        self.ei_pad = None
        self.ei_nident = None

    def __str__(self):
        return 'e_ident=[file_identification=%s, ei_class=%d, ei_data=%d, ei_version=%d, ei_osabi=%d, ei_abiversion=%d, ei_pad=%s, ei_nident=%d]' % (
        self.file_identification, self.ei_class, self.ei_data, self.ei_version, self.ei_osabi, self.ei_abiversion, self.ei_pad, self.ei_nident)