class Elf32_Sym(object):
    """docstring for Elf32_Sym"""
    def __init__(self):
        super(Elf32_Sym, self).__init__()
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
        self.st_name = None
        self.st_value = None
        self.st_size = None
        self.st_info = None
        self.st_other = None
        self.st_shndx = None

        self.symbol_name = None
    def size():
          return 16
    def __str__(self):
        return 'Elf32_Dyn=[st_name=%s, st_value=%d, st_size=%d, st_info=%d, st_other=%d, st_shndx=%d] #%s' % \
               (self.st_name, self.st_value, self.st_size, self.st_info, self.st_other, self.st_shndx, self.symbol_name)