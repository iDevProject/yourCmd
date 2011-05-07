#!/usr/bin/python
import struct
bytesize=2
def hex2dec(s):
        return int(s, 16)
def dec2hex(n):
    return "%X" % n
def baseaddr(data):
        irqhandlr=data[hex2dec("0x38"):hex2dec("0x38")+4];
	baseaddr_end=irqhandlr.encode('hex')[6:8]
	return baseaddr_end + "000000"
def cmdptr(data):
        return dec2hex(data.find('reset'));
def cmdptr_custom(data, cmd):
        return dec2hex(data.find(cmd));
def endianFlip(str):
	return struct.pack("<I", int(str, 16)).encode('hex')
def findRef(data):
	print "Baseaddr for image: 0x" + baseaddr(data)
	print "Pointer to unused cmd 'reset' relative to file: 0x" + cmdptr(data)
	memptr=dec2hex(hex2dec(baseaddr(data)) + hex2dec(cmdptr(data)));
	print "Pointer to unused cmd 'reset' in memory: 0x" + memptr
	print "EndianFlipped pointer: 0x" + endianFlip(memptr)
	print "Searching xref to endianflipped pointer.."
	cmptr=data.find(endianFlip(memptr).decode('hex'))
	print "XRef to a CmdStruct struct handler: 0x" + dec2hex(hex2dec(baseaddr(data))+cmptr)
	return cmptr

def findRef_custom(data, cmd):
	print "Baseaddr for image: 0x" + baseaddr(data)
	print "Pointer to unused cmd '" + cmd + "' relative to file: 0x" + cmdptr_custom(data, cmd)
	memptr=dec2hex(hex2dec(baseaddr(data)) + hex2dec(cmdptr_custom(data, cmd)));
	print "Pointer to unused cmd '" + cmd + "' in memory: 0x" + memptr
	print "EndianFlipped pointer: 0x" + endianFlip(memptr)
	print "Searching xref to endianflipped pointer.."
	cmptr=data.find(endianFlip(memptr).decode('hex'))
	print "XRef to a CmdStruct struct handler: 0x" + dec2hex(hex2dec(baseaddr(data))+cmptr)
	return cmptr

import sys
print ""
print "yourCmd, an iBSS Command handler Replacer"
if len(sys.argv) == 1:
	print "./yourCmd.py iBSS_file [specified cmd]"
	print ""
	exit()

if len(sys.argv) == 3:
	print "Patching with custom command..."
	dat=open(sys.argv[1]).read();
	command=sys.argv[2]
	obj=findRef_custom(dat, command)
	"""
	obj:
	nameptr = n
	descptr = d
	handler = h

	nnnnddddhhhh

	we'll mod hhhh

	"""
	handlr="0x41000000"
	print "Assuming that loadaddr is " + handlr
	structure=dat[obj:obj+12]
	print "Struct: " + structure.encode('hex')
	print "Genning a diff..."
	print
	print
	print "# Difference file built with YourCmd, an iBSS Analyzer"
	print
	print "0x" + dec2hex(obj+4) + ": 0x" + endianFlip(handlr)
	exit()

dat=open(sys.argv[1]).read();
obj=findRef(dat)
"""
obj:
nameptr = n
descptr = d
handler = h

nnnnddddhhhh

we'll mod hhhh

"""
handlr="0x41000000"
print "Assuming that loadaddr is " + handlr
structure=dat[obj:obj+12]
print "Struct: " + structure.encode('hex')
print "Genning a diff..."
print
print
print "# Difference file built with YourCmd, an iBSS Analyzer"
print
print "0x" + cmdptr(dat) + ": 6C6F616400"
print "0x" + dec2hex(obj+4) + ": " + endianFlip(handlr)

print
print "Injected the 'load' command. Apply the patch and enjoy."