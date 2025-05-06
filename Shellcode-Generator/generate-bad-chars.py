import argparse
import re
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
import utils

parser = argparse.ArgumentParser(description="This script will generate a python buffer containing all the characters in order to find bad chars")
parser.add_argument("-b", metavar="BAD CHARS", type=utils.parse_bytes, default="\\x00", help=" bad characters")
parser.add_argument("-n", default="bad_chars", help=" the variable name to use")
parser.add_argument("-c", action="store_true", help=" specify if the built buffer needs to be concatenated to an existing value")

args = parser.parse_args()

bad_chars = args.b

print("Using the following bad characters")
print()

utils.disaply_shellcode(bad_chars, var_name="ignored_chars")

print()

av_bytes = []
for byte in range(0, 256):
    av_bytes.append(byte)

for byte in bad_chars:
    if byte in av_bytes:
        av_bytes.remove(byte)

utils.disaply_shellcode(av_bytes, var_name=args.n, concatenate=args.c)