import sys

def compute_hash(s):
    edx = 0
    for c in s:
        edx = ((edx >> 13) | (edx << (32 - 13))) & 0xFFFFFFFF  # ror 13
        edx = (edx + ord(c)) & 0xFFFFFFFF                      # adaugam caracterul
    return hex(edx)

if(len(sys.argv) != 2):
    print("Usage: python " + sys.argv[0] + " {function name to hash}")
    exit()

print("Hash: " + sys.argv[1] + " - " + compute_hash(sys.argv[1]))