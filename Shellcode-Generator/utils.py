import ctypes, struct
import argparse
import codecs

# functie care ne permite sa avem comentarii in codul assembly
# ca baietii de la keystone engine nu au nevoie de comentarii, ei citesc assembly cum citeam eu Creanga in copilarie
def strip_comments(asm_code):
    lines = asm_code.splitlines()
    clean_lines = []
    for line in lines:
        stripped = line.split(';', 1)[0].rstrip()
        if stripped:
            clean_lines.append(stripped)
    return '\n'.join(clean_lines)

def execute_shellcode(shellcode):
    # alocam memorie RWX pentru shellcode
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                            ctypes.c_int(len(shellcode)),
                                            ctypes.c_int(0x3000),
                                            ctypes.c_int(0x40))

    # copiem shellcode-ul in memoria alocata
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                        shellcode,
                                        ctypes.c_int(len(shellcode)))

    print("Shellcode located at address %s" % hex(ptr))


    # oprim executia script-ului pentru a putea conecta WinDBG la procesul python.exe
    input("...ENTER TO START SHELLCODE THREAD...")

    # creem thread-ul la adresa shellcode-ului
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.c_int(ptr),
                                            ctypes.c_int(0),
                                            ctypes.c_int(0),
                                            ctypes.pointer(ctypes.c_int(0)))

    # asteptam terminarea executiei shellcode-ului
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

def disaply_shellcode(shellcode):
    print("Shellcode length:", len(shellcode))
    shown_shellcode = "shellcode =  b\""

    idx = 0
    col_number = 10
    for byte in shellcode:
        if(idx % col_number == 0):
            shown_shellcode += "\"\nshellcode += b\""
        shown_shellcode += "\\x" + format(byte, '02x')
        idx = idx + 1
    shown_shellcode += "\""
    print(shown_shellcode)

def parse_bytes(arg):
    try:
        return codecs.escape_decode(arg)[0]
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid format for bytes: {arg}") from e