import ctypes, struct
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

CODE = """
    xor eax, eax        ; facem EAX 0
    mov eax, fs:[0x30]  ; preluam adresa PEB in memoria EAX
    mov eax, [eax + 0x0C]  ; salvam structura PEB->Ldr
    mov eax, [eax + 0x1C]  ; ne ducem pe primul entry din
                           ; InInitializationOrderModuleList (FLINK - forward LINK)
    mov eax, [eax]         ; ne ducem pe adresa modulului din pointer
    mov eax, [eax + 0x08]  ; adresa din lista -0x10 (pentru a afla adresa 
                           ; _LDR_DATA_TABLE_ENTRY) +0x18 (pantru proprietatea DllBase) 
    ret                    ;
"""

ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)

shellcode = bytes(encoding)

# vom afisa shellcode-ul
print("Shellcode length:", len(shellcode))
print(shellcode)

# alocam memorie RWX pentru shellcode
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

# copiem shellcode-ul in memoria alocata
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))

# oprim executia script-ului pentru a putea conecta WinDBG la procesul python.exe
input("...ENTER TO EXECUTE SHELLCODE...")

# creem thread-ul la adresa shellcode-ului
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

# asteptam terminarea executiei shellcode-ului
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))