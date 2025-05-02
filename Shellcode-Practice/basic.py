import ctypes, struct
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

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

CODE = """
start:
    xor eax, eax        ;
    mov eax, fs:[0x30]  ;
    mov eax, [eax + 0x0C]  ; 
    mov esi, [eax + 0x1c]  ; salvam pointer catre Flink in ESI

next_module:
    ; toate offset-urile vor fi -0x10 pentru a merge in baza _LDR_DATA_TABLE_ENTRY
    mov ebx, [esi + 0x08]    ; + 0x18 pentru a merge in DllBase si rezolvam si adresa pointerului

    ; ATENTIE - proprietatea _UNICODE_STRING din _LDR_DATA_TABLE_ENTRY nu e pointer, e salvata ca structura in memorie
    mov edi, esi     ; mutam temporar ESI in EDI pentru a aduna dupa, sa rezulte adresa _UNICODE_STRING
    add edi, 0x1c    ; + 0x1c pentru a merge in BaseDllName (adresa catre _UNICODE_STRING)
    mov edi, [edi + 0x04]    ; ne ducem in Buffer din _UNICODE_STRING

check_char:
    mov ax, [edi]            ; ne ducem in adresa pointer-ului Buffer din _UNICODE_STRING (primul caracter unicode)
                             ; 
    cmp al, 'K'              ; 
    jne skip                 ; 
    cmp ah, 0x00
    jne skip

    cmp word ptr [edi + 2], 0x0045 ; 0x0045 - 'E' unicode
    jne skip
    cmp word ptr [edi + 4], 0x0052 ; 0x0052 - 'R' unicode
    jne skip
    cmp word ptr [edi + 6], 0x004e ; 0x004e - 'N' unicode
    jne skip

    cmp word ptr [edi + 12], 0x0033 ; 0x0033 - '3' unicode (verificam daca al 7 lea caracter este '3' pentru a nu lua adresa KERNELBASE in loc de KERNEL32)
    jne skip

    jmp found

skip:
    mov esi, [esi]           ; trecem la urmatorul modul
    jmp next_module

found:
    mov eax, ebx             ; salvam adresa de inceput a DLL-ului in EAX
    ret                    ;
"""


CODE = strip_comments(CODE)

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
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     shellcode,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))

# oprim executia script-ului pentru a putea conecta WinDBG la procesul python.exe
input("...ENTER TO EXECUTE SHELLCODE...")

ctypes.windll.kernel32.GetModuleHandleA(None)

# creem thread-ul la adresa shellcode-ului
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

# asteptam terminarea executiei shellcode-ului
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))