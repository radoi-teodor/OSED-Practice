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
    ; creem stiva
    mov ebp, esp
    sub esp, 0x200

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


; rezolvam functii din kernel32.dll
resolve_symbols_kernel32:
     push 0x78b5b983             ; has ROT 13 - TerminateProcess
     call search_function         ; apelam find_name_loop
     mov [ebp+0x10], eax         ; salvam adresa TerminateProcess

     push 0xec0e4e8e             ; has ROT 13 - LoadLibraryA
     call search_function         ; Call find_name_loop
     mov [ebp+0x14], eax         ; salvam adresa LoadLibraryA

     push 0x16b3fe72             ; has ROT 13 - CreateProcessA
     call search_function         ; Call find_name_loop
     mov [ebp+0x18], eax         ; salvam adresa CreateProcessA


; acum vom cauta functii in kernel32.dll
search_function:
    mov edx, [esp+4] ; preluam parametrul din stiva - parametrul este hash-ul functiei cautate
    ; facem +4 pentru a sari peste return address-ul functiei

    pushad                        ; salvam toate registrele

    mov eax, [ebx + 0x3C]        ; offset catre PE Header
    mov edi, [ebx + eax + 0x78]  ; RVA Export Directory Table
    add edi, ebx                 ; VMA Export Directory Table

    mov ecx, [edi + 0x18]        ; salvam NumberOfNames (cate functii exportate sunt)
                                 ; pe ECX

    mov eax, [edi + 0x20]        ; RVA AddressOfNames array
    add eax, ebx                 ; VMA AddressOfNames array

save_names_vma:
    mov [esp - 4], eax           ; salvam VMA AddressOfNames pe stack (safe)
    mov [esp - 8], edx           ; salvam functia cautata inainte de ESP (salvare sigura pentru a nu perturba backup-ul registrilor facut cu `pushad`)

find_name_loop:
    jecxz end_find_name          ; daca ECX == 0, am iterat pana la sfarsit
    dec ecx                      ; ECX = ECX - 1
    mov eax, [esp - 4]           ; restauram VMA AddressOfNames
    mov esi, [eax + ecx*4]       ; luam RVA simbol curent (4 bytes are un index)
    add esi, ebx                 ; VMA simbol curent in ESI

; vom verifica numele functiei
compute_hash:
    xor eax, eax                 ; stergem EAX 
    xor edx, edx                 ; clear EDX (hash calculat a ramas in EDX)
    cld                          ; setam DF pe 0 (mergem in fata in iteratie) - OPTIONAL

hash_loop:
    lodsb                        ; incarcam urmatorul caracter in registrul AL
    test al, al                  ; daca AL este 0, am ajuns la sfarsitul string-ului
    jz hash_done

    ror edx, 0x0d                ; executam ROT 13 (rotim la dreapta 13 biti)
    add edx, eax                 ; adaugam rezultatul la suma
    jmp hash_loop                ; sarim inapoi in loop pentru urmatorul caracter

hash_done:
    cmp edx, [esp - 8]           ; este hash-ul functiei cautate?
    jne find_name_loop

found_name:
    ; luam AddressOfOrdinals
    ; EDI -> adresa absoluta a Export Directory Table
    ; EBX -> adresa de baza a modulului KERNEL32.DLL

    mov eax, [edi + 0x24]        ; salvam RVA AddressOfOrdinals
    add eax, ebx                 ; calculam VMA AddressOfOrdinals

    xor edx, edx                 ; EDX inca va avea hash-ul functiei, asa ca ii dam clear inainte sa facem orice cu el
    mov dx, [eax + ecx*2]        ; luam ordinal (WORD) in DX

    ; luam AddressOfFunctions
    mov eax, [edi + 0x1C]        ; RVA AddressOfFunctions
    add eax, ebx                 ; VMA AddressOfFunctions

    mov eax, [eax + edx*4]       ; RVA functie gasita
    add eax, ebx                 ; VMA functie in EAX

end_find_name:
    popad                        ; restauram registrele, am gasit functia
    ret
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