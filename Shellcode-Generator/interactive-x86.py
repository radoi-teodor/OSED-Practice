from keystone import Ks, KS_ARCH_X86, KS_MODE_32
import utils

while True:
    try:
        CODE = input("ASM Command: ").strip()

        if(CODE == "exit"):
            print("[+] Quitting...")
            break

        CODE = utils.strip_comments(CODE)

        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)

        shellcode = bytes(encoding)

        utils.display_shellcode(shellcode, concatenate=True)
    except:
        print("Command not found")