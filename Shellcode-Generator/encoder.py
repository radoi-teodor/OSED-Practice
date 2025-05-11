from keystone import Ks, KS_ARCH_X86, KS_MODE_32
import utils

def encode(shellcode, bad_chars):
    av_bytes = []
    for byte in range(0, 256):
        av_bytes.append(byte)

    for byte in bad_chars:
        if byte in av_bytes:
            av_bytes.remove(byte)
    
    for byte in shellcode:
        if byte in av_bytes:
            av_bytes.remove(byte)


    # lista = [[1,2,3], [1,2,3, [4]], ...]
    # element descris:
    # 1 - bad char
    # 2 - replacement
    # 3 - 
    #       1 - increment
    #       2 - decrement
    #       3 - negativ
    #       4 - XOR
    # 4 - cheie de XOR (daca se aplica XOR)
    replacements = []

    for byte in bad_chars:
        inc_byte = byte+1
        dec_byte = byte-1
        neg_byte = -byte

        if(inc_byte in av_bytes):
            replacements.append([byte, dec_byte, 1])
        elif(dec_byte in av_bytes):
            replacements.append([byte, dec_byte, 2])
        elif(neg_byte in av_bytes):
            replacements.append([byte, neg_byte, 3])
        else: # calculam o cheie XOR disponibila si un rezultat disponibil
            found = False
            xor_byte = 0
            final_operand_byte = 0
            for operand_byte in av_bytes:
                xor_byte = byte ^ operand_byte
                final_operand_byte = operand_byte
                if xor_byte in av_bytes:
                    found = True
                    break
            
            if not found:
                raise ValueError("Unable to encode payload :(")

            replacements.append([byte, xor_byte, 4, final_operand_byte])

    # facem inlocuirile de bad char aici
    #

    CODE = """
    
    """

    CODE = utils.strip_comments(CODE)

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)

    encoded_shellcode = bytes(encoding)
    # vom adauga shellcode-ul encodat
    encoded_shellcode = encoded_shellcode + shellcode

    # pentru testari
    #exit()

    return encoded_shellcode

def sint_to_byte(i):
    i = i % 256
    return bytes([i])

def byte_to_uint(i):
    return int.from_bytes(i, byteorder="little", signed=False)

def byte_to_sint(i):
    return int.from_bytes(i, byteorder="little", signed=True)