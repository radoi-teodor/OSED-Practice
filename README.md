# General
This repository will include all my materials used to learn for EXP-301 exam and maybe something extra.
Feel free to use any script written here or fork the repo and modify the scripts for your needs. The scripts will be mostly commented in romanian, because I am romanian (#MâRGA).

# Shellcode Generator
To use the shellcode generator, execute `main.py` from `Shellcode-Generator` directory.
Example to create an encoded shellcode that avoids bad characters `0x00` and `0x0a`:
```
python main.py -d -e -b \x00\x0a
```

For information about the flags, use:
```
python main.py -h
```