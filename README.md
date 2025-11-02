# DKUWARE

Simple multi-threaded file encryptor/restorer created as a 2024 personal project.

## Files
- `dkuware.c` — main program: scans `target/`, spawns threads to attack/restore `.pdf` and `.jpg`. 
- `crypto.c` — AES-128-ECB encrypt/decrypt utilities. 
- `crypto.h` — crypto function declarations and constants. 
- `utils.c` — prints ransom and recovery notes. 
- `utils.h` — utility function headers. 
- `note_enc.txt` — ransom ASCII art/note shown after `attack`.  
- `note_dec.txt` — recovery ASCII art/note shown after `restore`. 
- `Makefile` — build instructions.

## Build & Run
```bash
make
./dkuware attack <key>
./dkuware restore <key>
```

## Note
For educational use only. Do not run on real systems without permission.
