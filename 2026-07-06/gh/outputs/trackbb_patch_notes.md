# trackbb.exe patch notes

Source: `E:\Soft\trackba.exe`

Output: `E:\Soft\trackbb.exe`

## Hashes

- `trackba.exe` SHA-256: `6C2C85A0D37E3FFA78A718C4B921907F3C84865AC049ED0A62CE7A519EEDF809`
- `trackbb.exe` SHA-256: `B1E07AFC023A8ED6F0BFEF857D6F47A01DBFEF155F518D4803970A0C67694074`

## Applied byte patches

1. `sub_47B6C0`, file offset `0x7B6E5`
   - Before: `74`
   - After: `EB`
   - Meaning: `jz short loc_47B6F8` becomes `jmp short loc_47B6F8`.

2. `sub_481320`, file offsets `0x8133C-0x81345`
   - Before: `83 7D F8 00 0F 84 81 00 00 00`
   - After: `90 90 90 90 90 90 90 90 90 90`
   - Meaning: remove the local `cmp [ebp+var_8], 0` / `jz loc_4813C7` branch.

3. `sub_47C280`, file offsets `0x7C42B-0x7C43E`
   - Before: `8B 4D F4 8B 91 C8 1B 00 00 52 B9 60 A3 54 00 E8 61 E1 FC FF`
   - After: `8B E5 5D C2 04 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90`
   - Meaning: return immediately at this point, matching the shorter `trackab.exe` control flow pattern.

## Not applied automatically

The `Toolbar -> sub_4EDBE9` site in `trackba.exe` corresponds to a real `trackaa.exe -> trackab.exe` change, but the surrounding flow in `trackab.exe` is not a simple same-size local replacement. I left it unpatched to avoid guessing.

## Verification

`trackbb.exe` has the same size as `trackba.exe`: `1,953,792` bytes.

`trackbb.exe` differs from `trackba.exe` only in the three ranges listed above: 30 bytes total.
