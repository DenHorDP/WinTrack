$source = 'E:\Soft\trackba.exe'
$target = 'E:\Soft\trackbb.exe'

$patches = @(
    @{
        Name = 'sub_47B6C0: jz -> jmp'
        Offset = 0x7B6E5
        Expected = [byte[]](0x74, 0x11)
        Replace = [byte[]](0xEB, 0x11)
    },
    @{
        Name = 'sub_481320: remove null-check branch'
        Offset = 0x8133C
        Expected = [byte[]](0x83, 0x7D, 0xF8, 0x00, 0x0F, 0x84, 0x81, 0x00, 0x00, 0x00)
        Replace = [byte[]](0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90)
    },
    @{
        Name = 'sub_47C280: early return after first call'
        Offset = 0x7C42B
        Expected = [byte[]](0x8B, 0x4D, 0xF4, 0x8B, 0x91, 0xC8, 0x1B, 0x00, 0x00, 0x52, 0xB9, 0x60, 0xA3, 0x54, 0x00, 0xE8, 0x61, 0xE1, 0xFC, 0xFF)
        Replace = [byte[]](0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90)
    }
)

if (-not (Test-Path -LiteralPath $source)) {
    throw "Source file not found: $source"
}

$bytes = [IO.File]::ReadAllBytes($source)

foreach ($patch in $patches) {
    $offset = [int]$patch.Offset
    $expected = [byte[]]$patch.Expected
    for ($i = 0; $i -lt $expected.Length; $i++) {
        if ($bytes[$offset + $i] -ne $expected[$i]) {
            $actual = ($bytes[$offset..($offset + $expected.Length - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
            $want = ($expected | ForEach-Object { $_.ToString('X2') }) -join ' '
            throw "Patch '$($patch.Name)' expected $want at 0x$($offset.ToString('X')), found $actual"
        }
    }
}

Copy-Item -LiteralPath $source -Destination $target -Force
$out = [IO.File]::ReadAllBytes($target)

foreach ($patch in $patches) {
    $offset = [int]$patch.Offset
    $replace = [byte[]]$patch.Replace
    for ($i = 0; $i -lt $replace.Length; $i++) {
        $out[$offset + $i] = $replace[$i]
    }
    Write-Output ("Applied {0} at file offset 0x{1:X}" -f $patch.Name, $offset)
}

[IO.File]::WriteAllBytes($target, $out)
Get-FileHash -Algorithm SHA256 -LiteralPath $source, $target
