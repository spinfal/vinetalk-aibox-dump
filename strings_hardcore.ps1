# standalone string/PEM extractor
param(
  [string]$BinsDir = "bins",
  [string]$OutDir  = "out2",
  [int]$MinLen = 4
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Read-AllBytes([string]$path) {
  return [System.IO.File]::ReadAllBytes($path)
}

function Write-UniqueLines([string[]]$lines, [string]$path) {
  $lines | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Sort-Object -Unique | Out-File -FilePath $path -Encoding ascii
}

# ascii strings with offsets
function Extract-AsciiStrings([byte[]]$buf, [int]$minLen) {
  $res = New-Object System.Collections.Generic.List[object]
  $start = -1
  $sb = New-Object System.Text.StringBuilder
  for ($i=0;$i -lt $buf.Length; $i++) {
    $b = $buf[$i]
    if ($b -ge 0x20 -and $b -le 0x7E) {
      if ($start -lt 0) { $start = $i }
      [void]$sb.Append([char]$b)
    } else {
      if ($sb.Length -ge $minLen) {
        $res.Add([pscustomobject]@{ Offset=$start; Text=$sb.ToString() })
      }
      $sb.Clear() | Out-Null
      $start = -1
    }
  }
  if ($sb.Length -ge $minLen) {
    $res.Add([pscustomobject]@{ Offset=$start; Text=$sb.ToString() })
  }
  return $res
}

# utf16le strings with offsets (ASCII chars interleaved with 0x00)
function Extract-Utf16Strings([byte[]]$buf, [int]$minLen) {
  $res = New-Object System.Collections.Generic.List[object]
  $start = -1
  $count = 0
  $sb = New-Object System.Text.StringBuilder
  $i=0
  while ($i -lt $buf.Length-1) {
    $lo = $buf[$i]
    $hi = $buf[$i+1]
    if ($hi -eq 0 -and $lo -ge 0x20 -and $lo -le 0x7E) {
      if ($start -lt 0) { $start = $i }
      [void]$sb.Append([char]$lo)
      $count++
      $i += 2
    } else {
      if ($count -ge $minLen) {
        $res.Add([pscustomobject]@{ Offset=$start; Text=$sb.ToString() })
      }
      $sb.Clear() | Out-Null; $count=0; $start=-1; $i++
    }
  }
  if ($count -ge $minLen) {
    $res.Add([pscustomobject]@{ Offset=$start; Text=$sb.ToString() })
  }
  return $res
}

# tolerant PEM recovery
function Recover-PEM([byte[]]$buf, [string]$label) {
  $text = -join ($buf | ForEach-Object { if ($_ -ne 0) { [char]$_ } else { "" } })
  $pattern = '-----BEGIN [^-]+-----.*?-----END [^-]+-----'
  $matches = [System.Text.RegularExpressions.Regex]::Matches($text, $pattern, 'Singleline')
  $list = @()
  foreach ($m in $matches) { $list += $m.Value }
  return $list
}

# find base64 blobs (long) and attempt JSON-decode
function Find-Base64([byte[]]$buf, [int]$minLen=40) {
  $text = -join ($buf | ForEach-Object { if ($_ -ne 0) { [char]$_ } else { "" } })
  $re = '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{' + $minLen + ',}={0,2}(?![A-Za-z0-9+/=])'
  $m = [System.Text.RegularExpressions.Regex]::Matches($text, $re)
  $ret = @()
  foreach ($mm in $m) { $ret += $mm.Value }
  return $ret
}

# context around offsets
function Slice-Context([byte[]]$buf, [int]$offset, [int]$before=32, [int]$after=64) {
  $s=[Math]::Max(0,$offset-$before); $e=[Math]::Min($buf.Length-1,$offset+$after)
  $slice = $buf[$s..$e]
  return [System.Text.Encoding]::ASCII.GetString(($slice | ForEach-Object { if ($_ -eq 0) { 32 } else { $_ } }))
}

$files = Get-ChildItem -Path $BinsDir -Filter *.bin | Sort-Object Name
if ($files.Count -eq 0) { Write-Error "no .bin files in $BinsDir"; exit 1 }

# make per-file dirs
foreach ($f in $files) {
  $base = $f.Name
  $dir = Join-Path $OutDir $base
  New-Item -ItemType Directory -Force -Path $dir | Out-Null

  $buf = Read-AllBytes $f.FullName

  $ascii = Extract-AsciiStrings $buf $MinLen
  $utf16 = Extract-Utf16Strings $buf $MinLen

  # write raw strings with offsets
  ($ascii | ForEach-Object { "$($_.Offset): $($_.Text)" }) | Out-File -FilePath (Join-Path $dir "ascii_offsets.txt") -Encoding ascii
  ($utf16 | ForEach-Object { "$($_.Offset): $($_.Text)" }) | Out-File -FilePath (Join-Path $dir "utf16le_offsets.txt") -Encoding ascii

  # combined unique list (no offsets)
  $comb = ($ascii + $utf16 | ForEach-Object { $_.Text }) | Sort-Object -Unique
  $comb | Out-File -FilePath (Join-Path $dir "strings_unique.txt") -Encoding ascii

  # regex hits with context
  $reUrl   = 'https?://[^\s""''<>(){}\\]+'
  $reWsUrl = 'wss?://[^\s""''<>(){}\\]+'
  $reEmail = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
  $reIPv4  = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
  $reMQTT  = '(?i)\b(?:mqtt|wss|ws|broker|topic|clientid|subscribe|publish)\b'
  $reCred  = '(?i)\b(?:token|access[_-]?token|refresh[_-]?token|auth|authorization|apikey|api[_-]?key|secret|client[_-]?id|client[_-]?secret|bearer|passwd|password)\b'

  $hits = @()
  foreach ($e in $ascii) {
    $t = $e.Text
    if ($t -match $reUrl -or $t -match $reWsUrl -or $t -match $reEmail -or $t -match $reIPv4 -or $t -match $reMQTT -or $t -match $reCred) {
      $ctx = Slice-Context $buf $e.Offset 64 96
      $hits += [pscustomobject]@{ Offset=$e.Offset; Text=$t; Context=$ctx }
    }
  }
  $hits | Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path $dir "hits_with_context.txt") -Encoding ascii

  # PEM recovery
  $pems = Recover-PEM $buf $null
  if ($pems.Count -gt 0) {
    $i=0
    foreach ($pem in $pems) {
      $i++
      $p = Join-Path $dir ("pem_recovered_{0:D2}.pem" -f $i)
      $pem | Out-File -FilePath $p -Encoding ascii
    }
  }

  # base64 blobs (long)
  $b64 = Find-Base64 $buf 48
  Write-UniqueLines $b64 (Join-Path $dir "base64_candidates.txt")
}

Write-Host "[done] outputs in $OutDir (per-bin folders with offsets, hits, PEM, base64)"