param(
  [string]$BinsDir = ".\bins",
  [string]$OutDir = ".\out_compressed"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Read-AllBytes([string]$path) {
  return [System.IO.File]::ReadAllBytes($path)
}

# try to inflate raw DEFLATE data (optionally skipping 2-byte zlib header)
function Try-Inflate([byte[]]$buf, [int]$offset) {
  try {
    $ms = New-Object System.IO.MemoryStream
    # copy from offset to end
    $ms.Write($buf, $offset, $buf.Length - $offset)
    $ms.Position = 0
    $ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $outMs = New-Object System.IO.MemoryStream
    $ds.CopyTo($outMs)     # may throw if header invalid
    $ds.Close(); $ms.Close()
    return $outMs.ToArray()
  } catch {
    return $null
  }
}

function Try-Inflate-Zlib([byte[]]$buf, [int]$offset) {
  # zlib header is 2 bytes; skip and inflate raw deflate
  return Try-Inflate $buf ($offset+2)
}

function Try-Inflate-Gzip([byte[]]$buf, [int]$offset) {
  try {
    $ms = New-Object System.IO.MemoryStream
    $ms.Write($buf, $offset, $buf.Length - $offset)
    $ms.Position = 0
    $gs = New-Object System.IO.Compression.GzipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $outMs = New-Object System.IO.MemoryStream
    $gs.CopyTo($outMs)
    $gs.Close(); $ms.Close()
    return $outMs.ToArray()
  } catch {
    return $null
  }
}

# scan binary for possible zlib/gzip members
function Scan-Compressed([byte[]]$buf) {
  $hits = @()
  for ($i=0; $i -lt $buf.Length-2; $i++) {
    $b0 = $buf[$i]; $b1 = $buf[$i+1]
    # detect zlib headers 78 01 / 78 9C / 78 DA (common)
    if ($b0 -eq 0x78 -and ($b1 -eq 0x01 -or $b1 -eq 0x9C -or $b1 -eq 0xDA)) {
      $hits += [pscustomobject]@{ Offset=$i; Kind="zlib" }
    }
    # detect gzip 1F 8B 08
    if ($b0 -eq 0x1F -and $b1 -eq 0x8B -and $buf[$i+2] -eq 0x08) {
      $hits += [pscustomobject]@{ Offset=$i; Kind="gzip" }
    }
  }
  return $hits
}

$files = Get-ChildItem -Path $BinsDir -Filter *.bin | Sort-Object Name
foreach ($f in $files) {
  $buf = Read-AllBytes $f.FullName
  $hits = Scan-Compressed $buf
  if ($hits.Count -eq 0) { continue }
  $dir = Join-Path $OutDir $f.Name
  New-Item -ItemType Directory -Force -Path $dir | Out-Null

  $idx = 0
  foreach ($h in $hits) {
    $idx++
    $bytes = $null
    if ($h.Kind -eq "zlib") { $bytes = Try-Inflate-Zlib $buf $h.Offset }
    elseif ($h.Kind -eq "gzip") { $bytes = Try-Inflate-Gzip $buf $h.Offset }

    if ($bytes -ne $null -and $bytes.Length -gt 0) {
      $outRaw = Join-Path $dir ("{0}_{1:D4}.bin" -f $h.Kind,$idx)
      [System.IO.File]::WriteAllBytes($outRaw, $bytes)

      # attempt to write as text if it looks texty
      $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
      if ($txt -match '[\x09\x0A\x0D\x20-\x7E]{8,}') {
        $outTxt = Join-Path $dir ("{0}_{1:D4}.txt" -f $h.Kind,$idx)
        $txt | Out-File -FilePath $outTxt -Encoding utf8
      }
    }
  }
}
Write-Host "[done] compressed scan results in $OutDir\<bin>\ (zlib_####.txt/gzip_####.txt if decodable)"