# requires: strings.exe (sysinternals). esptool.exe/espefuse.exe optional.
$ErrorActionPreference = "Stop"

# base paths
$root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Set-Location $root

# bins
$binsDir = Join-Path $root "bins"
$wanted = @(
  "bootloader.bin","partitions.bin","nvs.bin","phy_init.bin","otadata.bin",
  "storage.bin","ota_0.bin","ota_1.bin","app0.bin","dump.bin"
)

# output structure
$out = Join-Path $root "out"
$meta = Join-Path $out "meta"
$stringsRawAscii = Join-Path $out "strings/raw/ascii_offsets"
$stringsRawUni   = Join-Path $out "strings/raw/unicode_offsets"
$stringsComb     = Join-Path $out "strings/combined"
$hitsRoot        = Join-Path $out "strings/hits"
$agg             = Join-Path $out "aggregate"
$imgInfo         = Join-Path $meta "image_info"
$hashDir         = Join-Path $meta "hashes"
$logDir          = Join-Path $meta "logs"

$hitDirs = @("urls","ws_urls","domains","emails","ipv4","ipv6","mac","mqtt","jwt","aws","creds_lines","creds_kv","pem","base64","json")

# create folders
$allDirs = @($out,$meta,$stringsRawAscii,$stringsRawUni,$stringsComb,$hitsRoot,$agg,$imgInfo,$hashDir,$logDir) + ($hitDirs | ForEach-Object { Join-Path $hitsRoot $_ })
$allDirs | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }

# find strings.exe
function Find-Strings {
  $candidates = @(
    (Join-Path $root "strings.exe"),
    (Join-Path $root "STRING_EXE\\strings64.exe"),
    (Join-Path $root "STRING_EXE\\strings.exe"),
    "strings.exe"
  )
  foreach ($c in $candidates) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    if (Test-Path $c) { return (Resolve-Path $c).Path }
  }
  throw "strings.exe not found. put Sysinternals strings.exe next to this script or in PATH."
}
$StringsExe = Find-Strings

# collect bins
$bins = @()
foreach ($name in $wanted) {
  $p = Join-Path $binsDir $name
  if (Test-Path $p) { $bins += (Get-Item $p) } else { Write-Warning "missing: $name" }
}
if ($bins.Count -eq 0) {
  $bins = Get-ChildItem -Path $binsDir -Filter *.bin
}

# helper: write sorted unique lines
function Write-Unique {
  param([string[]]$Lines,[string]$Path)
  $Lines | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Sort-Object -Unique | Out-File -FilePath $Path -Encoding ascii
}

# helper: dump ascii+unicode strings with/without offsets
function Dump-Strings {
  param([string]$BinPath,[string]$BaseName)
  $asciiOff = Join-Path $stringsRawAscii "$BaseName.txt"
  $uniOff   = Join-Path $stringsRawUni "$BaseName.txt"
  $comb     = Join-Path $stringsComb "$BaseName.txt"
  & $StringsExe -accepteula -nobanner -n 4 -o -a $BinPath > $asciiOff
  & $StringsExe -accepteula -nobanner -n 4 -o -u $BinPath > $uniOff
  $a = & $StringsExe -accepteula -nobanner -n 4 -a $BinPath
  $u = & $StringsExe -accepteula -nobanner -n 4 -u $BinPath
  Write-Unique ($a + $u) $comb
  return $comb
}

# regexes
$reUrl   = 'https?://[^\s""''<>(){}\\]+'
$reWsUrl = 'wss?://[^\s""''<>(){}\\]+'
$reEmail = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
$reIPv4  = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
$reIPv6  = '(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b'
$reMAC   = '(?i)\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b'
$reMQTT  = '(?i)\b(?:mqtt|wss|ws|broker|topic|clientid|subscribe|publish)\b'
$reJWT   = '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
$reAWS   = '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'
$reCredLine = '(?i)\b(?:token|access[_-]?token|refresh[_-]?token|auth|authorization|apikey|api[_-]?key|secret|client[_-]?id|client[_-]?secret|bearer)\b'
$reCredKV1 = '(?i)""?(token|access[_-]?token|refresh[_-]?token|auth|authorization|apikey|api[_-]?key|client[_-]?id|client[_-]?secret|secret)""?\s*[:=]\s*""?([A-Za-z0-9._\-:/+=]{6,})""?'
$reBase64 = '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])'
$reJSONish = '^\s*[{[].*[}\]]\s*$'

# pem extraction
function Extract-PEM {
  param([string]$BinPath,[string]$OutPath)
  $bytes = [System.IO.File]::ReadAllBytes($BinPath)
  $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
  $m = [System.Text.RegularExpressions.Regex]::Matches($text, '-----BEGIN [^-]+-----.*?-----END [^-]+-----', 'Singleline')
  if ($m.Count -gt 0) {
    ($m | ForEach-Object { $_.Value }) | Out-File -FilePath $OutPath -Encoding ascii
  } else {
    New-Item -ItemType File -Path $OutPath -Force | Out-Null
  }
}

# aggregates
$aggUrls=@();$aggWs=@();$aggDomains=@();$aggEmails=@();$aggIPv4=@();$aggIPv6=@();$aggMAC=@();$aggMQTT=@();$aggJWT=@();$aggAWS=@();$aggCredLines=@();$aggCredKV=@();$aggPEM=@();$aggB64=@();$aggJSON=@()

# per bin processing
foreach ($b in $bins) {
  $base = $b.Name
  $comb = Dump-Strings -BinPath $b.FullName -BaseName $base

  $urls = Select-String -Path $comb -Pattern $reUrl -AllMatches | ForEach-Object { $_.Matches.Value }
  $ws   = Select-String -Path $comb -Pattern $reWsUrl -AllMatches | ForEach-Object { $_.Matches.Value }
  $emails = Select-String -Path $comb -Pattern $reEmail -AllMatches | ForEach-Object { $_.Matches.Value }
  $ipv4 = Select-String -Path $comb -Pattern $reIPv4 -AllMatches | ForEach-Object { $_.Matches.Value }
  $ipv6 = Select-String -Path $comb -Pattern $reIPv6 -AllMatches | ForEach-Object { $_.Matches.Value }
  $macs = Select-String -Path $comb -Pattern $reMAC -AllMatches | ForEach-Object { $_.Matches.Value }
  $mqtt = Select-String -Path $comb -Pattern $reMQTT -AllMatches | ForEach-Object { $_.Matches.Value }
  $jwt  = Select-String -Path $comb -Pattern $reJWT -AllMatches | ForEach-Object { $_.Matches.Value }
  $aws  = Select-String -Path $comb -Pattern $reAWS -AllMatches | ForEach-Object { $_.Matches.Value }
  $credL= Select-String -Path $comb -Pattern $reCredLine -AllMatches | ForEach-Object { $_.Line }
  $credKV= Select-String -Path $comb -Pattern $reCredKV1 -AllMatches | ForEach-Object { 
    $k=$_.Matches.Groups[1].Value
    $v=$_.Matches.Groups[2].Value
    "$k,$v"
  }
  $b64  = Select-String -Path $comb -Pattern $reBase64 -AllMatches | ForEach-Object { $_.Matches.Value }
  $json = Get-Content $comb | Where-Object { $_ -match $reJSONish }

  Write-Unique $urls (Join-Path (Join-Path $hitsRoot "urls") "$base.txt")
  Write-Unique $ws   (Join-Path (Join-Path $hitsRoot "ws_urls") "$base.txt")
  Write-Unique ($urls + $ws) (Join-Path (Join-Path $hitsRoot "urls") "$base.all_http_ws.txt")
  Write-Unique ($emails) (Join-Path (Join-Path $hitsRoot "emails") "$base.txt")
  Write-Unique ($ipv4) (Join-Path (Join-Path $hitsRoot "ipv4") "$base.txt")
  Write-Unique ($ipv6) (Join-Path (Join-Path $hitsRoot "ipv6") "$base.txt")
  Write-Unique ($macs) (Join-Path (Join-Path $hitsRoot "mac") "$base.txt")
  Write-Unique ($mqtt) (Join-Path (Join-Path $hitsRoot "mqtt") "$base.txt")
  Write-Unique ($jwt)  (Join-Path (Join-Path $hitsRoot "jwt") "$base.txt")
  Write-Unique ($aws)  (Join-Path (Join-Path $hitsRoot "aws") "$base.txt")
  Write-Unique ($credL) (Join-Path (Join-Path $hitsRoot "creds_lines") "$base.txt")
  if ($credKV.Count -gt 0) { "key,value" | Out-File -FilePath (Join-Path (Join-Path $hitsRoot "creds_kv") "$base.csv") -Encoding ascii; Write-Unique $credKV (Join-Path (Join-Path $hitsRoot "creds_kv") "$base.csv") }
  Write-Unique ($b64) (Join-Path (Join-Path $hitsRoot "base64") "$base.txt")
  Write-Unique ($json) (Join-Path (Join-Path $hitsRoot "json") "$base.txt")

  $pemOut = Join-Path (Join-Path $hitsRoot "pem") "$base.pem.txt"
  Extract-PEM -BinPath $b.FullName -OutPath $pemOut

  $aggUrls += $urls
  $aggWs   += $ws
  $aggEmails += $emails
  $aggIPv4 += $ipv4
  $aggIPv6 += $ipv6
  $aggMAC  += $macs
  $aggMQTT += $mqtt
  $aggJWT  += $jwt
  $aggAWS  += $aws
  $aggCredLines += $credL
  $aggCredKV += $credKV
  $aggPEM += (Get-Content $pemOut)
  $aggB64 += $b64
  $aggJSON += $json
}

# domains from urls
$domains = @()
foreach ($u in ($aggUrls + $aggWs)) {
  if ($u -match '^\w+://([^/:\s]+)') { $domains += $matches[1].ToLower() }
}

# write aggregates
Write-Unique $aggUrls (Join-Path $agg "all.urls.txt")
Write-Unique $aggWs (Join-Path $agg "all.ws_urls.txt")
Write-Unique $domains (Join-Path $agg "all.domains.txt")
Write-Unique $aggEmails (Join-Path $agg "all.emails.txt")
Write-Unique $aggIPv4 (Join-Path $agg "all.ipv4.txt")
Write-Unique $aggIPv6 (Join-Path $agg "all.ipv6.txt")
Write-Unique $aggMAC (Join-Path $agg "all.mac.txt")
Write-Unique $aggMQTT (Join-Path $agg "all.mqtt.txt")
Write-Unique $aggJWT (Join-Path $agg "all.jwt.txt")
Write-Unique $aggAWS (Join-Path $agg "all.aws_access_keys.txt")
Write-Unique $aggCredLines (Join-Path $agg "all.creds_lines.txt")
if ($aggCredKV.Count -gt 0) { "key,value" | Out-File -FilePath (Join-Path $agg "all.creds_kv.csv") -Encoding ascii; Write-Unique $aggCredKV (Join-Path $agg "all.creds_kv.csv") }
Write-Unique $aggPEM (Join-Path $agg "all.pem.txt")
Write-Unique $aggB64 (Join-Path $agg "all.base64.txt")
Write-Unique $aggJSON (Join-Path $agg "all.json.txt")

# meta: hashes and image_info, partition csv
$shaOut = Join-Path $hashDir "sha256.csv"
"file,sha256" | Out-File -FilePath $shaOut -Encoding ascii
foreach ($b in $bins) {
  $hash = (certutil -hashfile $b.FullName SHA256 | Select-Object -Skip 1 | Select-Object -First 1).Trim()
  "$($b.Name),$hash" | Out-File -FilePath $shaOut -Append -Encoding ascii
}

# esptool image_info if present
$esptool = Get-Command "esptool.exe" -ErrorAction SilentlyContinue
if ($esptool) {
  foreach ($n in @("ota_0.bin","ota_1.bin","app0.bin")) {
    $p = Join-Path $binsDir $n
    if (Test-Path $p) {
      & $esptool.Source image_info $p > (Join-Path $imgInfo "$n.image_info.txt")
    }
  }
}

# partitions.csv from partitions.bin if present
$partBin = Join-Path $binsDir "partitions.bin"
if (Test-Path $partBin) {
  $bytes = [System.IO.File]::ReadAllBytes($partBin)
  $rows = @()
  for ($i=0; $i -le $bytes.Length-32; $i+=32) {
    $magic = [BitConverter]::ToUInt16($bytes,$i)
    if ($magic -ne 0x50AA) { continue }
    $type    = $bytes[$i+2]
    $subtype = $bytes[$i+3]
    $offset  = [BitConverter]::ToUInt32($bytes,$i+4)
    $size    = [BitConverter]::ToUInt32($bytes,$i+8)
    $labelBytes = $bytes[($i+12)..($i+27)]
    $label = ([System.Text.Encoding]::ASCII.GetString($labelBytes)).Split([char]0)[0]
    $flags  = [BitConverter]::ToUInt32($bytes,$i+28)
    if ([string]::IsNullOrWhiteSpace($label)) { continue }
    $rows += [pscustomobject]@{
      name   = $label
      type   = $type
      subtype= $subtype
      offset = ("0x{0:x6}" -f $offset)
      size   = ("0x{0:x6}" -f $size)
      flags  = ("0x{0:x8}" -f $flags)
      index  = [int]($i/32)
    }
  }
  $csv = Join-Path $root "partitions.csv"
  "name,type,subtype,offset,size,flags,index" | Out-File -FilePath $csv -Encoding ascii
  foreach ($r in $rows) {
    "$($r.name),$($r.type),$($r.subtype),$($r.offset),$($r.size),$($r.flags),$($r.index)" | Out-File -FilePath $csv -Append -Encoding ascii
  }
}

# report
$report = @()
$report += "# analysis report"
$report += ""
$report += "date: $(Get-Date -Format s)"
$report += "bins dir: $binsDir"
$report += ""
$report += "## file counts"
$report += "- bins processed: $($bins.Count)"
$report += "- urls: $((Get-Content (Join-Path $agg 'all.urls.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- ws urls: $((Get-Content (Join-Path $agg 'all.ws_urls.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- domains: $((Get-Content (Join-Path $agg 'all.domains.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- emails: $((Get-Content (Join-Path $agg 'all.emails.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- ipv4: $((Get-Content (Join-Path $agg 'all.ipv4.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- ipv6: $((Get-Content (Join-Path $agg 'all.ipv6.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- mac: $((Get-Content (Join-Path $agg 'all.mac.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- mqtt hits: $((Get-Content (Join-Path $agg 'all.mqtt.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- jwt tokens: $((Get-Content (Join-Path $agg 'all.jwt.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- aws access keys: $((Get-Content (Join-Path $agg 'all.aws_access_keys.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- credential lines: $((Get-Content (Join-Path $agg 'all.creds_lines.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- credential kv rows: $((Get-Content (Join-Path $agg 'all.creds_kv.csv') -ErrorAction SilentlyContinue).Count)"
$report += "- pem blocks: $((Get-Content (Join-Path $agg 'all.pem.txt') -ErrorAction SilentlyContinue).Count)"
$report += "- base64 blobs: $((Get-Content (Join-Path $agg 'all.base64.txt') -ErrorAction SilentlyContinue).Count)"
$report += ""
$report += "## notes"
$report += "- redact secrets/mac/ssid before publishing."
$report += "- raw strings with offsets are in out/strings/raw."

$reportPath = Join-Path $out "REPORT.md"
$report -join "`r`n" | Out-File -FilePath $reportPath -Encoding utf8

Write-Host "[done] outputs in '$out'."
