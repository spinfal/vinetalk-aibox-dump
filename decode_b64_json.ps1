param(
  [string]$InDir = "out2",   # per-bin folders created by strings_hardcore.ps1
  [string]$OutSub = "decoded_json"
)
$ErrorActionPreference = "Stop"
$targets = Get-ChildItem -Path $InDir -Directory
foreach ($d in $targets) {
  $b64Path = Join-Path $d.FullName "base64_candidates.txt"
  if (-not (Test-Path $b64Path)) { continue }
  $outDir = Join-Path $d.FullName $OutSub
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null

  $i=0
  Get-Content $b64Path | ForEach-Object {
    $line = $_.Trim()
    if ($line.Length -lt 16) { return }
    try {
      $bytes = [Convert]::FromBase64String($line)
      $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
      if ($txt.Trim().StartsWith("{") -or $txt.Trim().StartsWith("[")) {
        # try parse json
        try {
          $null = $txt | ConvertFrom-Json -ErrorAction Stop
          $i++
          $out = Join-Path $outDir ("b64_json_{0:D3}.json" -f $i)
          $txt | Out-File -FilePath $out -Encoding utf8
        } catch {
          # not valid strict json; still save as text
          $i++
          $out = Join-Path $outDir ("b64_text_{0:D3}.txt" -f $i)
          $txt | Out-File -FilePath $out -Encoding utf8
        }
      }
    } catch {}
  }
}
Write-Host "[done] checked base64 candidates and saved any JSON-like payloads under each bin folder."