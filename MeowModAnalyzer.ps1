param(
    [string]$WorkerMode = '',
    [string]$WorkerList = '',
    [string]$WorkerOut  = ''
)

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { [Console]::InputEncoding  = [System.Text.Encoding]::UTF8 } catch { }
$OutputEncoding           = [System.Text.Encoding]::UTF8

# Workers run this same file with -WorkerMode; skip all of the interactive UI.
if (-not $WorkerMode) {
chcp 65001 | Out-Null
Clear-Host

$currentFont = (Get-ItemProperty "HKCU:\Console" -ErrorAction SilentlyContinue).FaceName
if ($currentFont -notmatch "NSimSun|Gothic|Noto") {
    Write-Host "  Tip: To see all Unicode characters, set the terminal font to 'NSimSun'" -ForegroundColor DarkYellow
    Write-Host
}

$Banner = @"

  ███╗   ███╗███████╗ ██████╗ ██╗    ██╗  ███╗   ███╗ ██████╗ ██████╗
  ████╗ ████║██╔════╝██╔═══██╗██║    ██║  ████╗ ████║██╔═══██╗██╔══██╗
  ██╔████╔██║█████╗  ██║   ██║██║ █╗ ██║  ██╔████╔██║██║   ██║██║  ██║
  ██║╚██╔╝██║██╔══╝  ██║   ██║██║███╗██║  ██║╚██╔╝██║██║   ██║██║  ██║
  ██║ ╚═╝ ██║███████╗╚██████╔╝╚███╔███╔╝  ██║ ╚═╝ ██║╚██████╔╝██████╔╝
  ╚═╝     ╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝   ╚═╝     ╚═╝ ╚═════╝ ╚═════╝

   █████╗ ███╗   ██╗ █████╗ ██╗   ██╗   ██╗███████╗███████╗██████╗
  ██╔══██╗████╗  ██║██╔══██╗██║   ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
  ███████║██╔██╗ ██║███████║██║    ╚████╔╝   ███╔╝ █████╗  ██████╔╝
  ██╔══██║██║╚██╗██║██╔══██║██║     ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
  ██║  ██║██║ ╚████║██║  ██║███████╗ ██║   ███████╗███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝

                         \    /\
                          )  ( ')
                         (  /  )
                          \(__)|

"@

Write-Host $Banner -ForegroundColor Cyan
Write-Host ""
Write-Host "                Made with " -ForegroundColor Gray -NoNewline
Write-Host "♥ " -ForegroundColor Red -NoNewline
Write-Host "by " -ForegroundColor Gray -NoNewline
Write-Host "MeowTonynoh" -ForegroundColor Cyan
Write-Host ""
Write-Host ("━" * 76) -ForegroundColor DarkCyan
Write-Host
}

# ---------------------------------------------------------------------------
# Scan-scope helpers
# ---------------------------------------------------------------------------
$script:SkipDirNames = @(
    '.git','.svn','.hg','node_modules','__pycache__','.cache','.gradle','.m2','loom-cache',
    'proc','sys','dev','run','usr','lib','lib32','lib64','bin','sbin','etc','boot','var','nix','snap',
    'libraries','versions','runtime','jre','jdk','processedMods','assets','natives',
    'System Volume Information','Windows','Program Files','Program Files (x86)',
    'ProgramData','Windows.old','Recovery','PerfLogs'
)

$script:ArchiveTemp = $null
if (-not $WorkerMode) {
    $script:ArchiveTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("meowmodanalyzer-archives-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:ArchiveTemp | Out-Null
}
$script:JarOrigin = @{}
$script:HashPrimary = @{}
$script:PathDupes = @{}
$script:DuplicateJars = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:DuplicateCount = 0

function Remove-ArchiveTemp {
    if ($script:ArchiveTemp -and (Test-Path -LiteralPath $script:ArchiveTemp)) {
        Remove-Item -LiteralPath $script:ArchiveTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-NormPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    try { return [System.IO.Path]::GetFullPath($Path).TrimEnd('\','/') }
    catch { return $Path.TrimEnd('\','/') }
}

function Test-IsSystemDir {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = Get-NormPath $Path
    $homeDir = ''
    if ($env:USERPROFILE) { $homeDir = Get-NormPath $env:USERPROFILE }
    elseif ($env:HOME)   { $homeDir = Get-NormPath $env:HOME }
    if ($homeDir -and $p -ieq $homeDir) { return $true }
    if ($p -eq '' -or $p -eq '/' -or $p -match '^[A-Za-z]:$') { return $true }

    $roots = @()
    foreach ($v in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
                     '/bin','/sbin','/usr','/usr/bin','/usr/sbin','/usr/local','/usr/lib','/lib','/lib64',
                     '/etc','/var','/opt','/boot','/run','/proc','/sys','/dev','/snap','/nix',
                     '/System','/Library','/Applications','/private')) {
        if ($v) {
            $n = Get-NormPath $v
            if ($n) { $roots += $n }
        }
    }
    $sep = [System.IO.Path]::DirectorySeparatorChar
    foreach ($r in $roots) {
        if ($p -ieq $r) { return $true }
        if ($p.StartsWith($r + $sep, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-DefaultMinecraftMods {
    if ($env:APPDATA) { return (Join-Path $env:APPDATA '.minecraft\mods') }
    $homeDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }
    if ($homeDir) { return (Join-Path (Join-Path $homeDir '.minecraft') 'mods') }
    return '.minecraft\mods'
}

function Get-DefaultCustomPath {
    $pwdPath = (Get-Location).Path
    if ($pwdPath -and -not (Test-IsSystemDir $pwdPath)) { return $pwdPath }
    return (Get-DefaultMinecraftMods)
}

function Test-SkipJarPath {
    param([string]$Path)
    $p = $Path -replace '/','\'
    $lp = $p.ToLowerInvariant()
    if ($lp -match '(^|\\)\.fabric\\processedmods(\\|$)') { return $true }
    if ($lp -match '\\(libraries|versions|runtime|jre|jdk|\.gradle|\.m2|loom-cache)\\') { return $true }

    $name = [System.IO.Path]::GetFileName($p).ToLowerInvariant()
    foreach ($pat in @('minecraft*.jar','forge-*.jar','neoforge-*.jar','fabric-loader*.jar','quilt-loader*.jar',
                       'authlib*.jar','brigadier*.jar','datafixerupper*.jar','log4j*.jar','netty*.jar','guava*.jar',
                       'gson*.jar','asm-*.jar','jopt-simple*.jar','commons-*.jar','slf4j*.jar','lwjgl*.jar',
                       'jna*.jar','joml*.jar','oshi*.jar','text2speech*.jar',
                       'gradle-wrapper*.jar','remapped.*.jar','remapped-*.jar')) {
        if ($name -like $pat) { return $true }
    }
    return $false
}

function Add-JarFile {
    param([string]$Path, [string]$Origin)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    if (Test-SkipJarPath $Path) { return }
    try { $full = (Resolve-Path -LiteralPath $Path).Path } catch { return }
    if (-not $script:JarSeen.Add($full)) { return }
    if ($Origin) { $script:JarOrigin[$full] = $Origin }
    [void]$script:JarFiles.Add([PSCustomObject]@{
        FullName = $full
        Name     = [System.IO.Path]::GetFileName($full)
    })
}

function Get-FullDisplay {
    param([string]$Path, [string]$Name)
    if ($Path -and $script:JarOrigin.ContainsKey($Path)) {
        return ("{0} → {1}" -f $script:JarOrigin[$Path], $Name)
    }
    if ($Path) { return $Path }
    return $Name
}

function Get-ModDisplay {
    param([string]$Path, [string]$Name)
    if ($script:scanMode -eq 'system' -or $script:scanMode -eq 'launchers') {
        return (Get-FullDisplay -Path $Path -Name $Name)
    }
    return $Name
}

function Get-ExtraPaths {
    param([string]$Path)
    if (-not $Path) { return @() }
    if ($script:PathDupes.ContainsKey($Path)) { return $script:PathDupes[$Path] }
    return @()
}

function Get-FullDisplayForPath {
    param([string]$Path)
    if (-not $Path) { return '' }
    return (Get-FullDisplay -Path $Path -Name ([System.IO.Path]::GetFileName($Path)))
}

function Write-ExtraPaths {
    param(
        [string]$Path,
        [string]$Prefix = '  │    ',
        [ConsoleColor]$Color = 'DarkGray'
    )
    foreach ($extra in (Get-ExtraPaths -Path $Path)) {
        Write-Host ($Prefix + "↳ ") -ForegroundColor $Color -NoNewline
        Write-Host (Get-FullDisplayForPath -Path $extra) -ForegroundColor $Color
    }
}

function Get-ModsDirJars {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return }
    Get-ChildItem -LiteralPath $Dir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -ieq '.jar' } |
        ForEach-Object { Add-JarFile $_.FullName }
}

function Get-LauncherModDirs {
    $dirs  = New-Object System.Collections.ArrayList
    $bases = New-Object System.Collections.ArrayList
    $lunar = New-Object System.Collections.ArrayList

    [void]$dirs.Add((Get-DefaultMinecraftMods))

    if ($env:APPDATA) {
        [void]$bases.Add((Join-Path $env:APPDATA 'PrismLauncher\instances'))
    }
    $homeDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }
    if ($homeDir) {
        [void]$bases.Add((Join-Path $homeDir '.local/share/PrismLauncher/instances'))
        [void]$bases.Add((Join-Path $homeDir '.var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher/instances'))
        [void]$bases.Add((Join-Path $homeDir 'Library/Application Support/PrismLauncher/instances'))
        [void]$lunar.Add((Join-Path $homeDir '.lunarclient'))
        [void]$lunar.Add((Join-Path $homeDir 'Library/Application Support/lunarclient'))
    }

    foreach ($base in $bases) {
        if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
        Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$dirs.Add((Join-Path (Join-Path $_.FullName 'minecraft') 'mods'))
            [void]$dirs.Add((Join-Path (Join-Path $_.FullName '.minecraft') 'mods'))
        }
    }

    foreach ($root in $lunar) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        Get-ChildItem -LiteralPath $root -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ieq 'mods' } |
            ForEach-Object { [void]$dirs.Add($_.FullName) }
    }

    return ($dirs | Select-Object -Unique)
}

function Get-SystemRoots {
    $roots = New-Object System.Collections.ArrayList
    try {
        foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
            if ($drive.DriveType -eq [System.IO.DriveType]::Fixed -and $drive.IsReady) {
                [void]$roots.Add($drive.RootDirectory.FullName)
            }
        }
    } catch { }
    if ($roots.Count -eq 0) {
        if ($env:SystemDrive) { [void]$roots.Add($env:SystemDrive + '\') }
        else { [void]$roots.Add('/') }
    }
    return $roots
}

function Test-SkipArchiveEntry {
    param([string]$Entry)
    $e = ($Entry -replace '/','\').ToLowerInvariant()
    if ($e -match '(^|\\)(libraries|versions|runtime|jre|jdk|loom-cache)(\\|$)') { return $true }
    if ($e -match '(^|\\)\.fabric\\processedmods(\\|$)') { return $true }
    return $false
}

function Expand-ArchiveJars {
    param([string]$Archive, [int]$Index)

    $dest = Join-Path $script:ArchiveTemp ("a{0}" -f $Index)
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    $fileName = [System.IO.Path]::GetFileName($Archive).ToLowerInvariant()
    $ext      = [System.IO.Path]::GetExtension($Archive).ToLowerInvariant()

    if ($ext -eq '.zip' -or $ext -eq '.mcpack') {
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
            try {
                foreach ($entry in $zip.Entries) {
                    if ($entry.FullName -notmatch '(?i)\.jar$') { continue }
                    if (Test-SkipArchiveEntry $entry.FullName) { continue }
                    $base = [System.IO.Path]::GetFileName($entry.FullName)
                    if (-not $base) { continue }
                    try {
                        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $dest $base), $true)
                    } catch { }
                }
            } finally { $zip.Dispose() }
        } catch { }
    }
    elseif ($fileName -like '*.tar.gz' -or $fileName -like '*.tgz' -or $ext -eq '.tar') {
        $tar = Get-Command tar -ErrorAction SilentlyContinue
        if ($tar) {
            & $tar.Source -xf $Archive -C $dest '*.jar' '*.JAR' 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                & $tar.Source -xf $Archive -C $dest '*.jar' 2>$null | Out-Null
            }
        }
    }
    elseif ($ext -eq '.rar' -or $ext -eq '.7z') {
        $seven = Get-Command 7z -ErrorAction SilentlyContinue
        if (-not $seven) { $seven = Get-Command 7za -ErrorAction SilentlyContinue }
        if ($seven) {
            & $seven.Source x -y ("-o{0}" -f $dest) $Archive '*.jar' 2>$null | Out-Null
        }
        elseif ($ext -eq '.rar') {
            $unrar = Get-Command unrar -ErrorAction SilentlyContinue
            if ($unrar) {
                & $unrar.Source x -o+ -inul $Archive '*.jar' ($dest + [System.IO.Path]::DirectorySeparatorChar) 2>$null | Out-Null
            } else {
                $bsdtar = Get-Command bsdtar -ErrorAction SilentlyContinue
                if ($bsdtar) { & $bsdtar.Source -xf $Archive -C $dest '*.jar' 2>$null | Out-Null }
            }
        }
    }

    Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -ieq '.jar' } |
        ForEach-Object { Add-JarFile -Path $_.FullName -Origin $Archive }
}

function Add-SystemJars {
    $archives = New-Object System.Collections.ArrayList
    $systemPaths = @('/System','/private','/Applications','/cores','/tmp')

    foreach ($root in (Get-SystemRoots)) {
        Write-Host "   searching: $root" -ForegroundColor Gray
        $stack = New-Object System.Collections.Stack
        $stack.Push($root)

        while ($stack.Count -gt 0) {
            $dir = [string]$stack.Pop()

            try {
                foreach ($file in [System.IO.Directory]::EnumerateFiles($dir)) {
                    $ext  = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
                    $name = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
                    if ($ext -eq '.jar') {
                        Add-JarFile $file
                    }
                    elseif ($ext -eq '.zip' -or $ext -eq '.mcpack' -or $ext -eq '.rar' -or
                            $ext -eq '.7z' -or $ext -eq '.tar' -or $ext -eq '.tgz' -or
                            $name -like '*.tar.gz') {
                        [void]$archives.Add($file)
                    }
                }
            } catch { }

            try {
                foreach ($sub in [System.IO.Directory]::EnumerateDirectories($dir)) {
                    $subName = [System.IO.Path]::GetFileName($sub)
                    if ($script:SkipDirNames -contains $subName) { continue }
                    if ($systemPaths -contains $sub) { continue }
                    if ($sub -ieq $script:ArchiveTemp) { continue }
                    try {
                        if (([System.IO.File]::GetAttributes($sub) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    } catch { continue }
                    [void]$stack.Push($sub)
                }
            } catch { }
        }
    }

    Write-Host "   archives found: $($archives.Count)" -ForegroundColor Gray
    $i = 0
    foreach ($archive in $archives) {
        $i++
        Expand-ArchiveJars -Archive $archive -Index $i
    }
}

if (-not $WorkerMode) {
Write-Host "Select scan scope:" -ForegroundColor White
Write-Host "  1) " -ForegroundColor Cyan -NoNewline
Write-Host "Whole system (jars + .zip/.tar.gz/.rar/.mcpack archives + recycle bin)" -ForegroundColor DarkGray
Write-Host "  2) " -ForegroundColor Cyan -NoNewline
Write-Host "Launchers only (PrismLauncher + Lunar + .minecraft)" -ForegroundColor DarkGray
$defPath = Get-DefaultCustomPath
Write-Host "  3) " -ForegroundColor Cyan -NoNewline
Write-Host "Custom folder " -ForegroundColor DarkGray -NoNewline
Write-Host "(default: $defPath)" -ForegroundColor DarkGray
Write-Host "Choice " -ForegroundColor DarkGray -NoNewline
Write-Host "[3]" -ForegroundColor DarkGray -NoNewline
Write-Host ": " -NoNewline
$scanChoice = Read-Host
if ([string]::IsNullOrWhiteSpace($scanChoice)) { $scanChoice = '3' }
while (@('1','2','3') -notcontains $scanChoice) {
    Write-Host "Please enter 1, 2 or 3: " -ForegroundColor Yellow -NoNewline
    $scanChoice = Read-Host
    if ([string]::IsNullOrWhiteSpace($scanChoice)) { $scanChoice = '3' }
}
Write-Host

$modsPath = $null
switch ($scanChoice) {
    '1' { $scanMode = 'system' }
    '2' { $scanMode = 'launchers' }
    '3' {
        $scanMode = 'custom'
        Write-Host "Enter path to the mods folder: " -NoNewline
        Write-Host "(press Enter to use default)" -ForegroundColor DarkGray
        Write-Host "PATH [$defPath]: " -NoNewline
        $modsPath = Read-Host
        Write-Host
        if (-not [string]::IsNullOrWhiteSpace($modsPath)) {
            $modsPath = $modsPath.Trim().Trim([char[]]@('"', "'"))
        }
        if ([string]::IsNullOrWhiteSpace($modsPath)) {
            $modsPath = $defPath
            Write-Host "Continuing with " -NoNewline
            Write-Host $modsPath -ForegroundColor White
            Write-Host
        }
        if (-not (Test-Path -LiteralPath $modsPath -PathType Container)) {
            Write-Host "❌ Invalid Path!" -ForegroundColor Red
            Write-Host "The directory does not exist or is not accessible." -ForegroundColor Yellow
            Write-Host
            Write-Host "Tried to access: $modsPath" -ForegroundColor Gray
            Write-Host
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
    }
}

switch ($scanMode) {
    'system'    {
        Write-Host "📁 Scan scope: whole system (recycle bin included)" -ForegroundColor Green
        Write-Host "⚠️  Whole-system scans can take a long time (archive extraction + network lookups)." -ForegroundColor Yellow
        Write-Host
        $scanWhere = 'the whole system'
    }
    'launchers' {
        Write-Host "📁 Scan scope: PrismLauncher / Lunar / .minecraft" -ForegroundColor Green
        $scanWhere = 'the launcher mod folders'
    }
    'custom'    {
        Write-Host "📁 Scanning directory: $modsPath" -ForegroundColor Green
        $scanWhere = $modsPath
    }
}
Write-Host

# ---------------------------------------------------------------------------
# Scan threads
# ---------------------------------------------------------------------------
$defaultThreads = if ($scanMode -eq 'custom') { 1 } else { 4 }
$threads = $defaultThreads
while ($true) {
    Write-Host "Threads for scanning" -ForegroundColor DarkGray -NoNewline
    Write-Host "(1-64) [$defaultThreads]: " -ForegroundColor DarkGray -NoNewline
    $threadInput = Read-Host
    if ([string]::IsNullOrWhiteSpace($threadInput)) { break }
    $parsedThreads = 0
    if ([int]::TryParse($threadInput.Trim(), [ref]$parsedThreads) -and $parsedThreads -ge 1 -and $parsedThreads -le 64) {
        $threads = $parsedThreads
        break
    }
    Write-Host "Please enter a number between 1 and 64." -ForegroundColor Yellow
}
Write-Host

$mcProcess = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $mcProcess) {
    $mcProcess = Get-Process java -ErrorAction SilentlyContinue
}

if ($mcProcess) {
    try {
        $startTime = $mcProcess.StartTime
        $uptime = (Get-Date) - $startTime
        Write-Host "🕒 { Minecraft Uptime }" -ForegroundColor DarkCyan
        Write-Host "   $($mcProcess.Name) PID $($mcProcess.Id) started at $startTime" -ForegroundColor Gray
        Write-Host "   Running for: $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" -ForegroundColor Gray
        Write-Host ""
    } catch { }
}
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$suspiciousPatterns = @(
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand", "JDWP.VirtualMachine.AllModules",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "LegitTotem", "PingSpoof", "SelfDestruct",
    "ShieldBreaker", "TriggerBot", "AxeSpam", "WebMacro",
    "FastPlace", "WalskyOptimizer", "WalksyOptimizer", "walsky.optimizer",
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod",
    "ShieldDisabler", "SilentAim", "Totem Hit", "Wtap", "FakeLag", "dev.virel", "orchard",
    "BlockESP", "dev.krypton", "dev/krypton", "skid.krypton", "skid/krypton",  "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "AntiBot",
    "ElytraSwap", "FastXP", "FastExp", "Refill",  "AirAnchor",
    "jnativehook", "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework",
    "PackSpoof", "Antiknockback", "catlean",
    "AuthBypass", "Asteria", "Prestige", "AutoEat", "AutoMine",
    "MaceSwap",  "Macro198", "StunSlam", "SafeAnchor", "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy",
    "AutoPotRefill", "WalksyOptimizer", "KeyPearl", "AimAssist", "AutoNethPot", "AutoDtap",
    "TriggerBot", "AutoWeb", "AnchorAction",

    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui.gl3", "imgui.glfw",
    "BowAim", "Criticals", "Fakenick", "FakeItem",
    "invsee", "ItemExploit", "Hellion", "hellion",
    "LicenseCheckMixin", "ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim", "dev.gambleclient", "obfuscatedAuth",
    "phantom-refmap.json", "xyz.greaj",
    "じ.class", "ふ.class", "ぶ.class", "ぷ.class", "た.class",
    "ね.class", "そ.class", "な.class", "ど.class", "ぐ.class",
    "ず.class", "で.class", "つ.class", "べ.class", "せ.class",
    "と.class", "み.class", "び.class", "す.class", "の.class"
)

$cheatStrings = @(
    "AutoCrystal", "autocrystal", "auto crystal", "cw crystal", "JDWP.VirtualMachine.AllModules",
    "dontPlaceCrystal", "dontBreakCrystal", "dev.virel", "orchard",
    "AutoHitCrystal", "autohitcrystal", "canPlaceCrystalServer", "healPotSlot",
    "ＡｕｔｏＣｒｙｓｔａｌ", "Ａｕｔｏ Ｃｒｙｓｔａｌ",
    "ＡｕｔｏＨｉｔＣｒｙｓｔａｌ",
    "AutoAnchor", "autoanchor", "auto anchor", "DoubleAnchor",
    "HasAnchor", "anchortweaks", "anchor macro", "safe anchor", "safeanchor",
    "SafeAnchor", "AirAnchor",
    "ＡｕｔｏＡｎｃｈｏｒ", "Ａｕｔｏ Ａｎｃｈｏｒ",
    "ＤｏｕｂｌｅＡｎｃｈｏｒ", "Ｄｏｕｂｌｅ Ａｎｃｈｏｒ",
    "ＳａｆｅＡｎｃｈｏｒ", "Ｓａｆｅ Ａｎｃｈｏｒ",
    "Ａｎｃｈｏｒ Ｍａｃｒｏ", "anchorMacro",
    "AutoTotem", "autototem", "auto totem", "InventoryTotem",
    "inventorytotem", "HoverTotem", "hover totem", "legittotem",
    "ＡｕｔｏＴｏｔｅｍ", "Ａｕｔｏ Ｔｏｔｅｍ",
    "ＨｏｖｅｒＴｏｔｅｍ", "Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "ＩｎｖｅｎｔｏｒｙＴｏｔｅｍ", "Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ",
    "Ａｕｔｏ Ｔｏｔｅｍ Ｈｉｔ",
    "AutoPot", "autopot", "auto pot", "speedPotSlot", "strengthPotSlot",
    "AutoArmor", "autoarmor", "auto armor",
    "ＡｕｔｏＰｏｔ", "Ａｕｔｏ Ｐｏｔ",
    "Ａｕｔｏ Ｐｏｔ Ｒｅｆｉｌｌ", "AutoPotRefill",
    "ＡｕｔｏＡｒｍｏｒ", "Ａｕｔｏ Ａｒｍｏｒ",
    "preventSwordBlockBreaking", "preventSwordBlockAttack",
    "ShieldDisabler", "ShieldBreaker",
    "ＳｈｉｅｌｄＤｉｓａｂｌｅｒ", "Ｓｈｉｅｌｄ Ｄｉｓａｂｌｅｒ",
    "Breaking shield with axe...",
    "AutoDoubleHand", "autodoublehand", "auto double hand",
    "ＡｕｔｏＤｏｕｂｌｅＨａｎｄ", "Ａｕｔｏ Ｄｏｕｂｌｅ Ｈａｎｄ",
    "AutoClicker",
    "ＡｕｔｏＣｌｉｃｋｅｒ",
    "Failed to switch to mace after axe!",
    "AutoMace", "MaceSwap", "SpearSwap",
    "ＡｕｔｏＭａｃｅ", "Ａｕｔｏ Ｍａｃｅ",
    "ＭａｃｅＳｗａｐ", "Ｍａｃｅ Ｓｗａｐ",
    "Ｓｐｅａｒ Ｓｗａｐ", "Ａｕｔｏｍａｔｉｃａｌｌｙ ａｘｅ ａｎｄ ｍａｃｅ ｓｈｉｅｌｄｅｄ ｐｌａｙｅｒｓ",
    "Ｓｔｕｎ Ｓｌａｍ", "StunSlam",
    "Donut", "JumpReset", "axespam", "axe spam",

    "findKnockbackSword", "attackRegisteredThisClick",
    "AimAssist", "aimassist", "aim assist",
    "triggerbot", "trigger bot",
    "ＡｉｍＡｓｓｉｓｔ", "Ａｉｍ Ａｓｓｉｓｔ",
    "ＴｒｉｇｇｅｒＢｏｔ", "Ｔｒｉｇｇｅｒ Ｂｏｔ",
    "Silent Rotations", "SilentRotations",
    "Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ",
    "FakeInv", "swapBackToOriginalSlot",
    "FakeLag", "pingspoof", "ping spoof",
    "ＦａｋｅＬａｇ", "Ｆａｋｅ Ｌａｇ",
    "fakePunch", "Fake Punch",
    "Ｆａｋｅ Ｐｕｎｃｈ",
    "mace_swap", "quick_strike", "macro_198", "stun_slam",
    "safe_anchor", "double_anchor", "auto_pot_refill",
    "walksy_optimizer", "key_pearl", "aim_assist",
    "auto_neth_pot", "auto_dtap", "trigger_bot", "auto_web",
    "DOUBLE_ESCAPE", "DOUBLE_RIGHTCLICK_FIRST", "DOUBLE_RIGHTCLICK_SECOND",
    "POST_CYCLE_DELAY", "PLACE_OBI", "WAIT_OBI", "PLACE_CRYSTAL", "BREAK_CRYSTAL",
    "ROTATING_DOWN", "ROTATING_BACK", "REFILLING", "PLANTING", "BONEMEALING",
    "AnchorAction", "Places two anchors for massive damage",
    "REOFFHAND_TOTEM",
    "webmacro", "web macro",
    "AntiWeb", "AutoWeb",
    "Ａｎｔｉ Ｗｅｂ", "ＡｕｔｏＷｅｂ",
    "Ｐｌａｃｅｓ Ｗｅｂｓ Ｏｎ Ｅｎｅｍｉｅｓ",
    "lvstrng", "dqrkis", "selfdestruct", "self destruct",
    "WalksyCrystalOptimizerMod", "WalksyOptimizer", "WalskyOptimizer",
    "Ｗａｌｋｓｙ Ｏｐｔｉｍｉｚｅｒ",
    "autoCrystalPlaceClock",
    "AutoFirework", "ElytraSwap", "FastXP", "FastExp", "NoJumpDelay",
    "ＥｌｙｔｒａＳｗａｐ", "Ｅｌｙｔｒａ Ｓｗａｐ",
    "PackSpoof", "Antiknockback", "catlean",
    "AuthBypass", "obfuscatedAuth", "LicenseCheckMixin",
    "BaseFinder", "invsee", "ItemExploit",
    "FreezePlayer",
    "Ｆｒｅｅｃａｍ", "Ｍｏｖｅ ｆｒｅｅｌｙ ｔｈｒｏｕｇｈ ｗａｌｌｓ",
    "Ｎｏ Ｃｌｉｐ", "Ｆｒｅｅｚｅ Ｐｌａｙｅｒ",
    "LWFH Crystal", "JDWP.VirtualMachine.AllModules",
    "ＬＷＦＨ Ｃｒｙｓｔａｌ",
    "KeyPearl", "LootYeeter",
    "ＫｅｙＰｅａｒｌ", "Ｋｅｙ Ｐｅａｒｌ",
    "Ｌｏｏｔ Ｙｅｅｔｅｒ",
    "FastPlace",
    "Ｆａｓｔ Ｐｌａｃｅ", "Ｐｌａｃｅ ｂｌｏｃｋｓ ｆａｓｔｅｒ",
    "AutoBreach",
    "Ａｕｔｏ Ｂｒｅａｃｈ",
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "blockBreakingCooldown",
    "onBlockBreaking", "setItemUseCooldown",
    "invokeDoAttack", "invokeDoItemUse", "invokeOnMouseButton",
    "onPushOutOfBlocks", "onIsGlowing",
    "Automatically switches to sword when hitting with totem",
    "arrayOfString", "POT_CHEATS",
    "Dqrkis Client", "Entity.isGlowing",
    "Activate Key", "Ａｃｔｉｖａｔｅ Ｋｅｙ",
    "Click Simulation", "Ｃｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ",
    "On RMB", "Ｏｎ ＲＭＢ",
    "No Count Glitch", "Ｎｏ Ｃｏｕｎｔ Ｇｌｉｔｃｈ",
    "No Bounce", "NoBounce", "Ｎｏ Ｂｏｕｎｃｅ", "ＮｏＢｏｕｎｃｅ",
    "Ｒｅｍｏｖｅｓ ｔｈｅ ｃｒｙｓｔａｌ ｂｏｕｎｃｅ ａｎｉｍａｔｉｏｎ",
    "Place Delay", "Ｐｌａｃｅ Ｄｅｌａｙ",
    "Break Delay", "Ｂｒｅａｋ Ｄｅｌａｙ",
     "Ｆａｓｔ Ｍｏｄｅ",
    "Place Chance", "Ｐｌａｃｅ Ｃｈａｎｃｅ",
    "Break Chance", "Ｂｒｅａｋ Ｃｈａｎｃｅ",
    "Stop On Kill", "Ｓｔｏｐ Ｏｎ Ｋｉｌｌ",
    "Ｄａｍａｇｅ Ｔｉｃｋ", "damagetick",
    "Anti Weakness", "Ａｎｔｉ Ｗｅａｋｎｅｓｓ",
    "Particle Chance", "Ｐａｒｔｉｃｌｅ Ｃｈａｎｃｅ",
    "Trigger Key", "Ｔｒｉｇｇｅｒ Ｋｅｙ",
    "Switch Delay", "Ｓｗｉｔｃｈ Ｄｅｌａｙ",
    "Totem Slot", "Ｔｏｔｅｍ Ｓｌｏｔ",
    "Silent Rotations", "Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ",
    "Smooth Rotations", "Ｓｍｏｏｔｈ Ｒｏｔａｔｉｏｎｓ",
    "Rotation Speed", "Ｒｏｔａｔｉｏｎ Ｓｐｅｅｄ",
    "Use Easing", "Ｕｓｅ Ｅａｓｉｎｇ",
    "Easing Strength", "Ｅａｓｉｎｇ Ｓｔｒｅｎｇｔｈ",
    "While Use", "Ｗｈｉｌｅ Ｕｓｅ",
    "Stop on Kill", "Ｓｔｏｐ ｏｎ Ｋｉｌｌ",
    "Click Simulation", "Ｃｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ",
    "Glowstone Delay", "Ｇｌｏｗｓｔｏｎｅ Ｄｅｌａｙ",
    "Glowstone Chance", "Ｇｌｏｗｓｔｏｎｅ Ｃｈａｎｃｅ",
    "Explode Delay", "Ｅｘｐｌｏｄｅ Ｄｅｌａｙ",
    "Explode Chance", "Ｅｘｐｌｏｄｅ Ｃｈａｎｃｅ",
    "Explode Slot", "Ｅｘｐｌｏｄｅ Ｓｌｏｔ",
    "Only Charge", "Ｏｎｌｙ Ｃｈａｒｇｅ",
    "Anchor Macro", "Ａｎｃｈｏｒ Ｍａｃｒｏ",
    "Reach Distance", "Ｒｅａｃｈ Ｄｉｓｔａｎｃｅ",
    "Min Height", "Ｍｉｎ Ｈｅｉｇｈｔ",
    "Min Fall Speed", "Ｍｉｎ Ｆａｌｌ Ｓｐｅｅｄ",
    "Attack Delay", "Ａｔｔａｃｋ Ｄｅｌａｙ",
    "Breach Delay", "Ｂｒｅａｃｈ Ｄｅｌａｙ",
    "Require Elytra", "Ｒｅｑｕｉｒｅ Ｅｌｙｔｒａ",
    "Auto Switch Back", "Ａｕｔｏ Ｓｗｉｔｃｈ Ｂａｃｋ",
    "Check Line of Sight", "Ｃｈｅｃｋ Ｌｉｎｅ ｏｆ Ｓｉｇｈｔ",
    "Only When Falling", "Ｏｎｌｙ Ｗｈｅｎ Ｆａｌｌｉｎｇ",
    "Require Crit", "Ｒｅｑｕｉｒｅ Ｃｒｉｔ",
    "Show Status Display", "Ｓｈｏｗ Ｓｔａｔｕｓ Ｄｉｓｐｌａｙ",
    "Stop On Crystal", "Ｓｔｏｐ Ｏｎ Ｃｒｙｓｔａｌ",
    "Check Shield", "Ｃｈｅｃｋ Ｓｈｉｅｌｄ",
    "On Pop", "Ｏｎ Ｐｏｐ",
    "Predict Damage", "Ｐｒｅｄｉｃｔ Ｄａｍａｇｅ",
    "On Ground", "Ｏｎ Ｇｒｏｕｎｄ",
    "Check Players", "Ｃｈｅｃｋ Ｐｌａｙｅｒｓ",
    "Predict Crystals", "Ｐｒｅｄｉｃｔ Ｃｒｙｓｔａｌｓ",
    "Check Aim", "Ｃｈｅｃｋ Ａｉｍ",
    "Check Items", "Ｃｈｅｃｋ Ｉｔｅｍｓ",
    "Activates Above", "Ａｃｔｉｖａｔｅｓ Ａｂｏｖｅ",
    "Blatant", "Ｂｌａｔａｎｔ",
    "Force Totem", "Ｆｏｒｃｅ Ｔｏｔｅｍ",
    "Stay Open For", "Ｓｔａｙ Ｏｐｅｎ Ｆｏｒ",
    "Auto Inventory Totem", "Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ",
    "Only On Pop", "Ｏｎｌｙ Ｏｎ Ｐｏｐ",
    "Vertical Speed", "Ｖｅｒｔｉｃａｌ Ｓｐｅｅｄ",
    "Hover Totem", "Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "Swap Speed", "Ｓｗａｐ Ｓｐｅｅｄ",
    "Strict One-Tick", "Ｓｔｒｉｃｔ Ｏｎｅ－Ｔｉｃｋ",
    "Mace Priority", "Ｍａｃｅ Ｐｒｉｏｒｉｔｙ",
    "Min Totems", "Ｍｉｎ Ｔｏｔｅｍｓ",
    "Min Pearls", "Ｍｉｎ Ｐｅａｒｌｓ",
    "Totem First", "Ｔｏｔｅｍ Ｆｉｒｓｔ",
    "Drop Interval", "Ｄｒｏｐ Ｉｎｔｅｒｖａｌ",
    "Random Pattern", "Ｒａｎｄｏｍ Ｐａｔｔｅｒｎ",
    "Loot Yeeter", "Ｌｏｏｔ Ｙｅｅｔｅｒ",
    "Horizontal Aim Speed", "Ｈｏｒｉｚｏｎｔａｌ Ａｉｍ Ｓｐｅｅｄ",
    "Vertical Aim Speed", "Ｖｅｒｔｉｃａｌ Ａｉｍ Ｓｐｅｅｄ",
    "Include Head", "Ｉｎｃｌｕｄｅ Ｈｅａｄ",
    "Web Delay", "Ｗｅｂ Ｄｅｌａｙ",
    "Holding Web", "Ｈｏｌｄｉｎｇ Ｗｅｂ",
    "Not When Affects Player", "Ｎｏｔ Ｗｈｅｎ Ａｆｆｅｃｔｓ Ｐｌａｙｅｒ",
    "Hit Delay", "Ｈｉｔ Ｄｅｌａｙ",
    "Ｓｗｉｔｃｈ Ｂａｃｋ",
    "Require Hold Axe", "Ｒｅｑｕｉｒｅ Ｈｏｌｄ Ａｘｅ",
    "Fake Punch", "Ｆａｋｅ Ｐｕｎｃｈ",
    "placeInterval", "breakInterval", "stopOnKill",
    "activateOnRightClick", "holdCrystal",
    "ｐｌａｃｅＩｎｔｅｒｖａｌ", "ｂｒｅａｋＩｎｔｅｒｖａｌ",
    "ｓｔｏｐＯｎＫｉｌｌ", "ａｃｔｉｖａｔｅＯｎＲｉｇｈｔＣｌｉｃｋ",
    "ｄａｍａｇｅｔｉｃｋ", "ｈｏｌｄＣｒｙｓｔａｌ",
    "ｆａｋｅＰｕｎｃｈ",
    "Ｒｅｆｉｌｌｓ ｙｏｕｒ ｈｏｔｂａｒ ｗｉｔｈ ｐｏｔｉｏｎｓ",
    "Ｋｅｐｓ ｙｏｕ ｓｐｒｉｎｔｉｎｇ ａｔ ａｌｌ ｔｉｍｅｓ",
    "Ｐｌａｃｅｓ ａｎｃｈｏｒ， ｃｈａｒｇｅｓ ｉｔ， ｐｒｏｔｅｃｔｓ ｙｏｕ， ａｎｄ ｅｘｐｌｏｄｅｓ",
    "Ａｕｔｏ ｓｗａｐ ｔｏ ｓｐｅａｒ ｏｎ ａｔｔａｃｋ",
    "Macro Key", "Ａｕｔｏ Ｐｏｔ", "Ｍａｃｒｏ Ｋｅｙ",
    "KillAura", "ClickAura", "MultiAura", "ForceField", "LegitAura",
    "AimBot", "AutoAim", "SilentAim", "AimLock", "HeadSnap",
    "CrystalAura",
    "AnchorAura", "AnchorFill", "AnchorPlace",
    "BedAura", "AutoBed", "BedBomb", "BedPlace",
    "BowAimbot", "BowSpam", "AutoBow",
    "AutoCrit", "CritBypass", "AlwaysCrit", "CriticalHit",
    "ReachHack", "ExtendReach", "LongReach", "HitboxExpand",
    "AntiKB", "NoKnockback", "GrimVelocity", "GrimDisabler", "VelocitySpoof", "KBReduce",
    "OffhandTotem", "TotemSwitch",
    "AutoWeapon", "AutoSword", "AutoCity", "Burrow", "SelfTrap",
    "HoleFiller", "AntiSurround", "AntiBurrow",
    "WTap", "TargetStrafe", "AutoGap", "AutoPearl",
    "FlyHack", "CreativeFlight", "BoatFly", "PacketFly", "AirJump",
    "SpeedHack", "BHop", "BunnyHop",
    "AntiFall", "NoFallDamage", "SafeFall",
    "StepHack", "FastClimb", "AutoStep", "HighStep",
    "WaterWalk", "LiquidWalk", "LavaWalk",
    "NoSlow", "NoSlowdown", "NoWeb", "NoSoulSand",
    "WallHack",
    "ElytraSpeed", "InstantElytra",
    "ScaffoldWalk", "FastBridge", "BuildHelper", "AutoBridge",
    "Nuker", "NukerLegit", "InstantBreak",
    "GhostHand", "NoSwing",
    "PlaceAssist", "AirPlace", "AutoPlace", "InstantPlace",
    "PlayerESP", "MobESP", "ItemESP", "StorageESP", "ChestESP",
    "Tracers", "NameTagsHack",
    "XRayHack", "OreFinder", "CaveFinder", "OreESP",
    "NewChunks", "ChunkBorders", "TunnelFinder",
    "TargetHUD", "ReachDisplay",
    "DoubleClicker", "JitterClick", "ButterflyClick", "CPSBoost",
    "ChestStealer", "InvManager", "InvMovebypass",
    "AutoSprint", "AntiAFK", "AutoRespawn",
    "PopSwitch",
    "FakeLatency", "FakePing", "SpoofRotation", "PositionSpoof",
    "GameSpeed", "SpeedTimer",
     "GrimBypass", "VulcanBypass", "MatrixBypass",
    "AACBypass", "VerusDisabler", "IntaveBypass", "WatchdogBypass",
    "PacketMine", "PacketWalk", "PacketSneak", "PacketCancel", "PacketDupe", "PacketSpam",
    "SelfDestruct", "HideClient",
    "SessionStealer", "TokenLogger", "TokenGrabber", "DiscordToken",
    "RemoteAccess", "ReverseShell", "C2Server", "Backdoor", "KeyLogger",
    "StashFinder", "TrailFinder",
    "imgui.binding",
    "JNativeHook", "GlobalScreen", "NativeKeyListener",
    "client-refmap.json", "cheat-refmap.json",
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "meteordevelopment", "cc/novoline",
    "com/alan/clients", "club/maxstats", "wtf/moonlight",
    "me/zeroeightsix/kami", "net/ccbluex", "today/opai",
    "net/minecraft/injection", "org/chainlibs/module/impl/modules",
    "xyz/greaj", "com/cheatbreaker", "com/moonsworth",
    "doomsdayclient", "DoomsdayClient", "doomsday.jar",
    "novaclient", "api.novaclient.lol",
    "WalksyOptimizer", "LWFH Crystal",
    "vape.gg", "vapeclient", "VapeClient", "VapeLite",
    "intent.store", "IntentClient",
    "rise.today", "riseclient.com",
    "meteor-client", "meteorclient", "meteordevelopment.meteorclient",
    "liquidbounce", "fdp-client", "net.ccbluex",
    "novoware", "novoclient",
    "aristois", "impactclient", "azura",
    "pandaware", "skilled", "moonClient", "astolfo",
    "futureClient", "konas", "rusherhack", "inertia", "exhibition",
    "dev.krypton", "dev/krypton", "skid.krypton", "skid/krypton",
     "VirginClient", "virgin client",
    "catlean", "CatleanClient", "catlean client",
     "ArgonClient", "argon client",
    "Asteria", "AsteriaClient", "asteria client",
    "Prestige", "PrestigeClient", "prestige client", "prestigeclient.vip",
    "gypsy", "GypsyClient", "gypsy client",
    "Xenon", "XenonClient", "xenon client",
     "GrimClient", "grim client",
    "phantom-refmap.json",
     "dqrkis.xyz", "Dqrkis Client"
)

$patternRegex = [regex]::new(
    '(?<![A-Za-z])(' + ($suspiciousPatterns -join '|') + ')(?![A-Za-z])',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$cheatStringSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($s in $cheatStrings) { [void]$cheatStringSet.Add($s) }

function Get-FileSHA1 {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA1).Hash
}

function Get-DownloadSource {
    param([string]$Path)
    $zoneData = Get-Content -Raw -Stream Zone.Identifier $Path -ErrorAction SilentlyContinue
    if ($zoneData -match "HostUrl=(.+)") {
        $url = $matches[1].Trim()
        if ($url -match "mediafire\.com")                                        { return "MediaFire" }
        elseif ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com") { return "Discord" }
        elseif ($url -match "dropbox\.com")                                      { return "Dropbox" }
        elseif ($url -match "drive\.google\.com")                                { return "Google Drive" }
        elseif ($url -match "mega\.nz|mega\.co\.nz")                             { return "MEGA" }
        elseif ($url -match "github\.com")                                       { return "GitHub" }
        elseif ($url -match "modrinth\.com")                                     { return "Modrinth" }
        elseif ($url -match "curseforge\.com")                                   { return "CurseForge" }
        elseif ($url -match "anydesk\.com")                                      { return "AnyDesk" }
        elseif ($url -match "doomsdayclient\.com")                               { return "DoomsdayClient" }
        elseif ($url -match "prestigeclient\.vip")                               { return "PrestigeClient" }
        elseif ($url -match "198macros\.com")                                    { return "198Macros" }
        elseif ($url -match "dqrkis\.xyz")                                       { return "Dqrkis" }
        else {
            if ($url -match "https?://(?:www\.)?([^/]+)") { return $matches[1] }
            return $url
        }
    }
    return $null
}

function Query-Modrinth {
    param([string]$Hash)
    try {
        $versionInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($versionInfo.project_id) {
            $projectInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($versionInfo.project_id)" -Method Get -UseBasicParsing -ErrorAction Stop
            return @{ Name = $projectInfo.title; Slug = $projectInfo.slug }
        }
    } catch { }
    return @{ Name = ""; Slug = "" }
}

function Query-Megabase {
    param([string]$Hash)
    try {
        $result = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$Hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if (-not $result.error) { return $result.data }
    } catch { }
    return $null
}

$fullwidthRegex = [regex]::new(
    "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}",
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

function Invoke-ModScan {
    param([string]$FilePath)

    $foundPatterns  = [System.Collections.Generic.HashSet[string]]::new()
    $foundStrings   = [System.Collections.Generic.HashSet[string]]::new()
    $foundFullwidth = [System.Collections.Generic.HashSet[string]]::new()

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        foreach ($entry in $archive.Entries) {
            foreach ($m in $script:patternRegex.Matches($entry.FullName)) {
                [void]$foundPatterns.Add($m.Value)
            }
        }

        $allEntries    = [System.Collections.Generic.List[object]]::new()
        $innerArchives = [System.Collections.Generic.List[object]]::new()

        foreach ($e in $archive.Entries) { $allEntries.Add($e) }

        foreach ($nj in ($archive.Entries | Where-Object { $_.FullName -match "^META-INF/jars/.+\.jar$" })) {
            try {
                $ns = $nj.Open()
                $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close()
                $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerArchives.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch { }
        }

        foreach ($entry in $allEntries) {
            $name = $entry.FullName

            if ($name -match '\.(class|json)$' -or $name -match 'MANIFEST\.MF') {
                try {
                    $st = $entry.Open()
                    $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2); $st.Close()
                    $bytes = $ms2.ToArray(); $ms2.Dispose()

                    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
                    $utf8  = [System.Text.Encoding]::UTF8.GetString($bytes)

                    foreach ($m in $script:patternRegex.Matches($ascii)) { [void]$foundPatterns.Add($m.Value) }

                    foreach ($s in $script:cheatStringSet) {
                        if ($ascii.Contains($s)) { [void]$foundStrings.Add($s); continue }
                        if ($utf8.Contains($s))  { [void]$foundStrings.Add($s) }
                    }

                    foreach ($m in $script:fullwidthRegex.Matches($utf8)) {
                        [void]$foundFullwidth.Add($m.Value)
                    }
                } catch { }
            }
        }

        foreach ($ia in $innerArchives) { try { $ia.Dispose() } catch { } }
        $archive.Dispose()
    } catch { }

    $fwCheatPool = @($script:cheatStrings | Where-Object {
        $_ -cmatch "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]"
    })
    $resolvedFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($fw in @($foundFullwidth)) {
        if ($fw.Length -lt 3) { continue }
        $bestMatch = $null
        foreach ($cs in $fwCheatPool) {
            if ($cs.Contains($fw)) {
                if ($null -eq $bestMatch -or $cs.Length -lt $bestMatch.Length) {
                    $bestMatch = $cs
                }
            }
        }
        if ($null -ne $bestMatch) {
            [void]$resolvedFullwidth.Add($bestMatch)
        } elseif ($fw.Length -ge 6) {
            [void]$resolvedFullwidth.Add($fw)
        }
    }
    $resolved = @($resolvedFullwidth)
    $finalFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($fw in $resolved) {
        $isRedundant = $false
        foreach ($other in $resolved) {
            if ($fw.Length -lt $other.Length -and $other.Contains($fw)) {
                $isRedundant = $true; break
            }
        }
        if (-not $isRedundant) { [void]$finalFullwidth.Add($fw) }
    }

    return @{ Patterns = $foundPatterns; Strings = $foundStrings; Fullwidth = $finalFullwidth }
}

function Invoke-ObfuscationScan {
    param([string]$FilePath)

    $flags = [System.Collections.Generic.List[string]]::new()

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $totalClass    = 0
        $numericCount  = 0
        $unicodeCount  = 0
        $fullwidthCount= 0
        $japaneseCount = 0
        $singleLetterCount = 0
        $twoLetterCount    = 0
        $gibberishCount    = 0
        $noVowelCount      = 0
        $confusionCount    = 0
        $singleCharPkg     = 0
        $contentSample     = [System.Text.StringBuilder]::new()
        $sampleSize        = 0

        $cheatObfuscators = @{
            "Skidfuscator"   = @("dev/skidfuscator", "Skidfuscator", "skidfuscator.dev")
            "Paramorphism"   = @("Paramorphism", "paramorphism-", "dev/paramorphism")
            "Radon"          = @("ItzSomebody/Radon", "me/itzsomebody/radon", "Radon Obfuscator")
            "Caesium"        = @("sim0n/Caesium", "Caesium Obfuscator", "dev/sim0n/caesium")
            "Bozar"          = @("vimasig/Bozar", "Bozar Obfuscator", "com/bozar")
            "Branchlock"     = @("Branchlock", "branchlock.dev")
            "Binscure"       = @("Binscure", "com/binscure")
            "SuperBlaubeere" = @("superblaubeere", "superblaubeere27")
            "Qprotect"       = @("Qprotect", "QProtect", "mdma.dev/qprotect")
            "Zelix"          = @("ZKMFLOW", "ZKM", "ZelixKlassMaster", "com/zelix")
            "Stringer"       = @("StringerJavaObfuscator", "com/licel/stringer")
            "JNIC"           = @("JNIC", "jnic.obf", "jnic-obfuscator")
            "Scuti"          = @("ScutiObf", "scuti.obf")
            "Smoke"          = @("SmokeObf", "smoke.obf")
        }

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName

            if ($name -match "\.class$") {
                $totalClass++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])

                if ($className -match "^\d+$")                          { $numericCount++ }
                if ($className -match "[^\x00-\x7F]")                   { $unicodeCount++ }
                if ($className -match "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]") { $fullwidthCount++ }
                if ($className -match "[\u3040-\u309F\u30A0-\u30FF]")  { $japaneseCount++ }
                if ($className -match "^[a-zA-Z]$")                     { $singleLetterCount++ }
                if ($className -match "^[a-zA-Z]{2}$")                  { $twoLetterCount++ }
                if ($className -match "^[Il1O0]+$" -or $className -match "^[_]+$") { $confusionCount++ }

                if ($className.Length -ge 3 -and $className.Length -le 8 -and $className -match "^[a-zA-Z]+$") {
                    $vowels = ($className.ToCharArray() | Where-Object { $_ -match "[aeiouAEIOU]" }).Count
                    if ($vowels -eq 0) { $noVowelCount++ }
                    $hasCluster = $className -match "[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{3,}"
                    if ($hasCluster -and ($vowels / $className.Length) -lt 0.3) { $gibberishCount++ }
                }

                $segs = ($name -replace "\.class$", "") -split "/"
                foreach ($seg in $segs[0..($segs.Count - 2)]) {
                    if ($seg.Length -eq 1) { $singleCharPkg++ }
                }

                if ($sampleSize -lt 150000 -and $entry.Length -lt 100000 -and $entry.Length -gt 100) {
                    try {
                        $st = $entry.Open()
                        $ms = New-Object System.IO.MemoryStream
                        $st.CopyTo($ms); $st.Close()
                        $ascii = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
                        $ms.Dispose()
                        [void]$contentSample.Append($ascii)
                        $sampleSize += $ascii.Length
                    } catch { }
                }
            }
        }

        $archive.Dispose()

        if ($totalClass -lt 5) { return $flags }

        $pct = { param($n) [math]::Round(($n / $totalClass) * 100) }

        $numPct   = & $pct $numericCount
        $uniPct   = & $pct $unicodeCount
        $fwPct    = & $pct $fullwidthCount
        $jpPct    = & $pct $japaneseCount
        $s1Pct    = & $pct $singleLetterCount
        $s2Pct    = & $pct $twoLetterCount
        $gibPct   = & $pct $gibberishCount
        $novPct   = & $pct $noVowelCount
        $confPct  = & $pct $confusionCount

        if ($numPct   -ge 20) { $flags.Add("Numeric class names — $numPct% of classes have numeric-only names") }
        if ($uniPct   -ge 10) { $flags.Add("Unicode class names — $uniPct% of classes use non-ASCII characters") }
        if ($fwPct    -gt  0) { $flags.Add("Fullwidth Unicode class names — $fwPct% use ａｂｃ/ＡＢＣ/０１２ chars ($fullwidthCount classes)") }
        if ($jpPct    -gt  0) { $flags.Add("Japanese obfuscation — $jpPct% use hiragana/katakana class names ($japaneseCount classes)") }
        if ($s1Pct    -ge 15) { $flags.Add("Single-letter class names — $s1Pct% ($singleLetterCount classes)") }
        if ($s2Pct    -ge 20) { $flags.Add("Two-letter class names — $s2Pct% ($twoLetterCount classes)") }
        if ($gibPct   -ge  5) { $flags.Add("Gibberish class names — $gibPct% have no vowels / consonant clusters ($gibberishCount classes)") }
        if ($novPct   -ge  8) { $flags.Add("No-vowel class names — $novPct% ($noVowelCount classes)") }
        if ($confPct  -ge  3) { $flags.Add("Confusion-char names (Il1O0/_) — $confPct% ($confusionCount classes)") }
        if ($singleCharPkg -ge 6) { $flags.Add("Single-char package paths — $singleCharPkg path segments like a/b/c") }

        $fwStringMatches = [regex]::Matches($contentSample.ToString(), "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}")
        if ($fwStringMatches.Count -gt 0) {
            $examples = ($fwStringMatches | Select-Object -First 3 | ForEach-Object { $_.Value }) -join ", "
            $flags.Add("Fullwidth strings in class content — $($fwStringMatches.Count) occurrences (e.g. $examples)")
        }

        $sampleStr = $contentSample.ToString()
        foreach ($obfName in $cheatObfuscators.Keys) {
            foreach ($pat in $cheatObfuscators[$obfName]) {
                if ($sampleStr.Contains($pat)) {
                    $flags.Add("Known cheat obfuscator detected — $obfName (matched: $pat)")
                    break
                }
            }
        }

    } catch { }

    return $flags
}

function Invoke-BypassScan {
    param([string]$FilePath)

    $flags = [System.Collections.Generic.List[string]]::new()

    $mavenPrefixes = @(
        "com_","org_","net_","io_","dev_","gs_","xyz_",
        "app_","me_","tv_","uk_","be_","fr_","de_"
    )

    function Test-SuspiciousJarName {
        param([string]$JarName)
        $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName)
        if ($base -match '\d')                                          { return $false }
        foreach ($pfx in $mavenPrefixes) {
            if ($base.ToLower().StartsWith($pfx))                       { return $false }
        }
        if ($base.Length -gt 20)                                        { return $false }
        return $true
    }

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $nestedJars   = @($zip.Entries | Where-Object { $_.FullName -match "^META-INF/jars/.+\.jar$" })
        $outerClasses = @($zip.Entries | Where-Object { $_.FullName -match "\.class$" })

        $suspiciousNestedJars = @()
        foreach ($nj in $nestedJars) {
            $njBase = [System.IO.Path]::GetFileName($nj.FullName)
            if (Test-SuspiciousJarName -JarName $njBase) {
                $suspiciousNestedJars += $njBase
            }
        }
        foreach ($sj in $suspiciousNestedJars) {
            $flags.Add("Suspicious nested JAR — no version, unknown dependency: $sj")
        }

        if ($nestedJars.Count -eq 1 -and $outerClasses.Count -lt 3) {
            $njName = [System.IO.Path]::GetFileName(($nestedJars | Select-Object -First 1).FullName)
            $flags.Add("Hollow shell — only $($outerClasses.Count) own class(es), wraps: $njName")
        }

        $outerModId = ""
        $fmje = $zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
        if ($fmje) {
            try {
                $s = $fmje.Open()
                $r = New-Object System.IO.StreamReader($s)
                $t = $r.ReadToEnd(); $r.Close(); $s.Close()
                if ($t -match '"id"\s*:\s*"([^"]+)"') { $outerModId = $matches[1] }
            } catch { }
        }

        $allEntries    = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $zip.Entries) { $allEntries.Add($e) }

        $innerZips = [System.Collections.Generic.List[object]]::new()
        foreach ($nj in $nestedJars) {
            try {
                $ns = $nj.Open()
                $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close()
                $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerZips.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch { }
        }

        $runtimeExecFound  = $false
        $httpDownloadFound = $false
        $httpExfilFound    = $false
        $obfuscatedCount   = 0
        $numericClassCount = 0
        $unicodeClassCount = 0
        $totalClassCount   = 0

        foreach ($entry in $allEntries) {
            $name = $entry.FullName

            if ($name -match "\.class$") {
                $totalClassCount++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])

                if ($className -match "^\d+$") { $numericClassCount++ }
                if ($className -match "[^\x00-\x7F]") { $unicodeClassCount++ }

                $segs = ($name -replace "\.class$","") -split "/"
                $consecutiveSingle = 0
                $maxConsecutive    = 0
                foreach ($seg in $segs) {
                    if ($seg.Length -eq 1) {
                        $consecutiveSingle++
                        if ($consecutiveSingle -gt $maxConsecutive) { $maxConsecutive = $consecutiveSingle }
                    } else {
                        $consecutiveSingle = 0
                    }
                }
                if ($maxConsecutive -ge 3) { $obfuscatedCount++ }

                try {
                    $st = $entry.Open()
                    $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2)
                    $st.Close()
                    $rawBytes = $ms2.ToArray()
                    $ms2.Dispose()
                    $ct = [System.Text.Encoding]::ASCII.GetString($rawBytes)

                    if ($ct -match "java/lang/Runtime" -and
                        $ct -match "getRuntime" -and
                        $ct -match "exec") {
                        $runtimeExecFound = $true
                    }

                    if ($ct -match "openConnection" -and
                        $ct -match "HttpURLConnection" -and
                        $ct -match "FileOutputStream") {
                        $httpDownloadFound = $true
                    }

                    if ($ct -match "openConnection" -and
                        $ct -match "setDoOutput" -and
                        $ct -match "getOutputStream" -and
                        $ct -match "getProperty") {
                        $httpExfilFound = $true
                    }

                } catch { }
            }
        }

        foreach ($iz in $innerZips) { try { $iz.Dispose() } catch { } }
        $zip.Dispose()

        $obfPct = if ($totalClassCount -ge 10) { [math]::Round(($obfuscatedCount   / $totalClassCount) * 100) } else { 0 }
        $numPct = if ($totalClassCount -ge 5)  { [math]::Round(($numericClassCount / $totalClassCount) * 100) } else { 0 }
        $uniPct = if ($totalClassCount -ge 5)  { [math]::Round(($unicodeClassCount / $totalClassCount) * 100) } else { 0 }

        if ($runtimeExecFound -and $obfPct -ge 25) {
            $flags.Add("Runtime.exec() in obfuscated code — can run arbitrary OS commands")
        }
        if ($httpDownloadFound) {
            $flags.Add("HTTP file download — fetches and writes files from a remote server at runtime")
        }
        if ($httpExfilFound) {
            $flags.Add("HTTP POST exfiltration — sends system data to an external server")
        }
        if ($totalClassCount -ge 10 -and $obfPct -ge 25) {
            $flags.Add("Heavy obfuscation — $obfPct% of classes use single-letter path segments (a/b/c style)")
        }
        if ($numPct -ge 20) {
            $flags.Add("Numeric class names — $numPct% of classes have numeric-only names (e.g. 1234.class)")
        }
        if ($uniPct -ge 10) {
            $flags.Add("Unicode class names — $uniPct% of classes use non-ASCII characters")
        }

        $knownLegitModIds = @(
            "vmp-fabric","vmp","lithium","sodium","iris","fabric-api",
            "modmenu","ferrite-core","lazydfu","starlight","entityculling",
            "memoryleakfix","krypton","c2me-fabric","smoothboot-fabric",
            "immediatelyfast","noisium","threadtweak"
        )
        $dangerCount = ($flags | Where-Object {
            $_ -match "Runtime\.exec|HTTP file download|HTTP POST|Heavy obfuscation|Suspicious nested JAR"
        }).Count
        if ($outerModId -and ($knownLegitModIds -contains $outerModId) -and $dangerCount -gt 0) {
            $flags.Add("Fake mod identity — claims to be '$outerModId' but contains dangerous code")
        }

    } catch { }

    return $flags
}

function Invoke-JvmScan {
    $results = [System.Collections.Generic.List[string]]::new()

    $javaProc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $javaProc) { $javaProc = Get-Process java -ErrorAction SilentlyContinue }
    if (-not $javaProc) { return $results }

    $javaPid = ($javaProc | Select-Object -First 1).Id

    try {
        $wmi     = Get-WmiObject Win32_Process -Filter "ProcessId = $javaPid" -ErrorAction Stop
        $cmdLine = $wmi.CommandLine

        if ($cmdLine) {
            $agentMatches = [regex]::Matches($cmdLine, '-javaagent:([^\s"]+)')
            foreach ($m in $agentMatches) {
                $agentPath = $m.Groups[1].Value.Trim('"').Trim("'")
                $agentName = [System.IO.Path]::GetFileName($agentPath)
                $legitAgents = @("jmxremote","yjp","jrebel","newrelic","jacoco","theseus")
                $isLegit = $false
                foreach ($la in $legitAgents) { if ($agentName -match $la) { $isLegit = $true; break } }
                if (-not $isLegit) {
                    $results.Add("JVM Agent — -javaagent:$agentName (path: $agentPath)")
                }
            }

            $suspiciousFlags = @(
                @{ Flag = "-Xbootclasspath/p:"; Desc = "prepends to bootstrap classpath, overrides core Java classes" },
                @{ Flag = "-Xbootclasspath/a:"; Desc = "appends to bootstrap classpath, injects below classloader" },
                @{ Flag = "-agentlib:jdwp";     Desc = "JDWP debug agent, remote debugging enabled" },
                @{ Flag = "-agentpath:";         Desc = "native agent loaded, bypasses Java sandbox" }
            )
            foreach ($sf in $suspiciousFlags) {
                if ($cmdLine -match [regex]::Escape($sf.Flag)) {
                    $results.Add("Suspicious JVM flag — $($sf.Flag) ($($sf.Desc))")
                }
            }
        }
    } catch { }

    return $results
}

# ---------------------------------------------------------------------------
# Worker mode (passes 2-4 run inside Start-Job child processes)
# ---------------------------------------------------------------------------
function Write-WorkerStatus {
    param([string]$Path, [string]$Text)
    try {
        $tmp = "$Path.tmp"
        [System.IO.File]::WriteAllText($tmp, $Text, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction SilentlyContinue
    } catch { }
}

function Invoke-WorkerItems {
    param(
        [string]$WorkerMode,
        [string]$WorkerList,
        [string]$WorkerOut
    )

    $items = @()
    try {
        if ($WorkerList -and (Test-Path -LiteralPath $WorkerList)) {
            $listText = [System.IO.File]::ReadAllText($WorkerList, [System.Text.Encoding]::UTF8)
            $items = @($listText | ConvertFrom-Json)
        }
    } catch { }

    $statusFile = Join-Path $WorkerOut "status.txt"
    $countFile  = Join-Path $WorkerOut "count.txt"
    $completed  = 0

    foreach ($item in $items) {
        $idx  = [int]$item.Index
        $path = [string]$item.Path
        $outFile = Join-Path $WorkerOut ("r{0}.json" -f $idx)

        Write-WorkerStatus $statusFile ([System.IO.Path]::GetFileName($path))

        $payload = @{
            Index     = $idx
            Patterns  = @()
            Strings   = @()
            Fullwidth = @()
            Flags     = @()
        }

        try {
            switch ($WorkerMode) {
                '2' {
                    if (-not ($item.White -eq $true)) {
                        $r = Invoke-ModScan -FilePath $path
                        $payload.Patterns  = @($r.Patterns)
                        $payload.Strings   = @($r.Strings)
                        $payload.Fullwidth = @($r.Fullwidth)
                    }
                }
                '3' {
                    if (-not ($item.White -eq $true)) {
                        $payload.Flags = @(Invoke-BypassScan -FilePath $path)
                    }
                }
                '4' {
                    $payload.Flags = @(Invoke-ObfuscationScan -FilePath $path)
                }
            }
        } catch { }

        try {
            $json = $payload | ConvertTo-Json -Compress -Depth 6
            [System.IO.File]::WriteAllText($outFile, $json, [System.Text.UTF8Encoding]::new($false))
        } catch { }

        $completed++
        Write-WorkerStatus $countFile ([string]$completed)
    }

    Write-WorkerStatus $statusFile "done"
}

if ($WorkerMode) {
    Invoke-WorkerItems -WorkerMode $WorkerMode -WorkerList $WorkerList -WorkerOut $WorkerOut
    exit 0
}

function Write-Rule {
    param([string]$Char = "─", [int]$Width = 76, [ConsoleColor]$Color = "DarkGray")
    Write-Host ($Char * $Width) -ForegroundColor $Color
}

function Write-SectionHeader {
    param(
        [string]$Title,
        [int]$Count,
        [ConsoleColor]$DotColor,
        [ConsoleColor]$CountColor
    )
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host "●" -ForegroundColor $DotColor -NoNewline
    Write-Host "  $Title  " -ForegroundColor White -NoNewline
    Write-Host "($Count)" -ForegroundColor $CountColor
    Write-Host ""
}

function Write-SuspiciousCard {
    param($Mod)

    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkRed
    Write-Host "  │ " -ForegroundColor DarkRed -NoNewline
    Write-Host " FLAGGED " -ForegroundColor White -BackgroundColor DarkRed -NoNewline
    Write-Host "  " -NoNewline
    Write-Host (Get-ModDisplay -Path $Mod.FilePath -Name $Mod.FileName) -ForegroundColor Yellow
    Write-ExtraPaths -Path $Mod.FilePath -Prefix '  │    ' -Color DarkGray
    Write-Host ("  │ " + ("─" * 66)) -ForegroundColor DarkRed

    if ($Mod.Patterns.Count -gt 0) {
        Write-Host "  │" -ForegroundColor DarkRed
        Write-Host "  │  " -ForegroundColor DarkRed -NoNewline
        Write-Host "PATTERNS" -ForegroundColor DarkGray
        foreach ($p in ($Mod.Patterns | Sort-Object)) {
            Write-Host "  │    " -ForegroundColor DarkRed -NoNewline
            Write-Host $p -ForegroundColor Red
        }
    }

    $uniqueStrings = $Mod.Strings | Where-Object { $Mod.Patterns -notcontains $_ } | Sort-Object
    if ($uniqueStrings.Count -gt 0) {
        Write-Host "  │" -ForegroundColor DarkRed
        Write-Host "  │  " -ForegroundColor DarkRed -NoNewline
        Write-Host "STRINGS" -ForegroundColor DarkGray
        foreach ($s in $uniqueStrings) {
            Write-Host "  │    " -ForegroundColor DarkRed -NoNewline
            Write-Host $s -ForegroundColor DarkYellow
        }
    }

    if ($Mod.Fullwidth -and $Mod.Fullwidth.Count -gt 0) {
        Write-Host "  │" -ForegroundColor DarkRed
        Write-Host "  │  " -ForegroundColor DarkRed -NoNewline
        Write-Host "FULLWIDTH UNICODE" -ForegroundColor DarkGray
        foreach ($fw in ($Mod.Fullwidth | Sort-Object)) {
            Write-Host "  │    " -ForegroundColor DarkRed -NoNewline
            Write-Host "FULLWIDTH: $fw" -ForegroundColor Cyan
        }
    }

    Write-Host "  │" -ForegroundColor DarkRed
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkRed
    Write-Host ""
}

function Write-InjectionCard {
    param($Mod)

    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkMagenta
    Write-Host "  │ " -ForegroundColor DarkMagenta -NoNewline
    Write-Host " INJECTION " -ForegroundColor White -BackgroundColor DarkMagenta -NoNewline
    Write-Host "  " -NoNewline
    Write-Host (Get-ModDisplay -Path $Mod.FilePath -Name $Mod.FileName) -ForegroundColor Yellow
    Write-ExtraPaths -Path $Mod.FilePath -Prefix '  │    ' -Color DarkGray
    Write-Host ("  │ " + ("─" * 66)) -ForegroundColor DarkMagenta

    foreach ($flag in $Mod.Flags) {
        if ($flag -match "^(.+?) — (.+)$") {
            $flagTitle = $matches[1]
            $flagDesc  = $matches[2]
        } else {
            $flagTitle = $flag
            $flagDesc  = ""
        }

        Write-Host "  │" -ForegroundColor DarkMagenta
        Write-Host "  │  " -ForegroundColor DarkMagenta -NoNewline
        Write-Host "◉ " -ForegroundColor Magenta -NoNewline
        Write-Host $flagTitle -ForegroundColor White

        if ($flagDesc -ne "") {
            Write-Host "  │    " -ForegroundColor DarkMagenta -NoNewline
            Write-Host $flagDesc -ForegroundColor Gray
        }
    }

    Write-Host "  │" -ForegroundColor DarkMagenta
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkMagenta
    Write-Host ""
}

function Write-ObfuscationCard {
    param($Mod)

    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkYellow
    Write-Host "  │ " -ForegroundColor DarkYellow -NoNewline
    Write-Host " OBFUSCATED " -ForegroundColor Black -BackgroundColor DarkYellow -NoNewline
    Write-Host "  " -NoNewline
    Write-Host (Get-ModDisplay -Path $Mod.FilePath -Name $Mod.FileName) -ForegroundColor Yellow
    Write-ExtraPaths -Path $Mod.FilePath -Prefix '  │    ' -Color DarkGray
    Write-Host ("  │ " + ("─" * 66)) -ForegroundColor DarkYellow

    foreach ($flag in $Mod.Flags) {
        if ($flag -match "^(.+?) — (.+)$") {
            $flagTitle = $matches[1]
            $flagDesc  = $matches[2]
        } else {
            $flagTitle = $flag
            $flagDesc  = ""
        }

        Write-Host "  │" -ForegroundColor DarkYellow
        Write-Host "  │  " -ForegroundColor DarkYellow -NoNewline
        Write-Host "⚑ " -ForegroundColor Yellow -NoNewline
        Write-Host $flagTitle -ForegroundColor White

        if ($flagDesc -ne "") {
            Write-Host "  │    " -ForegroundColor DarkYellow -NoNewline
            Write-Host $flagDesc -ForegroundColor Gray
        }
    }

    Write-Host "  │" -ForegroundColor DarkYellow
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkYellow
    Write-Host ""
}

$verifiedMods    = @()
$unknownMods     = @()
$suspiciousMods  = @()
$bypassMods      = @()
$obfuscatedMods  = @()

$script:JarFiles = New-Object System.Collections.ArrayList
$script:JarSeen  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

try {
    switch ($scanMode) {
        'system' {
            Add-SystemJars
        }
        'launchers' {
            $foundDirs = 0
            foreach ($d in (Get-LauncherModDirs)) {
                if (Test-Path -LiteralPath $d -PathType Container) {
                    Write-Host "   • $d" -ForegroundColor Gray
                    Get-ModsDirJars $d
                    $foundDirs++
                }
            }
            if ($foundDirs -eq 0) {
                Write-Host "   (no launcher mod folders found)" -ForegroundColor Yellow
            }
        }
        'custom' {
            Get-ModsDirJars $modsPath
        }
    }
} catch {
    Write-Host "❌ Error accessing directory: $_" -ForegroundColor Red
    Remove-ArchiveTemp
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

$jarFiles = @($script:JarFiles)

if ($jarFiles.Count -eq 0) {
    Write-Host "⚠️  No JAR files found in: $scanWhere" -ForegroundColor Yellow
    Remove-ArchiveTemp
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

$fileWord    = if ($jarFiles.Count -eq 1) { "file" } else { "files" }
Write-Host "🔍 Found $($jarFiles.Count) JAR $fileWord to analyze" -ForegroundColor Green
Write-Host

$spinnerFrames = @("⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷")
$totalFiles    = $jarFiles.Count
$idx           = 0

Write-Host "🔍 Pass 1 — Hash verification (Modrinth + Megabase)..." -ForegroundColor Cyan

foreach ($jar in $jarFiles) {
    $idx++
    $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
    Write-Host "`r[$spinner] Verifying: $idx/$totalFiles - $($jar.Name)" -ForegroundColor Yellow -NoNewline

    $hash = Get-FileSHA1 -Path $jar.FullName

    if ($hash -and ($script:scanMode -eq 'system' -or $script:scanMode -eq 'launchers')) {
        if ($script:HashPrimary.ContainsKey($hash)) {
            $primary = $script:HashPrimary[$hash]
            if ($primary -ne $jar.FullName) {
                if (-not $script:PathDupes.ContainsKey($primary)) {
                    $script:PathDupes[$primary] = New-Object System.Collections.Generic.List[string]
                }
                [void]$script:PathDupes[$primary].Add($jar.FullName)
                [void]$script:DuplicateJars.Add($jar.FullName)
                $script:DuplicateCount++
                continue
            }
        } else {
            $script:HashPrimary[$hash] = $jar.FullName
        }
    }

    if ($hash) {
        $modrinthData = Query-Modrinth -Hash $hash
        if ($modrinthData.Slug) {

            $modrinthWhitelistedSlugs = @("viafabricplus", "viafabricversion")
            $isModrinthWhitelisted = $modrinthWhitelistedSlugs -contains $modrinthData.Slug.ToLower()

            $verifiedMods += [PSCustomObject]@{
                ModName             = $modrinthData.Name
                FileName            = $jar.Name
                FilePath            = $jar.FullName
                ModrinthWhitelisted = $isModrinthWhitelisted
            }
            continue
        }
        $megabaseData = Query-Megabase -Hash $hash
        if ($megabaseData.name) {
            $verifiedMods += [PSCustomObject]@{
                ModName             = $megabaseData.Name
                FileName            = $jar.Name
                FilePath            = $jar.FullName
                ModrinthWhitelisted = $false
            }
            continue
        }
    }

    $src = Get-DownloadSource $jar.FullName
    $unknownMods += [PSCustomObject]@{ FileName = $jar.Name; FilePath = $jar.FullName; DownloadSource = $src }
}

Write-Host "`r$(' ' * 100)`r" -NoNewline

if ($script:DuplicateJars.Count -gt 0) {
    $jarFiles = @($jarFiles | Where-Object { -not $script:DuplicateJars.Contains($_.FullName) })
    $totalFiles = $jarFiles.Count
    $dupWord = if ($script:DuplicateCount -eq 1) { 'duplicate' } else { 'duplicates' }
    Write-Host "   ↺ Merged $($script:DuplicateCount) $dupWord with identical SHA-1" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Parallel scan support (passes 2-4)
# ---------------------------------------------------------------------------
function Get-WhitelistedNames {
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in $verifiedMods) {
        if ($m.ModrinthWhitelisted -eq $true) { [void]$set.Add($m.FileName) }
    }
    return ,$set
}

# When this script was launched through Invoke-Expression / Invoke-RestMethod there
# is no $PSCommandPath to re-execute for Start-Job -FilePath. In that case the
# worker is built from the functions and lookup tables already loaded in memory.
function Get-ParallelWorkerPayload {
    $names = @('Invoke-ModScan', 'Invoke-ObfuscationScan', 'Invoke-BypassScan', 'Write-WorkerStatus', 'Invoke-WorkerItems')
    $defs = @{}
    foreach ($name in $names) {
        $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
        if (-not $cmd) { return $null }
        $defs[$name] = "function $name {`n$($cmd.Definition)`n}"
    }
    return @{
        Functions        = $defs
        Patterns         = $patternRegex.ToString()
        PatternOptions   = [int]$patternRegex.Options
        Fullwidth        = $fullwidthRegex.ToString()
        FullwidthOptions = [int]$fullwidthRegex.Options
        CheatStrings     = @($script:cheatStrings)
    }
}

$script:ParallelWorkerBlock = {
    param($WorkerMode, $WorkerList, $WorkerOut, $Payload)

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    foreach ($name in @('Invoke-ModScan', 'Invoke-ObfuscationScan', 'Invoke-BypassScan', 'Write-WorkerStatus', 'Invoke-WorkerItems')) {
        if ($Payload.Functions -and $Payload.Functions.ContainsKey($name)) {
            . ([scriptblock]::Create([string]$Payload.Functions[$name]))
        }
    }

    $script:patternRegex   = [regex]::new([string]$Payload.Patterns, [System.Text.RegularExpressions.RegexOptions]$Payload.PatternOptions)
    $script:fullwidthRegex = [regex]::new([string]$Payload.Fullwidth, [System.Text.RegularExpressions.RegexOptions]$Payload.FullwidthOptions)
    $script:cheatStrings   = @($Payload.CheatStrings)
    $script:cheatStringSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($s in $script:cheatStrings) { [void]$script:cheatStringSet.Add($s) }

    Invoke-WorkerItems -WorkerMode $WorkerMode -WorkerList $WorkerList -WorkerOut $WorkerOut
}

function Invoke-ParallelPass {
    param(
        [string]$Mode,
        [string]$Label,
        $Whitelist
    )

    if (-not $script:ArchiveTemp) { return $null }
    $count = $jarFiles.Count
    if ($count -lt 2 -or $threads -lt 2) { return $null }

    $workerScriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($workerScriptPath) -or -not (Test-Path -LiteralPath $workerScriptPath)) {
        $workerScriptPath = Join-Path $script:ArchiveTemp "meow_worker.ps1"
        try {
            $myCode = $MyInvocation.MyCommand.ScriptBlock.ToString()
            if (-not $myCode) { $myCode = Get-Content -LiteralPath $script:MyInvocation.MyCommand.Path -Raw -ErrorAction SilentlyContinue }
            if ($myCode) { [System.IO.File]::WriteAllText($workerScriptPath, $myCode, [System.Text.Encoding]::UTF8) }
        } catch { }
    }

    if (-not (Test-Path -LiteralPath $workerScriptPath)) {
        Write-Host "   ⚠️  Could not create worker script path — falling back to single thread" -ForegroundColor DarkYellow
        return $null
    }

    $root = Join-Path $script:ArchiveTemp ("parallel-" + $Mode)
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $root | Out-Null

    $chunkCount = [Math]::Min($threads, $count)
    $baseSize = [int][Math]::Floor($count / [double]$chunkCount)
    $remainder = $count % $chunkCount

    $jobs = @()
    $start = 0
    for ($c = 0; $c -lt $chunkCount; $c++) {
        $size = $baseSize
        if ($c -lt $remainder) { $size++ }
        if ($size -lt 1) { continue }
        $end = $start + $size

        $chunkItems = @()
        for ($i = $start; $i -lt $end; $i++) {
            $jar = $jarFiles[$i]
            $isWhite = $false
            if ($Whitelist -and $Whitelist.Contains($jar.Name)) { $isWhite = $true }
            $chunkItems += [PSCustomObject]@{
                Index = $i
                Path  = $jar.FullName
                White = $isWhite
            }
        }

        $listPath = Join-Path $root ("chunk-{0}.json" -f $c)
        $chunkJson = ConvertTo-Json -InputObject @($chunkItems) -Compress -Depth 4
        [System.IO.File]::WriteAllText($listPath, $chunkJson, [System.Text.UTF8Encoding]::new($false))

        $outDir = Join-Path $root ("out-{0}" -f $c)
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null

        try {
            $job = Start-Job -FilePath $workerScriptPath -ArgumentList $Mode, $listPath, $outDir
        } catch {
            foreach ($j in $jobs) {
                try { Stop-Job -Job $j.Job -ErrorAction SilentlyContinue; Remove-Job -Job $j.Job -Force -ErrorAction SilentlyContinue } catch { }
            }
            return $null
        }
        $jobs += [PSCustomObject]@{ Job = $job; OutDir = $outDir; Start = $start; End = $end }
        $start = $end
    }

    if ($jobs.Count -eq 0) { return $null }

    try {
        while ($true) {
            $active = @($jobs | Where-Object { @('Completed','Failed','Stopped') -notcontains $_.Job.State })
            if ($active.Count -eq 0) { break }

            $completed = 0
            for ($c = 0; $c -lt $jobs.Count; $c++) {
                $j = $jobs[$c]
                $countFile = Join-Path $j.OutDir "count.txt"
                if (Test-Path -LiteralPath $countFile) {
                    try {
                        $n = 0
                        if ([int]::TryParse([System.IO.File]::ReadAllText($countFile, [System.Text.Encoding]::UTF8).Trim(), [ref]$n)) {
                            $completed += $n
                        }
                    } catch { }
                }
            }
            $percent = if ($count -gt 0) { [int][Math]::Floor(100.0 * $completed / $count) } else { 0 }
            if ($percent -gt 100) { $percent = 100 }
            Write-Progress -Activity "$Label ($threads threads)" -Status "$completed/$count mods scanned" -PercentComplete $percent
            Start-Sleep -Milliseconds 100
        }
    } finally {
        Write-Progress -Activity "$Label ($threads threads)" -Completed
    }

    $results = @{}
    $missing = 0
    foreach ($j in $jobs) {
        try { Receive-Job -Job $j.Job -ErrorAction SilentlyContinue | Out-Null } catch { }
        try { Remove-Job -Job $j.Job -Force -ErrorAction SilentlyContinue } catch { }
        for ($i = $j.Start; $i -lt $j.End; $i++) {
            $file = Join-Path $j.OutDir ("r{0}.json" -f $i)
            if (-not (Test-Path -LiteralPath $file)) { $missing++; continue }
            try {
                $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)
                $results[$i] = $text | ConvertFrom-Json
            } catch { $missing++ }
        }
    }

    if ($missing -gt 0) {
        Write-Host "   ⚠️  Parallel scan incomplete ($missing result(s) missing) — falling back to single thread" -ForegroundColor DarkYellow
        return $null
    }

    Write-Host "   ✓ $Label`: $count/$count mods scanned successfully with $threads threads" -ForegroundColor DarkGray
    return $results
}

$modWord = if ($totalFiles -eq 1) { "mod" } else { "mods" }
Write-Host "🔬 Pass 2 — Deep-scanning all $totalFiles $modWord..." -ForegroundColor Cyan

$whitelist = Get-WhitelistedNames
$parallel = $null
if ($threads -gt 1 -and $totalFiles -gt 1) {
    Write-Host "   Using $threads threads" -ForegroundColor DarkGray
    $parallel = Invoke-ParallelPass -Mode '2' -Label 'Scanning' -Whitelist $whitelist
}

$idx = 0
foreach ($jar in $jarFiles) {
    $i = $idx
    $idx++

    if ($null -ne $parallel) {
        if (-not $parallel.ContainsKey($i)) { continue }
        $r = $parallel[$i]
        $pats = @($r.Patterns)
        $strs = @($r.Strings)
        $fws  = @($r.Fullwidth)
        if ($pats.Count -gt 0 -or $strs.Count -gt 0 -or $fws.Count -gt 0) {
            $suspiciousMods += [PSCustomObject]@{
                FileName  = $jar.Name
                FilePath  = $jar.FullName
                Patterns  = $pats
                Strings   = $strs
                Fullwidth = $fws
            }
            $verifiedMods = $verifiedMods | Where-Object { $_.FileName -ne $jar.Name }
        }
        continue
    }

    $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
    Write-Host "`r[$spinner] Scanning: $idx/$totalFiles - $($jar.Name)" -ForegroundColor Yellow -NoNewline

    if ($whitelist -and $whitelist.Contains($jar.Name)) { continue }

    $result = Invoke-ModScan -FilePath $jar.FullName

    if ($result.Patterns.Count -gt 0 -or $result.Strings.Count -gt 0 -or $result.Fullwidth.Count -gt 0) {
        $suspiciousMods += [PSCustomObject]@{
            FileName = $jar.Name
            FilePath = $jar.FullName
            Patterns = $result.Patterns
            Strings  = $result.Strings
            Fullwidth = $result.Fullwidth
        }
        $verifiedMods = $verifiedMods | Where-Object { $_.FileName -ne $jar.Name }
    }
}

Write-Host "`r$(' ' * 100)`r" -NoNewline

Write-Host "🛡️  Pass 3 — Bypass/injection scan on all $totalFiles $modWord..." -ForegroundColor Magenta

$whitelist = Get-WhitelistedNames
$parallel = $null
if ($threads -gt 1 -and $totalFiles -gt 1) {
    Write-Host "   Using $threads threads" -ForegroundColor DarkGray
    $parallel = Invoke-ParallelPass -Mode '3' -Label 'Bypass scan' -Whitelist $whitelist
}

$idx = 0
foreach ($jar in $jarFiles) {
    $i = $idx
    $idx++

    if ($null -ne $parallel) {
        if (-not $parallel.ContainsKey($i)) { continue }
        $bypassFlags = @($parallel[$i].Flags)
        if ($bypassFlags.Count -gt 0) {
            $bypassMods += [PSCustomObject]@{
                FileName = $jar.Name
                FilePath = $jar.FullName
                Flags    = $bypassFlags
            }
            $verifiedMods = $verifiedMods | Where-Object { $_.FileName -ne $jar.Name }
            $unknownMods  = $unknownMods  | Where-Object { $_.FileName -ne $jar.Name }
        }
        continue
    }

    $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
    Write-Host "`r[$spinner] Bypass scan: $idx/$totalFiles - $($jar.Name)" -ForegroundColor Yellow -NoNewline

    if ($whitelist -and $whitelist.Contains($jar.Name)) { continue }

    $bypassFlags = Invoke-BypassScan -FilePath $jar.FullName

    if ($bypassFlags.Count -gt 0) {
        $bypassMods += [PSCustomObject]@{
            FileName = $jar.Name
            FilePath = $jar.FullName
            Flags    = $bypassFlags
        }
        $verifiedMods = $verifiedMods | Where-Object { $_.FileName -ne $jar.Name }
        $unknownMods  = $unknownMods  | Where-Object { $_.FileName -ne $jar.Name }
    }
}

Write-Host "`r$(' ' * 100)`r" -NoNewline

Write-Host "🔎 Pass 4 — Obfuscation analysis on all $totalFiles $modWord..." -ForegroundColor DarkCyan

$parallel = $null
if ($threads -gt 1 -and $totalFiles -gt 1) {
    Write-Host "   Using $threads threads" -ForegroundColor DarkGray
    $parallel = Invoke-ParallelPass -Mode '4' -Label 'Obf scan' -Whitelist $null
}

$idx = 0
foreach ($jar in $jarFiles) {
    $i = $idx
    $idx++

    if ($null -ne $parallel) {
        if (-not $parallel.ContainsKey($i)) { continue }
        $obfFlags = @($parallel[$i].Flags)
    } else {
        $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
        Write-Host "`r[$spinner] Obf scan: $idx/$totalFiles - $($jar.Name)" -ForegroundColor Yellow -NoNewline
        $obfFlags = Invoke-ObfuscationScan -FilePath $jar.FullName
    }

    if ($obfFlags.Count -gt 0) {
        $alreadyFlagged = ($suspiciousMods | Where-Object { $_.FileName -eq $jar.Name }).Count -gt 0 -or
                          ($bypassMods     | Where-Object { $_.FileName -eq $jar.Name }).Count -gt 0
        if (-not $alreadyFlagged) {
            $obfuscatedMods += [PSCustomObject]@{
                FileName = $jar.Name
                FilePath = $jar.FullName
                Flags    = $obfFlags
            }
            $verifiedMods = $verifiedMods | Where-Object { $_.FileName -ne $jar.Name }
        }
    }
}

Write-Host "`r$(' ' * 100)`r" -NoNewline

$jvmFlags = @()
Write-Host "⚡ Pass 5 — Scanning JVM for agents and injections..." -ForegroundColor DarkYellow
$jvmFlags = Invoke-JvmScan
if ($jvmFlags.Count -gt 0) {
    Write-Host "   ⚠️  JVM issues found!" -ForegroundColor Yellow
} else {
    Write-Host "   ✓  JVM looks clean" -ForegroundColor DarkGray
}

Write-Host "`r$(' ' * 100)`r" -NoNewline

if ($verifiedMods.Count -gt 0) {
    Write-SectionHeader -Title "VERIFIED MODS" -Count $verifiedMods.Count -DotColor Green -CountColor Green
    Write-Rule "─" 76 DarkGray
    foreach ($mod in $verifiedMods) {
        Write-Host "  ✓ " -ForegroundColor Green -NoNewline
        Write-Host "$($mod.ModName)" -ForegroundColor White -NoNewline
        Write-Host " → " -ForegroundColor Gray -NoNewline
        Write-Host (Get-ModDisplay -Path $mod.FilePath -Name $mod.FileName) -ForegroundColor DarkGray
        Write-ExtraPaths -Path $mod.FilePath -Prefix '               ' -Color DarkGray
    }
    Write-Host ""
}

if ($unknownMods.Count -gt 0) {
    Write-SectionHeader -Title "UNKNOWN MODS" -Count $unknownMods.Count -DotColor Yellow -CountColor Yellow
    Write-Rule "─" 76 DarkGray
    foreach ($mod in $unknownMods) {
        $name = $mod.FileName
        if ($name.Length -gt 50) { $name = $name.Substring(0,47) + "..." }
        $topLine    = "  ╔═ ? " + $name + " " + ("═" * (65 - $name.Length)) + "╗"
        $sourceText = if ($mod.DownloadSource) { "Source: $($mod.DownloadSource)" } else { "Source: ?" }
        $bottomLine = "  ╚═ " + $sourceText + " " + ("═" * (67 - $sourceText.Length)) + "╝"
        Write-Host $topLine    -ForegroundColor Yellow
        Write-Host $bottomLine -ForegroundColor Yellow
        if ($script:scanMode -eq 'system' -or $script:scanMode -eq 'launchers') {
            Write-Host "  ↳ " -ForegroundColor DarkGray -NoNewline
            Write-Host (Get-ModDisplay -Path $mod.FilePath -Name $mod.FileName) -ForegroundColor DarkGray
            Write-ExtraPaths -Path $mod.FilePath -Prefix '  ' -Color DarkGray
        }
        Write-Host ""
    }
}

if ($suspiciousMods.Count -gt 0) {
    Write-SectionHeader -Title "SUSPICIOUS MODS" -Count $suspiciousMods.Count -DotColor Red -CountColor Red
    Write-Rule "─" 76 DarkGray
    Write-Host ""
    foreach ($mod in $suspiciousMods) {
        Write-SuspiciousCard -Mod $mod
    }
}

if ($bypassMods.Count -gt 0) {
    Write-SectionHeader -Title "BYPASS / INJECTION DETECTED" -Count $bypassMods.Count -DotColor Magenta -CountColor Magenta
    Write-Rule "─" 76 DarkGray
    Write-Host ""
    foreach ($mod in $bypassMods) {
        Write-InjectionCard -Mod $mod
    }
}

if ($obfuscatedMods.Count -gt 0) {
    Write-SectionHeader -Title "OBFUSCATED MODS" -Count $obfuscatedMods.Count -DotColor DarkYellow -CountColor Yellow
    Write-Rule "─" 76 DarkGray
    Write-Host ""
    foreach ($mod in $obfuscatedMods) {
        Write-ObfuscationCard -Mod $mod
    }
}

if ($jvmFlags.Count -gt 0) {
    Write-SectionHeader -Title "JVM / RUNTIME INJECTION" -Count $jvmFlags.Count -DotColor Yellow -CountColor Yellow
    Write-Rule "─" 76 DarkGray
    Write-Host ""
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkYellow
    Write-Host "  │ " -ForegroundColor DarkYellow -NoNewline
    Write-Host " JVM " -ForegroundColor Black -BackgroundColor Yellow -NoNewline
    Write-Host "  javaw / java process" -ForegroundColor Yellow
    Write-Host ("  │ " + ("─" * 66)) -ForegroundColor DarkYellow
    foreach ($flag in $jvmFlags) {
        $ft = $flag; $fd = ""; $fpath = ""
        if ($flag -match "^(.+?) — (.+) \(path: (.+)\)$") {
            $ft = $matches[1]; $fd = $matches[2]; $fpath = $matches[3]
        } elseif ($flag -match "^(.+?) — (.+)$") {
            $ft = $matches[1]; $fd = $matches[2]
        }
        Write-Host "  │" -ForegroundColor DarkYellow
        Write-Host "  │  " -ForegroundColor DarkYellow -NoNewline
        Write-Host "◉ " -ForegroundColor Yellow -NoNewline
        Write-Host $ft -ForegroundColor White
        if ($fd -ne "") {
            Write-Host "  │    " -ForegroundColor DarkYellow -NoNewline
            Write-Host $fd -ForegroundColor Gray
        }
        if ($fpath -ne "") {
            $display = if ($fpath.Length -gt 60) { "..." + $fpath.Substring($fpath.Length - 57) } else { $fpath }
            Write-Host "  │    " -ForegroundColor DarkYellow -NoNewline
            Write-Host $display -ForegroundColor DarkGray
        }
    }
    Write-Host "  │" -ForegroundColor DarkYellow
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkYellow
    Write-Host ""
}

function Add-ResultExtraLines {
    param($Lines, [string]$Path)
    foreach ($extra in (Get-ExtraPaths -Path $Path)) {
        $null = $Lines.Add("  ↳ " + (Get-FullDisplayForPath -Path $extra))
    }
}

function Write-ResultsFile {
    $lines = [System.Collections.Generic.List[string]]::new()
    $null = $lines.Add('Meow Mod Analyzer — Results')
    $null = $lines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $lines.Add("Scan scope: $script:scanMode")
    $null = $lines.Add("Scanned: $scanWhere")
    $null = $lines.Add('')
    $null = $lines.Add('SUMMARY')
    $null = $lines.Add('-------')
    $null = $lines.Add("Total files scanned: $totalFiles")
    if ($script:DuplicateJars.Count -gt 0) {
        $null = $lines.Add("Duplicates merged:   $($script:DuplicateCount)")
    }
    $null = $lines.Add("Verified mods:       $($verifiedMods.Count)")
    $null = $lines.Add("Unknown mods:        $($unknownMods.Count)")
    $null = $lines.Add("Suspicious mods:     $($suspiciousMods.Count)")
    $null = $lines.Add("Bypass/Injected:     $($bypassMods.Count)")
    $null = $lines.Add("Obfuscated mods:     $($obfuscatedMods.Count)")
    $null = $lines.Add("JVM issues:          $($jvmFlags.Count)")

    if ($verifiedMods.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add('VERIFIED MODS')
        $null = $lines.Add('-------------')
        foreach ($mod in $verifiedMods) {
            $null = $lines.Add(("✓ {0} → {1}" -f $mod.ModName, (Get-FullDisplay -Path $mod.FilePath -Name $mod.FileName)))
            Add-ResultExtraLines -Lines $lines -Path $mod.FilePath
        }
    }

    if ($unknownMods.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add('UNKNOWN MODS')
        $null = $lines.Add('------------')
        foreach ($mod in $unknownMods) {
            $null = $lines.Add("? $(Get-FullDisplay -Path $mod.FilePath -Name $mod.FileName)")
            Add-ResultExtraLines -Lines $lines -Path $mod.FilePath
            $src = if ($mod.DownloadSource) { $mod.DownloadSource } else { '?' }
            $null = $lines.Add("  Source: $src")
        }
    }

    if ($suspiciousMods.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add('SUSPICIOUS MODS')
        $null = $lines.Add('---------------')
        foreach ($mod in $suspiciousMods) {
            $null = $lines.Add("! $(Get-FullDisplay -Path $mod.FilePath -Name $mod.FileName)")
            Add-ResultExtraLines -Lines $lines -Path $mod.FilePath
            if ($mod.Patterns.Count -gt 0) {
                $null = $lines.Add('  Patterns:')
                foreach ($p in ($mod.Patterns | Sort-Object)) { $null = $lines.Add("    $p") }
            }
            $uniqueStrings = $mod.Strings | Where-Object { $mod.Patterns -notcontains $_ } | Sort-Object
            if ($uniqueStrings.Count -gt 0) {
                $null = $lines.Add('  Strings:')
                foreach ($s in $uniqueStrings) { $null = $lines.Add("    $s") }
            }
            if ($mod.Fullwidth -and $mod.Fullwidth.Count -gt 0) {
                $null = $lines.Add('  Fullwidth Unicode:')
                foreach ($fw in ($mod.Fullwidth | Sort-Object)) { $null = $lines.Add("    $fw") }
            }
        }
    }

    if ($bypassMods.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add('BYPASS / INJECTION DETECTED')
        $null = $lines.Add('---------------------------')
        foreach ($mod in $bypassMods) {
            $null = $lines.Add("! $(Get-FullDisplay -Path $mod.FilePath -Name $mod.FileName)")
            Add-ResultExtraLines -Lines $lines -Path $mod.FilePath
            foreach ($flag in $mod.Flags) { $null = $lines.Add("    $flag") }
        }
    }

    if ($obfuscatedMods.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add('OBFUSCATED MODS')
        $null = $lines.Add('---------------')
        foreach ($mod in $obfuscatedMods) {
            $null = $lines.Add("! $(Get-FullDisplay -Path $mod.FilePath -Name $mod.FileName)")
            Add-ResultExtraLines -Lines $lines -Path $mod.FilePath
            foreach ($flag in $mod.Flags) { $null = $lines.Add("    $flag") }
        }
    }

    if ($jvmFlags.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add('JVM / RUNTIME INJECTION')
        $null = $lines.Add('-----------------------')
        foreach ($flag in $jvmFlags) { $null = $lines.Add("◉ $flag") }
    }

    $resultsDir  = if ($env:SystemDrive) { $env:SystemDrive + '\ss' } else { 'C:\ss' }
    $resultsFile = Join-Path $resultsDir 'MeowModResults.txt'

    try {
        if (-not (Test-Path -LiteralPath $resultsDir -PathType Container)) {
            New-Item -ItemType Directory -Force -Path $resultsDir -ErrorAction Stop | Out-Null
        }
        [System.IO.File]::WriteAllLines($resultsFile, $lines)
        Write-Host "📝 Results saved to: $resultsFile" -ForegroundColor DarkGray
    } catch {
        Write-Host "⚠️  Could not write results file: $resultsFile" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "📊 SUMMARY" -ForegroundColor Cyan
Write-Rule "━" 76 Blue
Write-Host "  Total files scanned: " -ForegroundColor Gray -NoNewline; Write-Host "$totalFiles"                   -ForegroundColor White
Write-Host "  Verified mods:       " -ForegroundColor Gray -NoNewline; Write-Host "$($verifiedMods.Count)"        -ForegroundColor Green
Write-Host "  Unknown mods:        " -ForegroundColor Gray -NoNewline; Write-Host "$($unknownMods.Count)"         -ForegroundColor Yellow
Write-Host "  Suspicious mods:     " -ForegroundColor Gray -NoNewline; Write-Host "$($suspiciousMods.Count)"      -ForegroundColor Red
Write-Host "  Bypass/Injected:     " -ForegroundColor Gray -NoNewline; Write-Host "$($bypassMods.Count)"          -ForegroundColor Magenta
Write-Host "  Obfuscated mods:     " -ForegroundColor Gray -NoNewline; Write-Host "$($obfuscatedMods.Count)"      -ForegroundColor Yellow
Write-Host "  JVM issues:          " -ForegroundColor Gray -NoNewline; Write-Host "$($jvmFlags.Count)"            -ForegroundColor Yellow
Write-Host
Write-Rule "━" 76 Blue
Write-Host ""
Write-ResultsFile
Write-Host "  ✨ Analysis complete! Thanks for using Meow Mod Analyzer 🐱" -ForegroundColor Cyan
Write-Host ""
Write-Host "  👤 Created by: " -ForegroundColor White -NoNewline
Write-Host "🌟 " -ForegroundColor Cyan -NoNewline
Write-Host "Tonynoh" -ForegroundColor Cyan
Write-Host "  📱 My Socials: " -ForegroundColor White -NoNewline
Write-Host "💬 " -ForegroundColor Blue -NoNewline
Write-Host "Discord  : " -ForegroundColor Blue -NoNewline
Write-Host "tonyboy90_" -ForegroundColor Blue
Write-Host "                 " -NoNewline
Write-Host "🔗 " -ForegroundColor DarkGray -NoNewline
Write-Host "GitHub   : " -ForegroundColor DarkGray -NoNewline
Write-Host "https://github.com/MeowTonynoh" -ForegroundColor DarkGray
Write-Host "                 " -NoNewline
Write-Host "🎥 " -ForegroundColor Red -NoNewline
Write-Host "YouTube  : " -ForegroundColor Red -NoNewline
Write-Host "tonynoh-07" -ForegroundColor Red
Write-Host ""
Write-Rule "━" 76 Blue
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor DarkGray
Remove-ArchiveTemp
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
