############################################
## manuelle Eingabe der Version in das Skript
## ohne stoppen & starten des Service
## sucht rekursiv nach dem Versionsordner (bzw. ZIP-Archiv) unter C:\DBA und all seinen Unterordnern.
## offene Todo: starten & starten optional, wenn preplans es nicht geschafft hat, dann wird optional start bzw. stop per skript ausgeführt
############################################
param (
    [Parameter(Mandatory = $true)]
    [string]$ComponentName,

    [string]$ComponentType = $null
)

function Ensure-TempFolder {
    param(
        [string]$Path = "C:\TEMP"
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            Write-Host "Folder '$Path' not found — creating..." -ForegroundColor Yellow
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-Host "Folder '$Path' created successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Folder '$Path' already exists." -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "VERROR: Could not verify or create '$Path' — $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ((Get-Date -Format s) + " - VRETURNCODE : 11")
        exit 11
    }
}

Ensure-TempFolder -Path "C:\TEMP"

$logFile = "C:\TEMP\UpdateComponent_$ComponentName_$(Get-Date -Format yyyyMMdd_HHmmss).log"
Start-Transcript -Path $logFile -Force
trap { Stop-Transcript | Out-Null; throw }

$SenvFolder = "C:\DBA\nest\senv\local"

#Enter new Apache version manually
$NewApacheVersion = "2.4.60"

#Enter new Tomcat version manually
$NewTomcatVersion = "10.1.44"


function Get-SenvFilesForType {
    param(
        [string]$ComponentType,
        [string]$SenvFolder
    )
    if ($ComponentType) {
        $typed = Join-Path $SenvFolder "$ComponentType.senv"
        if (Test-Path $typed) { return , (Get-Item $typed) }
        return @()
    }
    else {
        return Get-ChildItem -Path $SenvFolder -Filter *.senv
    }
}

function Detect-ComponentType {
    param([string]$ComponentName, [string]$Fallback = $null)
    if ($Fallback) { return $Fallback }
    switch -Regex ($ComponentName) {
        '^WSA' { return 'apache' }
        '^AST' { return 'tomcat' }
        '^APM' { return 'apm' }
        '^APC' { return 'apc' }
        '^APS' { return 'wildfly' }
        default { return $null }
    }
}

function Find-ComponentInSenv {
    param(
        [string]$ComponentName,
        [string]$ComponentType = $null,
        [string]$SenvFolder = "C:\DBA\nest\senv\local"
    )

    if (-not (Test-Path $SenvFolder)) {
        throw "Senv directory '$SenvFolder' does not exist."
    }

    $type = Detect-ComponentType -ComponentName $ComponentName -Fallback $ComponentType
    $files = Get-SenvFilesForType -ComponentType $type -SenvFolder $SenvFolder
    if (-not $files -or $files.Count -eq 0) {
        $files = Get-ChildItem -Path $SenvFolder -Filter *.senv
    }

    foreach ($file in $files) {
        $lines = Get-Content -Path $file.FullName
        $startIndex = ($lines | ForEach-Object { $_.Trim() }).IndexOf("[$ComponentName]")

        if ($startIndex -ge 0) {
            $endIndex = $startIndex + 1
            while ($endIndex -lt $lines.Count -and $lines[$endIndex] -notmatch '^\s*\[.+\]\s*$') {
                $endIndex++
            }

            $block = $lines[($startIndex + 1)..($endIndex - 1)]

            return [pscustomobject]@{
                File            = $file.FullName
                ComponentType   = $type
                ComponentName   = $ComponentName
                StartLineNumber = $startIndex + 1
                EndLineNumber   = $endIndex
                Block           = ($block -join [Environment]::NewLine)
            }
        }
    }

    return $null
}

$resolvedType = Detect-ComponentType -ComponentName $ComponentName -Fallback $ComponentType
Write-Host "Component type detected: $resolvedType"


try {
    $result = Find-ComponentInSenv -ComponentName $ComponentName -ComponentType $resolvedType -SenvFolder $SenvFolder
    if ($null -eq $result) {
        Write-Host ((Get-Date -Format s) + " - INFO   : No block found for [$ComponentName] in *.senv.")
        exit 4
    }

    Write-Host "Found in : $($result.File)"
    Write-Host "Typ         : $($result.ComponentType)"
    if ($resolvedType -eq 'apache') {
    Write-Host "target Version : $NewApacheVersion"
    }elseif ($resolvedType -eq 'tomcat') {
    Write-Host "target Version : $NewTomcatVersion"    
    }
    Write-Host "lines      : $($result.StartLineNumber)-$($result.EndLineNumber-1)"
    Write-Host "`n--- Current block (before update) ---"
    Write-Host $result.Block
    
}
catch {
    Write-Host ((Get-Date -Format s) + " - VERROR : $($_.Exception.Message)")
    Write-Host ((Get-Date -Format s) + " - VRETURNCODE : 7")
    exit 7
}

$serviceName = $ComponentName

try {
    Stop-Service -Name $ComponentName -Force -ErrorAction Stop
    Write-Host "Service '$ComponentName' successfully stopped."
    Start-Sleep -Seconds 5
}
catch {
    $rc = 21
    $msg = "Could not stop service '$ComponentName': $($_.Exception.Message)"
    Write-Host ((Get-Date -format s) + " - VERROR : $msg")
    Write-Host ((Get-Date -format s) + " - VRETURNCODE : $rc")
    exit $rc
}

if ($resolvedType -eq 'apache') {
    Write-Host "Start Apache update to version $NewApacheVersion..."

    $apacheRoot = "C:\DBA\apache24\WWW"

    function Ensure-ApacheReady {
        param(
            [Parameter(Mandatory = $true)][string]$Version,
            [string[]]$SearchRoots = @("C:\DBA"),
            [string]$TargetRoot = "C:\DBA\apache24\WWW"
        )

        $target = Join-Path $TargetRoot $Version
        if (Test-Path (Join-Path $target "bin\httpd.exe")) {
            Write-Host "Apache version $Version already prepared at $target"
            return $target
        }

        Write-Host "Searching for Apache version $Version under $($SearchRoots -join ', ')..."

        $esc = [regex]::Escape($Version)
        $hits = Get-ChildItem -Path $SearchRoots -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match $esc -and ( $_.PSIsContainer -or $_.Name -match '\.(zip|tar\.gz|tgz)$' ) }

        if (-not $hits -or $hits.Count -eq 0) {
            throw "Apache version '$Version' not found in $($SearchRoots -join ', ')"
        }

        foreach ($hit in $hits) {
            if ($hit.PSIsContainer -and (Test-Path (Join-Path $hit.FullName "bin\httpd.exe"))) {
                Write-Host "Found unpacked Apache folder: $($hit.FullName)"
                if (-not (Test-Path $TargetRoot)) { New-Item -ItemType Directory -Path $TargetRoot | Out-Null }
                if (Test-Path $target) { Remove-Item -Recurse -Force $target }
                Move-Item -Path $hit.FullName -Destination $target
                return $target
            }
        }

        $archive = $hits | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
        if (-not $archive) { throw "No unpacked folder and no archive found for Apache $Version." }

        Write-Host "Found archive: $($archive.FullName)"
        $tmp = Join-Path ([System.IO.Path]::GetDirectoryName($archive.FullName)) ("__extract_" + [IO.Path]::GetFileNameWithoutExtension($archive.Name))
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }

        if ($archive.Extension -eq ".zip") {
            Expand-Archive -Path $archive.FullName -DestinationPath $tmp -Force
        } elseif ($archive.Name -match "\.tar\.gz$|\.tgz$") {
            $tar = Get-Command tar -ErrorAction SilentlyContinue
            if (-not $tar) { throw "No tar found – cannot unpack '$($archive.FullName)'" }
            & $tar.Source -xzf $archive.FullName -C $tmp
        } else {
            throw "Unsupported archive format: $($archive.Name)"
        }

        $candidate = Get-ChildItem -Path $tmp -Directory -Recurse | Where-Object { Test-Path (Join-Path $_.FullName "bin\httpd.exe") } | Select-Object -First 1
        if (-not $candidate) { throw "No valid Apache24 structure found inside $tmp" }

        if (Test-Path $target) { Remove-Item -Recurse -Force $target }
        Move-Item -Path $candidate.FullName -Destination $target

        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
        if (Test-Path $archive.FullName) { Remove-Item -Force $archive.FullName }

        Write-Host "Apache $Version prepared at $target"
        return $target
    }

    try {
        $apacheTarget = Ensure-ApacheReady -Version $NewApacheVersion -SearchRoots @("C:\DBA") -TargetRoot "C:\DBA\apache24\WWW"
        Write-Host "Apache ready at: $apacheTarget"
    }
    catch {
        Write-Host ((Get-Date -Format s) + " - VERROR : $($_.Exception.Message)")
        Write-Host ((Get-Date -Format s) + " - VRETURNCODE : 23")
        exit 23
    }

    try {
        $svc = Get-Service -Name $ComponentName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "Stop service $ComponentName..."
            Stop-Service -Name $ComponentName -Force -ErrorAction Stop
            Start-Sleep -Seconds 5
        }
    }
    catch {
        Write-Warning "Service $ComponentName could not be stopped: $($_.Exception.Message)"
    }

    $senvFile = "C:\DBA\nest\senv\local\apache.senv"
    if (-not (Test-Path $senvFile)) { throw "apache.senv not found under $senvFile" }

    $lines = Get-Content -Path $senvFile -Encoding UTF8
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -eq "[$ComponentName]") { $start = $i; break }
    }
    if ($start -lt 0) { throw "block [$ComponentName] not found in apache.senv." }

    $end = $start + 1
    while ($end -lt $lines.Count -and $lines[$end] -notmatch '^\s*\[.+\]\s*$') { $end++ }

    $block = if ($end -gt $start + 1) { $lines[($start + 1)..($end - 1)] } else { @() }

    $verParts = $NewApacheVersion.Split('.')
    $major = $verParts[0]
    $minor = if ($verParts.Length -ge 2) { $verParts[1] } else { "0" }
    $release = if ($verParts.Length -ge 3) { $verParts[2] } else { "0" }
    $incLine = if ("$major.$minor" -eq "2.4") { "INC apache_24" } elseif ("$major.$minor" -eq "2.5") { "INC apache_25" } else { "INC apache_${major}${minor}" }
    $httpdPath = "$apacheRoot\$NewApacheVersion\bin\httpd.exe"

    $foundRelease = $false
    $foundInc = $false
    $foundHttpd = $false

    for ($i = 0; $i -lt $block.Count; $i++) {
        if ($block[$i] -match '^\s*SET\s+set\s+APACHE_RELEASE=') {
            $block[$i] = "SET set APACHE_RELEASE=$release"
            $foundRelease = $true
        }
        elseif ($block[$i] -match '^\s*INC\s+apache_') {
            $block[$i] = $incLine
            $foundInc = $true
        }
        elseif ($block[$i] -match '^\s*SET\s+set\s+APACHE_HTTPD=') {
            $block[$i] = "SET set APACHE_HTTPD=$httpdPath"
            $foundHttpd = $true
        }
    }

    if (-not $foundRelease) { $block += "SET set APACHE_RELEASE=$release" }
    if (-not $foundInc) { $block += $incLine }
    if (-not $foundHttpd) { $block += "SET set APACHE_HTTPD=$httpdPath" }

    $newLines = @()
    if ($start -gt 0) { $newLines += $lines[0..$start] } else { $newLines += $lines[0] }
    $newLines += $block
    if ($end -lt $lines.Count) { $newLines += $lines[$end..($lines.Count - 1)] }

    Set-Content -Path $senvFile -Value $newLines -Encoding UTF8
    Write-Host "apache.senv updated for $ComponentName."

    try {
        $svc = Get-Service -Name $ComponentName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "Delete service $ComponentName..."
            & sc.exe delete $ComponentName | Out-Null
            Start-Sleep -Seconds 5
        }
    }
    catch {
        Write-Warning "The $ComponentName service could not be deleted: $($_.Exception.Message)"
    }
    $serviceName = $ComponentName 

    $wshell = New-Object -ComObject WScript.Shell 

    $sessionDir = "C:\DBA\nest\senv" 
 

    if (-not (Test-Path $sessionDir)) { 

        $rc = 10 

        $msg = "Session directory '$sessionDir' not found." 

        Write-Host ((Get-Date -format s) + " - VERROR : $msg") 

        Write-Host ((Get-Date -format s) + " - VRETURNCODE : $rc") 

        exit $rc 

    } 

    $cmd = @"
@echo off
set "SENV_HOME=C:\DBA\nest\senv"
call "%SENV_HOME%\senv_profile.cmd"
timeout /t 30 /nobreak >nul
call "%SENV_HOME%\senv.cmd" $resolvedType $ComponentName
timeout /t 30 /nobreak >nul
if %errorlevel% neq 0 (
  echo Error when calling senv.cmd
  rem Window remains open
)
rem calls ...
call confresolve --inputfile %SRV_BASE%\conf\httpd.conf.in --configfile=%SRV_BASE%\conf\server.inc
timeout /t 30 /nobreak >nul
call %APACHE_HTTPD% -f %SRV_BASE%\conf\httpd.conf -t
timeout /t 30 /nobreak >nul
call %APACHE_HTTPD% -k install -n "%SRV_SID%" -D SSL -f "%SRV_BASE%\conf\httpd.conf"
timeout /t 30 /nobreak >nul
echo.
echo Done. This window will close automatically in 30 seconds....
timeout /t 30 /nobreak >nul
exit
"@

    $cmdPath = "C:\TEMP\disable_component_$ComponentName.cmd"
    Set-Content -Path $cmdPath -Value $cmd -Encoding ASCII

    Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$cmdPath`"" -WorkingDirectory "C:\DBA\nest\senv"

    Write-Host "`nWait 4 minutes before checking status..." -ForegroundColor Yellow
    Start-Sleep -Seconds 240   
    Start-Sleep -Seconds 10

    $newResult = Find-ComponentInSenv -ComponentName $ComponentName -ComponentType $resolvedType -SenvFolder $SenvFolder
    if ($null -ne $newResult) {
        Write-Host "`n--- New block (after update) ---"
        Write-Host $newResult.Block
    }
    else {
        Write-Host "New block [$ComponentName] could not be read from apache.senv."
    }

    try {
        $svc = Get-Service -Name $ComponentName -ErrorAction Stop
        if ($svc.Status -eq 'Running') {
            Write-Host "Service '$ComponentName' is running successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Service '$ComponentName' is not running (Status: $($svc.Status))." -ForegroundColor Red
            exit 31
        }
    }
    catch {
        Write-Host "Service '$ComponentName' could not be found: $($_.Exception.Message)" -ForegroundColor Red
        exit 32
    }

}

####################################################################################
elseif ($resolvedType -eq 'tomcat') {

    function Test-TomcatHome {
        param([Parameter(Mandatory = $true)][string]$Path)
        if (-not (Test-Path $Path)) { return $false }
        $it = Get-Item $Path -ErrorAction SilentlyContinue
        if (-not $it -or -not $it.PSIsContainer) { return $false }
        return (Test-Path (Join-Path $Path "bin\catalina.bat"))
    }

    function Find-TomcatArtifacts {
        param([Parameter(Mandatory = $true)][string]$Version,
            [string[]]$SearchRoots = @("C:\DBA"))
        $esc = [regex]::Escape($Version)
        Get-ChildItem -Path $SearchRoots -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match $esc -and ( $_.PSIsContainer -or $_.Name -match '\.(zip|tar\.gz|tgz)$' ) }
    }

    function Expand-ArchiveSmart {
        param([Parameter(Mandatory = $true)][string]$ArchivePath,
            [Parameter(Mandatory = $true)][string]$Destination)
        $ext = [IO.Path]::GetExtension($ArchivePath).ToLowerInvariant()
        $isTarGz = $ArchivePath.ToLowerInvariant().EndsWith(".tar.gz")
        if ($ext -eq ".zip") {
            if (-not (Test-Path $Destination)) { New-Item -ItemType Directory -Path $Destination | Out-Null }
            Expand-Archive -Path $ArchivePath -DestinationPath $Destination -Force
            return
        }
        elseif ($isTarGz -or $ext -eq ".tar" -or $ext -eq ".tgz") {
            $tar = Get-Command tar -ErrorAction SilentlyContinue
            if (-not $tar) { throw "No 'tar' found – cannot unpack '$ArchivePath'." }
            if (-not (Test-Path $Destination)) { New-Item -ItemType Directory -Path $Destination | Out-Null }
            & $tar.Source -xzf $ArchivePath -C $Destination
            return
        }
        else { throw "Unsupported archive format: $ArchivePath" }
    }

    function Ensure-TomcatReady {
        param([Parameter(Mandatory = $true)][string]$Version,
            [string[]]$SearchRoots = @("C:\DBA"),
            [string]$TargetRoot = "C:\DBA\apache\JTC")
        $target = Join-Path $TargetRoot $Version
        if (Test-TomcatHome -Path $target) { return $target }
        $hits = Find-TomcatArtifacts -Version $Version -SearchRoots $SearchRoots
        if (-not $hits) { throw "Tomcat version '$Version' not found at: $($SearchRoots -join ', ')" }
        foreach ($h in $hits) {
            if ($h.PSIsContainer -and (Test-TomcatHome -Path $h.FullName)) {
                if (-not (Test-Path $TargetRoot)) { New-Item -ItemType Directory -Path $TargetRoot | Out-Null }
                if (Test-Path $target) { Remove-Item -Recurse -Force $target }
                Move-Item -Path $h.FullName -Destination $target
                return $target
            }
        }
        $archive = $hits | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
        if (-not $archive) { throw "No unpacked Tomcat home and no archive for '$Version' found." }
        $parent = Split-Path -Parent $archive.FullName
        $tmp = Join-Path $parent ("__extract_" + [IO.Path]::GetFileNameWithoutExtension($archive.Name))
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
        Expand-ArchiveSmart -ArchivePath $archive.FullName -Destination $tmp
        $candidates = @($tmp) + (Get-ChildItem -Path $tmp -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        $tchome = $null; foreach ($p in $candidates) { if (Test-TomcatHome -Path $p) { $tchome = $p; break } }
        if (-not $tchome) { throw "Archive unpacked, but no valid Tomcat home found under '$tmp'." }
        if (-not (Test-Path $TargetRoot)) { New-Item -ItemType Directory -Path $TargetRoot | Out-Null }
        if (Test-Path $target) { Remove-Item -Recurse -Force $target }
        Move-Item -Path $tchome -Destination $target
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
        if (Test-Path $archive.FullName) { Remove-Item -Force $archive.FullName }
        if (-not (Test-TomcatHome -Path $target)) { throw "After normalization, no valid Tomcat home in '$target'." }
        return $target
    }

    function Update-TomcatSenvBlock {
        param(
            [Parameter(Mandatory = $true)][string]$FilePath,
            [Parameter(Mandatory = $true)][string]$ComponentName,
            [Parameter(Mandatory = $true)][string]$NewTomcatVersion,
            [Parameter(Mandatory = $true)][string]$TargetRoot
        )

        if (-not (Test-Path $FilePath)) { throw "File not found: $FilePath" }

        $lines = Get-Content -Path $FilePath
        $start = ($lines | ForEach-Object { $_.Trim() }).IndexOf("[$ComponentName]")
        if ($start -lt 0) { throw "Block [$ComponentName] not found." }

        $end = $start + 1
        while ($end -lt $lines.Count -and $lines[$end] -notmatch '^\s*\[.+\]\s*$') { $end++ }

    
        $verParts = $NewTomcatVersion.Split('.')
        $major = $verParts[0]                        
        $majorMinor = ($verParts[0..1] -join '.')        
        $subvers = if ($NewTomcatVersion -match '^\d+\.(.+)$') { $Matches[1] } else { $NewTomcatVersion }
        $catalinaHome = Join-Path $TargetRoot $NewTomcatVersion

        $block = $lines[($start + 1)..($end - 1)]

    
        $patSub = '^\s*SET\s+set\s+TOMCAT_SUBVERS\s*='
        $patCat = '^\s*SET\s+set\s+CATALINA_HOME\s*='
        $patStop = '^\s*SET\s+set\s+TOMCAT_STOP_CMD\s*='
        $patInc = '^\s*INC\s+tomcat_\d+\s*$'

        $foundSub = $false; $foundCat = $false; $foundStop = $false; $foundInc = $false

        for ($i = 0; $i -lt $block.Count; $i++) {
            if ($block[$i] -match $patSub) { $block[$i] = "SET set TOMCAT_SUBVERS=$subvers"; $foundSub = $true; continue }
            if ($block[$i] -match $patCat) { $block[$i] = "SET set CATALINA_HOME=$catalinaHome"; $foundCat = $true; continue }
            if ($block[$i] -match $patStop) { 
                $block[$i] = "SET set TOMCAT_STOP_CMD=%CATALINA_HOME%/bin/tomcat$major.exe //SS//%SRV_SID%"
                $foundStop = $true
                continue
            }
            if ($block[$i] -match $patInc) { $block[$i] = "INC tomcat_$major"; $foundInc = $true; continue }
        }

        if (-not $foundSub) { $block = @("SET set TOMCAT_SUBVERS=$subvers") + $block }
        if (-not $foundCat) { $block = @("SET set CATALINA_HOME=$catalinaHome") + $block }
        if (-not $foundStop) { $block = @("SET set TOMCAT_STOP_CMD=%CATALINA_HOME%/bin/tomcat$major.exe //SS//%SRV_SID%") + $block }
        if (-not $foundInc) { $block = @("INC tomcat_$major") + $block }

    
        $newContent = @()
        if ($start -gt 0) { $newContent += $lines[0..$start] } else { $newContent += $lines[0] }
        $newContent += $block
        if ($end -lt $lines.Count) { $newContent += $lines[$end..($lines.Count - 1)] }

        Set-Content -Path $FilePath -Value $newContent -Encoding UTF8
        return ($block -join [Environment]::NewLine)
    }


    function Update-TomcatServiceVersion {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)] [string]$ServiceName,   
            [Parameter(Mandatory = $true)] [string]$NewTomcatVersion,    
            [string]$JtcRoot = 'C:\DBA\apache\JTC',
            [string]$OldVersion = $null
        )

        $svcRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        if (-not (Test-Path $svcRoot)) { throw "Service not found: $svcRoot" }

        $procrunRoots = @(
            "HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0\$ServiceName",
            "HKLM:\SOFTWARE\Wow6432Node\Apache Software Foundation\Procrun 2.0\$ServiceName"
        )
        $procrun = $procrunRoots | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $procrun) { throw "Procrun key for '$ServiceName' not found." }

        $parts = $NewTomcatVersion.Split('.')
        $major = $parts[0]                
        $majorMinor = ($parts[0..1] -join '.') 

        if (-not $OldVersion) {
            $rx = [regex]"\\JTC\\(?<ver>\d+(?:\.\d+){1,2})\\"
            $cand = @()
            $img = (Get-ItemProperty -Path $svcRoot -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
            if ($img) { $cand += $img }
            foreach ($sub in 'Java', 'Jvm', 'Start', 'Stop', 'Log') {
                $k = Join-Path $procrun "Parameters\$sub"
                if (Test-Path $k) {
                    (Get-ItemProperty -Path $k).PSObject.Properties | ForEach-Object { $cand += $_.Value }
                }
            }
            foreach ($c in $cand) { $s = [string]$c; if ($rx.IsMatch($s)) { $OldVersion = $rx.Match($s).Groups['ver'].Value; break } }
            if (-not $OldVersion) { throw "Old version cannot be determined – please specify -OldVersion." }
        }

        function _Swap([object]$val, [string]$fromVer, [string]$toVer, [string]$root) {
            $from = [regex]::Escape((Join-Path $root $fromVer)) + '(?=\\)'
            $to = (Join-Path $root $toVer)
            switch ($val.GetType().Name) {
                'String' { return ([string]$val) -replace $from, $to }
                'String[]' { return @($val | ForEach-Object { ($_ -replace $from, $to) }) }
                default { return $val }
            }
        }

        $newImagePath = "$JtcRoot\$NewTomcatVersion\bin\Tomcat$major.exe //RS//$ServiceName"
        Set-ItemProperty -Path $svcRoot -Name ImagePath -Value $newImagePath

        Set-ItemProperty -Path $svcRoot -Name DisplayName -Value "Apache Tomcat $majorMinor $ServiceName"
        Set-ItemProperty -Path $svcRoot -Name Description -Value "Apache Tomcat $NewTomcatVersion Server - https://tomcat.apache.org/"

        $javaKey = Join-Path $procrun "Parameters\Java"
        if (Test-Path $javaKey) {
            $javaProps = Get-ItemProperty -Path $javaKey

            if ($null -ne $javaProps.Options) {
                $opts = [string[]]$javaProps.Options
                $opts = $opts | ForEach-Object {
                    $_ = _Swap $_ $OldVersion $NewTomcatVersion $JtcRoot
                    $_ = $_ -replace "(?i)(-Dcatalina\.home=).*$", "`$1$JtcRoot\$NewTomcatVersion"
                    $_ = $_ -replace "(?i)(-Dcatalina\.base=).*$", "`$1$JtcRoot\$NewTomcatVersion"
                    $_
                }
                Set-ItemProperty -Path $javaKey -Name Options -Value $opts
            }

            foreach ($name in 'Classpath', 'ClassPath', 'LibraryPath') {
                if ($null -ne (Get-ItemProperty -Path $javaKey -Name $name -ErrorAction SilentlyContinue).$name) {
                    $val = (Get-ItemProperty -Path $javaKey -Name $name).$name
                    $val = _Swap $val $OldVersion $NewTomcatVersion $JtcRoot
                    Set-ItemProperty -Path $javaKey -Name $name -Value $val
                }
            }
        }

        foreach ($sub in 'Start', 'Stop') {
            $k = Join-Path $procrun "Parameters\$sub"
            if (Test-Path $k) {
                Set-ItemProperty -Path $k -Name WorkingPath -Value "$JtcRoot\$NewTomcatVersion" -ErrorAction SilentlyContinue
                $p = Get-ItemProperty -Path $k
                foreach ($prop in $p.PSObject.Properties) {
                    $newVal = _Swap $prop.Value $OldVersion $NewTomcatVersion $JtcRoot
                    if ($null -ne $prop.Value -and $newVal -ne $prop.Value) {
                        Set-ItemProperty -Path $k -Name $prop.Name -Value $newVal
                    }
                }
            }
        }
        $logKey = Join-Path $procrun "Parameters\Log"
        if (Test-Path $logKey) {
            $p = Get-ItemProperty -Path $logKey
            foreach ($prop in $p.PSObject.Properties) {
                $newVal = _Swap $prop.Value $OldVersion $NewTomcatVersion $JtcRoot
                if ($null -ne $prop.Value -and $newVal -ne $prop.Value) {
                    Set-ItemProperty -Path $logKey -Name $prop.Name -Value $newVal
                }
            }
        }
  
        Write-Host "Registry updated (ImagePath, DisplayName, Description, Java.Options, Start/Stop WorkingPath, Paths in Parameters)."
    }

    try {
        $TomcatHome = Ensure-TomcatReady -Version $NewTomcatVersion -SearchRoots @("C:\DBA", "C:\DBA\apache\JTC") -TargetRoot "C:\DBA\apache\JTC"
        Write-Host "Tomcat home ready at: $TomcatHome"

        $tomcatSenv = Join-Path $SenvFolder 'tomcat.senv'
        $updatedBlock = Update-TomcatSenvBlock -FilePath $tomcatSenv -ComponentName $ComponentName -NewTomcatVersion $NewTomcatVersion -TargetRoot 'C:\DBA\apache\JTC'
        Write-Host "`n--- Updated block ---"
        Write-Host $updatedBlock

        Update-TomcatServiceVersion -ServiceName $serviceName -NewTomcatVersion $NewTomcatVersion
    }
    catch {
        $rc = 23
        Write-Host ((Get-Date -Format s) + " - VERROR : $($_.Exception.Message)")
        Write-Host ((Get-Date -Format s) + " - VRETURNCODE : $rc")
        exit $rc
    }
}

###########################bemb004#######################################
if ($resolvedType -eq 'tomcat') {

    try {
        sc.exe delete $ComponentName
        Start-Sleep -Seconds 5
        $serviceCheck = sc.exe query $ComponentName
        if ($LASTEXITCODE -eq 0) {
            sc.exe delete $ComponentName
            Start-Sleep -Seconds 5
            sc.exe query $ComponentName
            if ($LASTEXITCODE -eq 0) {
                throw "The $ComponentName service could not be deleted."
            }
        }
        Write-Host "Service $ComponentName successfully deleted."
    }
    catch {
        Write-Host "VERROR: $_"
        exit 22
    }

    $serviceName = $ComponentName 

    $wshell = New-Object -ComObject WScript.Shell 

    $sessionDir = "C:\DBA\nest\senv" 
 

    if (-not (Test-Path $sessionDir)) { 

        $rc = 10 

        $msg = "Session directory '$sessionDir' not found." 

        Write-Host ((Get-Date -format s) + " - VERROR : $msg") 

        Write-Host ((Get-Date -format s) + " - VRETURNCODE : $rc") 

        exit $rc 

    } 

    $cmd = @"
@echo off
set "SENV_HOME=C:\DBA\nest\senv"
call "%SENV_HOME%\senv_profile.cmd"
timeout /t 30 /nobreak >nul
call "%SENV_HOME%\senv.cmd" $resolvedType $ComponentName
timeout /t 30 /nobreak >nul
if %errorlevel% neq 0 (
  echo Error when calling senv.cmd
  rem no exit here, so that the window remains open
)
rem calls  ...
call C:\DBA\apache\JTC\$NewTomcatVersion\bin\service.bat install $ComponentName
timeout /t 30 /nobreak >nul
echo.
echo Done. This window will close automatically in 30 seconds....
timeout /t 30 /nobreak >nul
exit
"@

    $cmdPath = "C:\TEMP\disable_component_$ComponentName.cmd"
    Set-Content -Path $cmdPath -Value $cmd -Encoding ASCII

    Start-Process -FilePath "cmd.exe" -ArgumentList "/k `"$cmdPath`"" -WorkingDirectory "C:\DBA\nest\senv"

    Write-Host "`nWait 4 minutes before checking the status..." -ForegroundColor Yellow
    Start-Sleep -Seconds 240
    
    $newResult = Find-ComponentInSenv -ComponentName $ComponentName -ComponentType $resolvedType -SenvFolder $SenvFolder
    if ($null -ne $newResult) {
        Write-Host "`n--- New block (after update) ---"
        Write-Host $newResult.Block
    }
    else {
        Write-Host "New block [$ComponentName] could not be read from apache.senv."
    }  

    $service = Get-Service -Name $ComponentName -ErrorAction SilentlyContinue
    $success = $false
    $currentVersion = $null

    if ($service -and $service.Status -eq 'Running') {
        try {
        
            $svcRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\$ComponentName"
            $imgPath = (Get-ItemProperty -Path $svcRoot -Name ImagePath -ErrorAction Stop).ImagePath
            if ($imgPath -match "\\JTC\\(?<ver>[\d\.]+)\\") {
                $currentVersion = $Matches['ver']
                if ($currentVersion -eq $NewTomcatVersion) {
                    $success = $true
                }
            }
        }
        catch {
            Write-Host "Could not determine current version from registry: $($_.Exception.Message)"
        }
    }

    if ($success) {
        Write-Host "`n Component '$ComponentName' runs successfully with the new version." -ForegroundColor Green
    }
    else {
        Write-Host "`n Update of '$ComponentName' unsuccessful: " -ForegroundColor Red
        if ($service) {
            Write-Host "   service status : $($service.Status)"
            if ($currentVersion) {
                Write-Host "   Current version: $currentVersion is not the updated version"
            }
            else {
                Write-Host "   Version could not be determined."
            }
        }
        else {
            Write-Host "   Service no longer exists."
        }
    }
}
Stop-Transcript
Write-Host "Log written to $logFile"