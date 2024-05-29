param(
    [switch]$force,
    [switch]$skip_hash_check,
    [string]$lang = "en-GB",
    [string]$version
)

function Is-Admin() {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Enforce-Tls() {
    try {
        # not available on Windows 7 by default
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls2
    } catch {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls
        } catch {
            # ignore
        }
    }
}

function Fetch-SHA512($source, $fileName) {
    $response = Invoke-WebRequest $source -UseBasicParsing

    $data = $response.Content.split("`n")

    foreach ($line in $data) {
        $splitLine = $line.Split(" ", 2)
        $hash = $splitLine[0]
        $currentFileName = $splitLine[1].Trim()

        if ($null -ne $hash -and $null -ne $currentFileName) {
            if ($currentFileName -eq $fileName) {
                return $hash
            }
        }
    }
    return $null
}

function main() {
    if (-not (Is-Admin)) {
        Write-Host "error: administrator privileges required"
        return 1
    }

    # disable progress bar
    # https://github.com/PowerShell/PowerShell/issues/2138
    $ProgressPreference = 'SilentlyContinue'

    # silently try to enforce Tls
    Enforce-Tls

    try {
        $response = Invoke-WebRequest "https://product-details.mozilla.org/1.0/firefox_versions.json" -UseBasicParsing
    } catch [System.Net.WebException] {
        Write-Host "error: failed to fetch json data, check internet connection and try again"
        return 1
    }

    $firefoxVersions = ConvertFrom-Json $response.Content
    $setupFile = "$($env:TEMP)\FirefoxSetup.exe"
    $remoteVersion = if ($version) { $version } else { $firefoxVersions.LATEST_FIREFOX_VERSION }
    $downloadUrl = "https://releases.mozilla.org/pub/firefox/releases/$($remoteVersion)/win64/$($lang)/Firefox%20Setup%20$($remoteVersion).exe"
    $installDir = "C:\Program Files\Mozilla Firefox"
    $hashSource = "https://ftp.mozilla.org/pub/firefox/releases/$($remoteVersion)/SHA512SUMS"

    # check if currently installed version is already latest
    if (Test-Path "$($installDir)\firefox.exe") {
        $localVersion = (Get-Item "$($installDir)\firefox.exe").VersionInfo.ProductVersion

        if ($localVersion -eq $remoteVersion) {
            Write-Host "info: Mozilla Firefox $($remoteVersion) already installed"

            if ($force) {
                Write-Host "warning: -force specified, proceeding anyway"
            } else {
                return 1
            }
        }
    }

    Write-Host "info: downloading firefox $($remoteVersion) setup"
    Invoke-WebRequest $downloadUrl -OutFile $setupFile

    if (-not (Test-Path $setupFile)) {
        Write-Host "error: failed to download setup file"
        return 1
    }

    if (-not $skip_hash_check) {
        Write-Host "info: checking SHA512"
        $localSHA512 = (Get-FileHash -Path $setupFile -Algorithm SHA512).Hash
        $remoteSHA512 = Fetch-SHA512 -source $hashSource -fileName "win64/$($lang)/Firefox Setup $($remoteVersion).exe"

        if ($null -eq $remoteSHA512) {
            Write-Host "error: unable to find hash"
            return 1
        }

        if ($localSHA512 -ne $remoteSHA512) {
            Write-Host "error: hash mismatch"
            return 1
        }
    }

    Write-Host "info: installing firefox"

    # close firefox if it is running
    Stop-Process -Name "firefox" -ErrorAction SilentlyContinue

    # start installation
    Start-Process -FilePath $setupFile -ArgumentList "/S /MaintenanceService=false" -Wait

    # remove installer binary
    Remove-Item $setupFile -Force

    $removeFiles = @(
        "crashreporter.exe",
        "crashreporter.ini",
        "defaultagent.ini",
        "defaultagent_localized.ini",
        "default-browser-agent.exe",
        "maintenanceservice.exe",
        "maintenanceservice_installer.exe",
        "pingsender.exe",
        "updater.exe",
        "updater.ini",
        "update-settings.ini"
    )

    # remove files
    foreach ($file in $removeFiles) {
        $file = "$($installDir)\$($file)"
        if (Test-Path $file) {
            Remove-Item $file -Force
        }
    }

    $policiesContent = @{
        policies = @{
            DisableAppUpdate     = $true
            OverrideFirstRunPage = ""
            Extensions           = @{
                Install = @(
                    "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/11423598-latest.xpi",
                    "https://addons.mozilla.org/firefox/downloads/latest/fastforwardteam/17032224-latest.xpi",
                    "https://addons.mozilla.org/firefox/downloads/latest/clearurls/13196993-latest.xpi"
                )
            }
        }
    }

    $autoconfigContent = @(
        "pref(`"general.config.filename`", `"firefox.cfg`");",
        "pref(`"general.config.obscure_value`", 0);"
    ) -join "`n"

    $firefoxConfigContent =
    "`r`ndefaultPref(`"app.shield.optoutstudies.enabled`", false)`
defaultPref(`"datareporting.healthreport.uploadEnabled`", false)`
defaultPref(`"browser.newtabpage.activity-stream.feeds.section.topstories`", false)`
defaultPref(`"browser.newtabpage.activity-stream.feeds.topsites`", false)`
defaultPref(`"dom.security.https_only_mode`", true)`
defaultPref(`"browser.uidensity`", 1)`
defaultPref(`"full-screen-api.transition-duration.enter`", `"0 0`")`
defaultPref(`"full-screen-api.transition-duration.leave`", `"0 0`")`
defaultPref(`"full-screen-api.warning.timeout`", 0)`
defaultPref(`"nglayout.enable_drag_images`", false)`
defaultPref(`"reader.parse-on-load.enabled`", false)`
defaultPref(`"browser.tabs.firefox-view`", false)`
defaultPref(`"browser.tabs.tabmanager.enabled`", false)`
lockPref(`"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons`", false)`
lockPref(`"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features`", false)"

    # create "distribution" folder for policies.json
    (New-Item -Path "$($installDir)" -Name "distribution" -ItemType "directory" -Force) 2>&1 > $null
    # write to policies.json
    Set-Content -Path "$($installDir)\distribution\policies.json" -Value (ConvertTo-Json -InputObject $policiesContent -Depth 10)

    # write to autoconfig.js
    Set-Content -Path "$($installDir)\defaults\pref\autoconfig.js" -Value $autoconfigContent

    # write to firefox.cfg
    Set-Content -Path "$($installDir)\firefox.cfg" -Value $firefoxConfigContent

    Write-Host "info: release notes: https:/www.mozilla.org/en-US/firefox/$($remoteVersion)/releasenotes"

    return 0
}

$_exitCode = main
Write-Host # new line
exit $_exitCode