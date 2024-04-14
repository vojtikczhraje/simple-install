# Default settings
param (
    [switch]$WindowsUpdate = $false,
    [switch]$WindowsActivation = $true,
    [switch]$WindowsFeatures = $true,
    [switch]$VisualCppRedistributable = $true,
    [switch]$InstallApplications = $true,
    [switch]$InstallFirefox = $true,
    [switch]$RemoveBloatApplications = $true,
    [switch]$DisableServices = $true,
    [switch]$PowerSettings = $true,
    [switch]$BootSettings = $true,
    [switch]$RegistrySettings = $true,
    [switch]$DisableScheduledTasks = $true,
    [switch]$TaskbarSettings = $false,   
    [switch]$DisableMitigations = $true,
    [switch]$MemoryCompression = $true,
    [switch]$RemoveEdge = $false,
    [switch]$RemoveOneDrive = $true,
    [string]$tempFile = "C:\temp",
    [string]$configFile = "C:\config.ini"
)


# Define a function to parse the configuration file
function Parse-ConfigFile {
    param (
        [string]$ConfigPath
    )
    
    $configSettings = @{}
    if (Test-Path $ConfigPath) {
        $configLines = Get-Content $ConfigPath
        foreach ($line in $configLines) {
            if ($line -match '^\s*([^#]+?)\s*=\s*(.*?)\s*$') {
                $configSettings[$matches[1]] = $matches[2]
            }
        }
    }
    return $configSettings
}

# Read settings from the configuration file
$configSettings = Parse-ConfigFile -ConfigPath $configFile

# Override default parameters with settings from the configuration file
foreach ($setting in $configSettings.GetEnumerator()) {
    switch ($setting.Key) {
        "WindowsUpdate" { $WindowsUpdate = [convert]::ToBoolean($setting.Value) }
        "WindowsActivation" { $WindowsActivation = [convert]::ToBoolean($setting.Value) }
        "WindowsFeatures" { $WindowsFeatures = [convert]::ToBoolean($setting.Value) }
        "VisualCppRedistributable" { $VisualCppRedistributable = [convert]::ToBoolean($setting.Value) }
        "InstallApplications" { $InstallApplications = [convert]::ToBoolean($setting.Value) }
        "InstallFirefox" { $InstallFirefox = [convert]::ToBoolean($setting.Value) }
        "RemoveBloatApplications" { $RemoveBloatApplications = [convert]::ToBoolean($setting.Value) }
        "DisableServices" { $DisableServices = [convert]::ToBoolean($setting.Value) }
        "PowerSettings" { $PowerSettings = [convert]::ToBoolean($setting.Value) }
        "BootSettings" { $BootSettings = [convert]::ToBoolean($setting.Value) }
        "RegistrySettings" { $RegistrySettings = [convert]::ToBoolean($setting.Value) }
        "DisableScheduledTasks" { $DisableScheduledTasks = [convert]::ToBoolean($setting.Value) }
        "TaskbarSettings" { $TaskbarSettings = [convert]::ToBoolean($setting.Value) }
        "DisableMitigations" { $DisableMitigations = [convert]::ToBoolean($setting.Value) }
        "MemoryCompression" { $MemoryCompression = [convert]::ToBoolean($setting.Value) }
        default { Write-Output "Unknown setting: $($_)" }
    }
}


# Run as Administrator check
function Admin-Check {
    If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "error: Script is not runned as administrator"
        Break
    }
    
}

# Ensure the C:\temp directory is cleaned up and recreated
function Create-TempFolder{
    if (Test-Path -Path $tempFile) {
        Remove-Item -Path $tempFile -Force -Recurse -Confirm:$false | Out-Null
    }
    New-Item -Path $tempFile -ItemType Directory | Out-Null

}

# Needed to get the Windows Update PS Module
function Install-NuGET {
    Install-PackageProvider -Name NuGet -Force | Out-Null
}

# Install Windows Updates
function Install-WindowsUpdates {

    try {
        Write-Output "info: Running Windows Update"
	
        # Windows Update PS Module
        Install-Module -Name PSWindowsUpdate -Force | Out-Null
    
        # Get all Updates
        Get-WindowsUpdate -Confirm -AcceptAll | Out-Null
    
        # Do all upgrades
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Confirm -IgnoreReboot | Out-Null
    }
    catch {
        # Attempt to catch an error (doesn't work :))
        Write-Output "error with updating windows"
    }

}

# Install Windows Features (example: .NET Framework 3.5)
function Windows-features {
    Write-Output "info: Installing Windows features..."
    Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All | Out-Null
}

# Install Visual C++ Redistributable
function Install-VisualCppRedistributable {
    Write-Output "info: Installing Visual C++ Redistributable." 
    $url = "https://github.com/abbodi1406/vcredist/releases/download/v0.79.0/VisualCppRedist_AIO_x86_x64.exe"
    
    # Use a predefined temporary directory path
    $fileName = "VisualCppRedist_AIO_x86_x64.exe"
    $path = Join-Path -Path $tempFile -ChildPath $fileName

    # Add -UseBasicParsing to work on systems without IE or with IE not fully configured
    Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing | Out-Null

    # Now that $path is correctly defined, Start-Process should work without issues
    Start-Process -FilePath $path -ArgumentList "/ai /gm2" -Wait
}
function Activate-Windows {
    Write-Output "info: Activating windows." 

    $url = "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/assets/HWID_Activation.cmd"
    $fileName = "hwid_activation.cmd"
    $path = Join-Path -Path $tempFile -ChildPath $fileName
    
    Try {
        # Download the file
        $content = Invoke-RestMethod -Uri $url -ErrorAction Stop
        $content | Out-File -FilePath $path -Encoding UTF8

        # Verify the file is downloaded and has content
        if ((Test-Path -Path $path) -and ((Get-Content -Path $path).Length -gt 0)) {
            Write-Output "info: $fileName downloaded successfully."
        } else {
            Write-Error "error: $fileName file is empty or missing."
        }

        # Run file -WindowStyle Minimized
        Start-Process "cmd.exe" -ArgumentList "/c `"$path`"" -WindowStyle Minimized
    }
    Catch {
        Write-Error "error: An error occurred while trying to download $fileName. $_"
    }
    
}

# Install scoop(package manager), apps
function apps {
    $scoopInstalled = Test-Path -Path "$env:USERPROFILE\scoop"
    if ($scoopInstalled) {
        Write-Output "info: Scoop is already installed."
    } else {
        Write-Output "info: Scoop is not installed, installing now..."
    
        iex "& {$(irm get.scoop.sh)} -RunAsAdmin"
    
        # Update the check for Scoop installation after the installation attempt
        $scoopInstalled = Test-Path -Path "$env:USERPROFILE\scoop"
    
        if ($scoopInstalled) {
            Write-Output "info: Scoop has been successfully installed."
        } else {
            Write-Output "info: Scoop installation failed."
            # Exit the script if Scoop couldn't be installed
            exit
        }
    }

    $scoopInstalled = Test-Path -Path "$env:USERPROFILE\scoop"
    if($scoopInstalled){
        # Configure repositories
        scoop bucket add main
    
        # Development tools
        Write-Output "info: Installing development tools..."
        scoop install main/git
        scoop install main/python
        scoop install main/nodejs
        scoop install main/mingw
        scoop install main/7zip
    
    
        Write-Output "info: Applications installation completed."
    }
}

# Install firefox
function firefox {
    Write-Output "info: Installing firefox." 
    $scriptCommand = "irm https://raw.githubusercontent.com/amitxv/firefox/main/setup.ps1 | iex"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $scriptCommand -Wait 
}

function Remove-Apps {
    param (
        [string[]]$AppList
    )

    Write-Output "info: Removing unwatend Apps"

    foreach($App in $AppList) {
        Get-AppxPackage "*$App*" | Remove-AppxPackage -AllUsers -ErrorAction 'SilentlyContinue' | Out-Null
        Write-Output "Removing: $App" 
    }
}

# Disable windows bloat services
 function Disable-Services {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ServiceNames
    )

    foreach ($service in $ServiceNames) {
        $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceObj) {
            Write-Output "disabling service: $service"
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Service $service not found."
        }
    }

    Write-Output "All specified services have been set to disabled."
}

# Configure power settings
function Power-Settings {
    # Set High Performance profile
    powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    
    # Disable monitor timeout
    powercfg.exe /change monitor-timeout-ac 0
    powercfg.exe /change monitor-timeout-dc 0

    # Disable standby timeout
    powercfg.exe /change standby-timeout-ac 0
    powercfg.exe /change standby-timeout-dc 0

    # Disable hibernate timeout
    powercfg.exe /change hibernate-timeout-ac 0
    powercfg.exe /change hibernate-timeout-dc 0

    # Disable hibernate
    powercfg.exe /hibernate off

    Write-Output "info: Power settings has been configured." 
}

# Configure the BCD store
function BCD-settings {
    #  Disables boot graphics.
    bcdedit /set bootux disabled | Out-Null

    # Set Boot Menu to Standard Instead Of Legacy
    bcdedit /set bootmenupolicy standard | Out-Null
    
    # Enable Quietboot
    bcdedit /set quietboot yes | Out-Null

    # Avoid the use of uncontiguous portions of low-memory from the OS
    bcdedit /set firstmegabytepolicy UseAll | Out-Null
    bcdedit /set avoidlowmemory 0x8000000 | Out-Null
    bcdedit /set nolowmem Yes | Out-Null

    # Disable Some Kernel Memory Mitigations
    bcdedit /set allowedinmemorysettings 0x0 | Out-Null
    bcdedit /set isolatedcontext No | Out-Null
 
    # Disable DMA Memory Protection And Cores Isolation
    bcdedit /set vsmlaunchtype Off | Out-Null
    bcdedit /set vm No | Out-Null

    # Enable X2Apic And Enable Memory Mapping
    bcdedit /set x2apicpolicy Enable | Out-Null
    bcdedit /set configaccesspolicy Default | Out-Null
    bcdedit /set MSI Default | Out-Null
    bcdedit /set usephysicaldestination No | Out-Null
    bcdedit /set usefirmwarepcisettings No | Out-Null
    
    Write-Output "info: BCD settings has been configured." 
}

# Create settings.reg and apply it (
function Apply-RegistrySettings {
    param (
        [string]$RegFilePath
    )

    # Define the content of the .reg file
    $regFileContent = @"
Windows Registry Editor Version 5.00

; disable windows update

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
"WUServer"=" "
"WUStatusServer"=" "
"UpdateServiceUrlAlternate"=" "
"DisableWindowsUpdateAccess"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU]
"NoAutoUpdate"=dword:00000001
"UseWUServer"=dword:00000001
"AUOptions"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching]
"SearchOrderConfig"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata]
"PreventDeviceMetadataFromNetwork"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DriverSearching]
"SearchOrderConfig"=dword:00000000
"DontSearchWindowsUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update]
"IncludeRecommendedUpdates"=dword:00000000
"SetupWizardLaunchTime"=-
"AcceleratedInstallRequired"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings]
"ExcludeWUDriversInQualityUpdate"=dword:00000001

; disable windows visual stuff

[HKEY_CURRENT_USER\Control Panel\Desktop]
"UserPreferencesMask"=hex:90,32,07,80,12,00,00,00
"MinAnimate"="0"
"MenuShowDelay"="0"
"TooltipAnimation"="0"
"MouseHoverTime"="0"
"DragFullWindows"="0"
"FontSmoothing"="2"
"FontSmoothingType"="2"
"FontSmoothingGamma"="1000"
"FontSmoothingOrientation"="1"

[HKEY_CURRENT_USER\Control Panel\Desktop]
"MenuShowDelay"="0"

; disable UAC

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLUA"=dword:00000000

; disable automatic maintenance

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance]
"MaintenanceDisabled"=dword:00000001

; allocate processor resources primarily to programs

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000026

; prevent windows marking file attachments with information about their zone of origin

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments]
"SaveZoneInformation"=dword:00000001

; disable search indexing

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch]
"Start"=dword:00000004

; disable program compatibility assistant

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\AppCompat]
"DisablePCA"=dword:00000001

; disable customer experience improvement program

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient\Windows]
"CEIPEnable"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows]
"CEIPEnable"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM]
"OptIn"=dword:00000000

; disable fault tolerant heap
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTH]
"Enabled"=dword:00000000

; disable sticky keys

[HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys]
"Flags"="506"

; disable windows defender

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableAntiSpyware"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection]
"DisableScanOnRealtimeEnable"=dword:00000001
"DisableOnAccessProtection"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"DisableScanOnRealtimeEnable"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]
"Start"=dword:00000004

; disable powershell telemetry

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment]
"POWERSHELL_TELEMETRY_OPTOUT"="1"

; disable pointer acceleration

[HKEY_CURRENT_USER\Control Panel\Mouse]
"MouseSpeed"="0"
"MouseThreshold1"="0"
"MouseThreshold2"="0"

; disable hibernation

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"HibernateEnabled"=dword:00000000

; disable fast startup

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"HiberbootEnabled"=dword:00000000

; disable windows error reporting

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting]
"DoReport"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting]
"Disabled"=dword:00000001

; reserve 10% of CPU resources for low-priority tasks instead of the default 20%

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"SystemResponsiveness"=dword:0000000a

; disable Remote assistance

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance]
"fAllowToGetHelp"=dword:00000000

; show file extensions

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"HideFileExt"=dword:00000000

Windows Registry Editor Version 5.00

; disable windows update

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
"DoNotConnectToWindowsUpdateInternetLocations"=dword:00000001
"DisableOSUpgrade"=dword:00000001

; disable windows defender

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"DisableBehaviorMonitoring"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv]
"Start"=dword:00000004

; disable search the web or display web results in Search

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]
"ConnectedSearchUseWeb"=dword:00000000

; disable notifications network usage

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications]
"NoCloudApplicationNotification"=dword:00000001

Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}]
"System.IsPinnedToNameSpaceTree"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Classes\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}]
"System.IsPinnedToNameSpaceTree"=dword:00000000

; disable windows update

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
"ExcludeWUDriversInQualityUpdate"=dword:00000001
"SetDisableUXWUAccess"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc]
"Start"=dword:00000004

; disable sign-in and lock last interactive user after a restart

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableAutomaticRestartSignOn"=dword:00000001

; disable windows defender

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet]
"SpyNetReporting"=dword:00000000
"SubmitSamplesConsent"=dword:00000000

; disable gamebarpresencewriter

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter]
"ActivationType"=dword:00000000

; disable telemetry

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection]
"AllowTelemetry"=dword:00000000

; disable retrieval of online tips and help in the immersive control panel

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"AllowOnlineTips"=dword:00000000

; enable the legacy photo viewer

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations]
".tif"="PhotoViewer.FileAssoc.Tiff"
".tiff"="PhotoViewer.FileAssoc.Tiff"
".bmp"="PhotoViewer.FileAssoc.Tiff"
".dib"="PhotoViewer.FileAssoc.Tiff"
".gif"="PhotoViewer.FileAssoc.Tiff"
".jfif"="PhotoViewer.FileAssoc.Tiff"
".jpe"="PhotoViewer.FileAssoc.Tiff"
".jpeg"="PhotoViewer.FileAssoc.Tiff"
".jpg"="PhotoViewer.FileAssoc.Tiff"
".jxr"="PhotoViewer.FileAssoc.Tiff"
".png"="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpg]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpeg]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.gif]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.png]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.bmp]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.tiff]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.ico]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.tif]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.wdp]
@="PhotoViewer.FileAssoc.Wdp"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jfif]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.dib]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jpe]
@="PhotoViewer.FileAssoc.Tiff"

[HKEY_CURRENT_USER\SOFTWARE\Classes\.jxr]
@="PhotoViewer.FileAssoc.Tiff"

; disable typing insights

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\input\Settings]
"InsightsEnabled"=dword:00000000

; disable transparency

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"EnableTransparency"=dword:00000000

Windows Registry Editor Version 5.00

; disable suggestions in the search box and in search home

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings]
"IsDynamicSearchBoxEnabled"=dword:00000000

; restore old context menu

[HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}]
@=""

[HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32]
@=""

; disable activity history

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"ShowRecent"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableActivityFeed"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableActivityFeed"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"PublishUserActivities"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\System]
"PublishUserActivities"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]
"BingSearchEnabled"=dword:00000000
"AllowSearchToUseLocation"=dword:00000000
"CortanaConsent"=dword:00000000

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer]
"DisableSearchBoxSuggestions"=dword:00000001
"HideRecentlyAddedApps"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_TrackDocs"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"NoRecentDocsHistory"=dword:00000001

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"NoRecentDocsHistory"=dword:00000001

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer]
"HideRecentlyAddedApps"=dword:00000001

; Set privacy and search settings
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings]
"AcceptedPrivacyPolicy"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization]
"RestrictImplicitTextCollection"=dword:00000001
"RestrictImplicitInkCollection"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore]
"HarvestContacts"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features]
"WiFiSenseCredShared"=dword:00000000
"WiFiSenseOpen"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings]
"SafeSearchMode"=dword:00000000
"IsMSACloudSearchEnabled"=dword:00000000
"IsAADCloudSearchEnabled"=dword:00000000
"IsDeviceSearchHistoryEnabled"=dword:00000000

[HKEY_CURRENT_USER\Control Panel\International\User Profile]
"HttpAcceptLanguageOptOut"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI]
"DisableMFUTracking"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EdgeUI]
"DisableMFUTracking"=dword:00000001

; realtime csrss

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions]
"CpuPriorityClass"=dword:00000004
"IoPriority"=dword:00000003

; disable spectre meltdown

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"FeatureSettings"=dword:00000001
"FeatureSettingsOverride"=dword:00000003
"FeatureSettingsOverrideMask"=dword:00000003

; disable powerthrottling

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"CoalescingTimerInterval"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"CoalescingTimerInterval"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"CoalescingTimerInterval"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"CoalescingTimerInterval"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive]
"CoalescingTimerInterval"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\ModernSleep]
"CoalescingTimerInterval"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"CoalescingTimerInterval"=dword:00000000
"PlatformAoAcOverride"=dword:00000000
"EnergyEstimationEnabled"=dword:00000000
"EventProcessorEnabled"=dword:00000000
"CsEnabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling]
"PowerThrottlingOff"=dword:00000001

; auto reboot on crash

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl]
"AutoReboot"=dword:00000001

; disable windows tips
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"SubscribedContent-338393Enabled"=dword:00000000

; disable start menu suggestions
"SystemPaneSuggestionsEnabled"=dword:00000000

; disable lock screen suggestions (Ads)
"SubscribedContent-310093Enabled"=dword:00000000
"RotatingLockScreenOverlayEnabled"=dword:00000000
"RotatingLockScreenEnabled"=dword:00000000

; disable advertising id
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo]
"Enabled"=dword:00000000

; disable app suggestions
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent]
"DisableWindowsConsumerFeatures"=dword:00000001

; show hidden files

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Hidden"=dword:00000001
"ShowSuperHidden"=dword:00000001

"@

    # Check if the temporary directory for the .reg file exists, if not, create it
    $tempDir = Split-Path -Path $RegFilePath
    if (-not (Test-Path -Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory | Out-Null
    }

    # Save the content to the .reg file
    $regFileContent | Out-File -FilePath $RegFilePath -Encoding UTF8

    # Execute the .reg file silently
    Start-Process -FilePath "regedit.exe" -ArgumentList "/s `"$RegFilePath`"" -Wait -NoNewWindow

    Write-Output "info: Registry changes have been applied."
}

# Disable scheduled tasks
function Disable-ScheduledTasksByWildcard {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Wildcards
    )

    # Retrieve all scheduled tasks
    $allTasks = Get-ScheduledTask

    foreach ($wildcard in $Wildcards) {
        # Filter tasks by wildcard pattern
        $filteredTasks = $allTasks | Where-Object { $_.TaskName -like "*$wildcard*" }

        if ($filteredTasks.Count -eq 0) {
            <# Write-Host "No tasks match the pattern: $wildcard" #>
            continue
        }

        foreach ($task in $filteredTasks) {
            # Disable each task
            try {
                Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
                <# Write-Host "Successfully disabled task: $($task.TaskName)" #>
            } catch {
                <# Write-Warning "Failed to disable task: $($task.TaskName). Error: $_" #>
            }
        }
    }

    Write-Output "info: Scheduled tasks were succesfully disabled."
}

function taskbar-settings {

    try {
    # Disable Search Bar
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchBoxTaskbarMode" -Value 0 -Type DWord -Force | Out-Null

    # Left Align
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Type DWord -Force | Out-Null


    # Unpin applications from taskbar
    function Unpin-App([string]$appname) {
        ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
            ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt()}
    }
    Unpin-App("Microsoft Edge")
    Unpin-App("Microsoft Store") 
    Unpin-App("Mail") 

    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force | Out-Null
    
    # Dark Mode
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize "-Name "AppsUseLightTheme" -Value 0 -Force | Out-Null

    Write-Output "info: Taskbar have been cleaned"
    }

    catch {
        Write-Output "error: Taskbar was not cleaned correctly"
    }


}

function Disable-ProcessMitigations {
    # Disable process mitigations
    Set-ProcessMitigation -System -Disable CFG | Out-Null

    # Get current mask
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    $regName = "MitigationAuditOptions"
    $mitigationMask = (Get-ItemProperty -Path $regPath -Name $regName).MitigationAuditOptions
    
    # Ensure mitigationMask is a string for replacement operation
    $mitigationMaskStr = [BitConverter]::ToString($mitigationMask).Replace("-", "")

    # Set all values in current mask to 2
    0..9 | ForEach-Object {
        $mitigationMaskStr = $mitigationMaskStr.Replace("$_", "2")
    }

    # Convert the modified string back to byte array
    $modifiedMask = [byte[]] -split ($mitigationMaskStr -replace '..', '0x$& ')
    
    # Apply modified mask to kernel
    Set-ItemProperty -Path $regPath -Name "MitigationOptions" -Value $modifiedMask -Type Binary -Force
    Set-ItemProperty -Path $regPath -Name "MitigationAuditOptions" -Value $modifiedMask -Type Binary -Force
}

function Remove-Edge {
    $edgeUpdatePath = "C:\Program Files (x86)\Microsoft\EdgeUpdate"
    if (Test-Path $edgeUpdatePath) {
        Remove-Item -Path $edgeUpdatePath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "info: EdgeUpdate directory removed."
    } else {
        Write-Output "info: EdgeUpdate directory not found."
    }
    
    # Search for and delete all shortcuts related to Edge across the C: drive
    Get-ChildItem -Path C:\ -Filter *edge.lnk* -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        Write-Output "info: Deleted shortcut: $($_.FullName)"
    }

}

function Remove-OneDrive {
    Write-Output "info: Removing OneDrive"

    # Kill OneDrive process
    taskkill.exe /f /im "OneDrive.exe" | Out-Null
    taskkill.exe /f /im "explorer.exe" | Out-Null

    try {
        if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
            & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall | Out-Null
        }
        if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
            & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall | Out-Null
        }
        
        # Removing OneDrive leftovers
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive" | Out-Null
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive" | Out-Null
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp" | Out-Null
    
        # Check if directory is empty before removing
        If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive" | Out-Null
        }
        
        # info: Disable OneDrive via Group Policies
        New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1 | Out-Null
        
        # Remove Onedrive from explorer sidebar
        New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR" | Out-Null
        New-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force | Out-Null
        New-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force | Out-Null
        Remove-PSDrive "HKCR" | Out-Null
        
        # Removing run hook for new users
        reg load "HKU\Default" "C:\Users\Default\NTUSER.DAT" | Out-Null
        Remove-ItemProperty -Path "HKU:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force | Out-Null
        reg unload "HKU\Default" | Out-Null
        
        # Removing startmenu entry
        Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" | Out-Null
        
        # Removing scheduled task
        Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
        
        # Restarting explorer
        Start-Process "explorer.exe"
    }
    catch {
        Write-Output "info: OneDrive wasn't uninstalled succesfully" 
    }   
}

# All functions are ran in main function 
function Main {
    # Admin check
    Admin-Check

    # Create temp folder
    Create-TempFolder

    # Activate Windows
    if($WindowsActivation) {
        Activate-Windows
    }
    

    # Install Windows update
    if($WindowsUpdate) {
        Install-NuGET
        Install-WindowsUpdates
    }
    

    # Install windows features (NET - Framework 3.5)
    if($WindowsFeatures){
        Windows-features
    }

    # Install Visual C++ Redistributable
    if($VisualCppRedistributable){
        Install-VisualCppRedistributable
    }
 
    # Install package manager and applications
    if($InstallApplications){
        apps
    }

    # Install firefox
    if($InstallFirefox){
        firefox
    }
    

    # Remove bloated apps
    if($RemoveBloatApplications){
        $AppsToRemove = @(
            'Microsoft.3DBuilder',
        	'Microsoft.Microsoft3DViewer',
        	'Microsoft.Print3D',
        	'Microsoft.Appconnector',
        	'Microsoft.BingFinance',
        	'Microsoft.BingNews',
        	'Microsoft.BingSports',
        	'Microsoft.BingTranslator',
        	'Microsoft.BingWeather',
        	'Microsoft.BingFoodAndDrink',
        	'Microsoft.BingTravel',
        	'Microsoft.BingHealthAndFitness',
        	'Microsoft.FreshPaint',
        	'Microsoft.MicrosoftOfficeHub',
        	'Microsoft.WindowsFeedbackHub',
        	'Microsoft.MicrosoftSolitaireCollection',
        	'Microsoft.MicrosoftPowerBIForWindows',
        	'Microsoft.MinecraftUWP',
        	'Microsoft.MicrosoftStickyNotes',
        	'Microsoft.NetworkSpeedTest',
        	'Microsoft.Office.OneNote',
        	'Microsoft.OneConnect',
        	'Microsoft.People',
        	'Microsoft.SkypeApp',
        	'Microsoft.Wallet',
        	'Microsoft.WindowsAlarms',
        	'Microsoft.WindowsCamera',
        	'Microsoft.windowscommunicationsapps',
        	'Microsoft.WindowsMaps',
        	'Microsoft.WindowsPhone',
        	'Microsoft.WindowsSoundRecorder',
        	'Microsoft.XboxApp',
        	'Microsoft.XboxGameOverlay',
        	'Microsoft.XboxIdentityProvider',
        	'Microsoft.XboxSpeechToTextOverlay',
        	'Microsoft.ZuneMusic',
        	'Microsoft.ZuneVideo',
        	'Microsoft.CommsPhone',
        	'Microsoft.ConnectivityStore',
        	'Microsoft.GetHelp',
        	'Microsoft.Getstarted',
        	'Microsoft.Messaging',
        	'Microsoft.Office.Sway',
        	'Microsoft.WindowsReadingList',
        	'9E2F88E3.Twitter',
        	'PandoraMediaInc.29680B314EFC2',
        	'Flipboard.Flipboard',
        	'ShazamEntertainmentLtd.Shazam',
        	'king.com.CandyCrushSaga',
        	'king.com.CandyCrushSodaSaga',
        	'king.com.*',
        	'ClearChannelRadioDigital.iHeartRadio',
        	'4DF9E0F8.Netflix',
        	'6Wunderkinder.Wunderlist',
        	'Drawboard.DrawboardPDF',
        	'2FE3CB00.PicsArt-PhotoStudio',
        	'D52A8D61.FarmVille2CountryEscape',
        	'TuneIn.TuneInRadio',
        	'GAMELOFTSA.Asphalt8Airborne',
        	'TheNewYorkTimes.NYTCrossword',
        	'DB6EA5DB.CyberLinkMediaSuiteEssentials',
        	'Facebook.Facebook',
        	'flaregamesGmbH.RoyalRevolt2',
        	'Playtika.CaesarsSlotsFreeCasino',
        	'A278AB0D.MarchofEmpires',
        	'KeeperSecurityInc.Keeper',
        	'ThumbmunkeysLtd.PhototasticCollage',
        	'XINGAG.XING',
        	'89006A2E.AutodeskSketchBook',
        	'D5EA27B7.Duolingo-LearnLanguagesforFree',
        	'46928bounde.EclipseManager',
        	'ActiproSoftwareLLC.562882FEEB491',
        	'DolbyLaboratories.DolbyAccess',
        	'A278AB0D.DisneyMagicKingdoms',
        	'WinZipComputing.WinZipUniversal',
        	'Microsoft.ScreenSketch',
        	'Microsoft.XboxGamingOverlay',
        	'Microsoft.Xbox.TCUI',
        	'Microsoft.YourPhone',
        	'HP Wolf Security',
        	'HP Wolf Security Application Support for Sure Sense',
        	'HP Wolf Security Application Support for Windows',
        	'Hp Wolf Security - Console',
        	'ExpressVPN',
        	'ACGMediaPlayer',
            'ActiproSoftwareLLC',
            'AdobePhotoshopExpress',
            'Amazon.com.Amazon',
            'Asphalt8Airborne',
            'AutodeskSketchBook',
            'BubbleWitch3Saga',
            'CaesarsSlotsFreeCasino',
            'CandyCrush',
            'COOKINGFEVER',
            'CyberLinkMediaSuiteEssentials';
            'DisneyMagicKingdoms',
            'Dolby',
            'DrawboardPDF',
            'Duolingo-LearnLanguagesforFree',
            'EclipseManager',
            'Facebook',
            'FarmVille2CountryEscape',
            'FitbitCoach',
            'Flipboard',
            'HiddenCity',
            'Hulu',
        	'iHeartRadio',
            'Keeper',
            'LinkedInforWindows',
            'MarchofEmpires',
            'Netflix',
            'NYTCrossword',
            'OneCalendar',
            'PandoraMediaInc',
            'PhototasticCollage',
            'PicsArt-PhotoStudio',
            'Plex',
            'PolarrPhotoEditorAcademicEdition',
            'RoyalRevolt',
            'Shazam',
            'Sidia.LiveWallpaper',
            'SlingTV',
            'Speed Test',
            'Sway',
            'TuneInRadio',
            'Twitter',
            'Viber',
            'WinZipUniversal',
            'Wunderlist',
            'XING'
        )

        Remove-Apps -AppList $AppsToRemove     
    }

    # Disable services
    if($DisableServices) {
        $servicesToDisable = @(
            'DiagTrack',
            'DialogBlockingService',
            'MsKeyboardFilter',
            'NetMsmqActivator',
            'PcaSvc',
            'SEMgrSvc',
            'ShellHWDetection',
            'shpamsvc',
            'SysMain',
            'Themes',
            'TrkWks',
            'tzautoupdate',
            'uhssvc',
            'W3SVC',
            'OneSyncSvc',
            'WdiSystemHost',
            'WdiServiceHost',
            'SCardSvr',
            'ScDeviceEnum',
            'SCPolicySvc',
            'SensorDataService',
            'SensrSvc',
            'Beep',
            'cdfs',
            'cdrom',
            'cnghwassist',
            'GpuEnergyDrv',
            'GpuEnergyDr',
            'Telemetry',
            'VerifierExt'
        )

    # Call the function with the service names to disable
        Disable-Services -ServiceNames $servicesToDisable
    }

    # Configure Power settings
    if($PowerSettings) {
        Power-Settings
    }

    # Configure BCD settings
    if($BootSettings) {
        BCD-settings
    }

    # Registry settings
    if($RegistrySettings){
        $regSettings = "$tempFile\settings.reg"
        $regFilePath = [System.IO.Path]::ChangeExtension($regSettings, ".reg")
        Apply-RegistrySettings -RegFilePath $regFilePath
    }

    if($DisableScheduledTasks){
        $wildcards = @(
            "update",
            "helloface",
            "customer experience improvement program",
            "microsoft compatibility appraiser",
            "startupapptask",
            "dssvccleanup",
            "bitlocker",
            "chkdsk",
            "data integrity scan",
            "defrag",
            "languagecomponentsinstaller",
            "upnp",
            "windows filtering platform",
            "tpm",
            "speech",
            "spaceport",
            "power efficiency",
            "cloudexperiencehost",
            "diagnosis",
            "file history",
            "bgtaskregistrationmaintenancetask",
            "autochk\proxy",
            "siuf",
            "device information",
            "edp policy manager",
            "defender",
            "marebackup"
        )
    
        # Disable schedule tasks
        Disable-ScheduledTasksByWildcard -Wildcards $wildcards 
    }

    # Configure taskbar
    if($TaskbarSettings){
        taskbar-settings
    }

    # Disable Process Mitigations
    if($DisableMitigations){
        Disable-ProcessMitigations     
    }

    # Disable memory compression
    if($MemoryCompression){
        PowerShell -Command "Disable-MMAgent -MemoryCompression" | Out-Null
        Write-Output "info: Disabling Memory Compression"
    }
    
    # Remove edge
    if($RemoveEdge) {
        Remove-Edge
    }

    if($RemoveOneDrive) {
        Remove-OneDrive
    }

    Write-Output "" "Windows setup completed!"
}



# execute main function
main


