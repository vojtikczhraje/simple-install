# Run as Administrator check
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "error: Script is not runned as administrator"
    Break
}

# Ensure the C:\temp directory is cleaned up and recreated
$tempFile = "C:\temp"
if (Test-Path -Path $tempFile) {
    Remove-Item -Path $tempFile -Force -Recurse -Confirm:$false
}
New-Item -Path $tempFile -ItemType Directory | Out-Null

# Install Windows Features (example: .NET Framework 3.5)
function Windows-features {
    Write-Output "Installing Windows features..."
    Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All
}

# Install Visual C++ Redistributable
function Visual-Cpp-Redistributable {
    Write-Output "info: Installing Visual C++ Redistributable." 
    $url = "https://github.com/abbodi1406/vcredist/releases/download/v0.79.0/VisualCppRedist_AIO_x86_x64.exe"
    $path = Join-Path $tempFile "VisualCppRedist_AIO_x86_x64.exe"
    Invoke-WebRequest -Uri $url -OutFile $path

    Start-Process -FilePath $path -ArgumentList "/ai /gm2" -Wait
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
        scoop bucket add versions
        scoop bucket add extras
    
        # Development tools
        Write-Output "info: Installing development tools..."
        scoop install git
        scoop install main/python
        scoop install main/nodejs
        scoop install main/mingw
        scoop install versions/vscode-insiders
    
        # Utilities
        Write-Output "info: Installing utilities..."
        scoop install main/7zip
        scoop install extras/lightshot
    
        # Entertainment and communication
        Write-Output "info: Installing entertainment and communication apps..."
        scoop install extras/spotify
        scoop install extras/qbittorrent
        scoop install extras/discord
        scoop install extras/steam
    
        Write-Output "info: Applications installation completed."
    }
}

# Install firefox
function firefox {
    Write-Output "info: Installing firefox." 
    $scriptCommand = "irm https://raw.githubusercontent.com/amitxv/firefox/main/setup.ps1 | iex"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $scriptCommand -Wait 
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
            Write-Output "Disabling service: $service"
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Service $service not found."
        }
    }

    Write-Output "All specified services have been set to disabled."
}

# TODO: finish debloat script
function FunctionName {
    $servicesToDisable = @(
        '3DBuilder',
        'bing',
        'bingfinance',
        'bingsports',
        'BingWeather',
        'CommsPhone',
        'Drawboard PDF',
        'Facebook',
        'Getstarted',
        'Microsoft.Messaging',
        'MicrosoftOfficeHub',
        'Office.OneNote',
        'OneNote',
        'people',
        'SkypeApp',
        'solit',
        'Sway',
        'Twitter',
        'WindowsAlarms',
        'WindowsPhone',
        'WindowsMaps',
        'WindowsPhone',
        'WindowsFeedbackHub',
        'WindowsSoundRecorder',
        'windowscommunicationsapps',
        'zune'
    )
}

# Configure power settings
function Power-Settings {
    # Set the active power scheme to High performance
    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    # Remove the Balanced power scheme
    powercfg /delete 381b4222-f694-41f0-9685-ff5bb260df2e

    # Remove the Power Saver power scheme
    powercfg /delete a1841308-3541-4fab-bc81-f71556f20b4a

    # USB 3 Link Power Management - Off
    powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3   d4e98f31-5ffe-4ce1-be31-1b38b384c009 0

    # USB Selective Suspend - Disabled
    powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3   48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

    # CPU Parking - Disabled
    powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00   0cc5b647-c1df-4637-891a-dec35c318583 100

    powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00   0cc5b647-c1df-4637-891a-dec35c318584 100

    # Make the Power Plan Active
    powercfg /setactive scheme_current

    Write-Output "info: Power settings has been configured." 
}

# Configure the BCD store
function BCD-settings {
    bcdedit /set nx AlwaysOff
    bcdedit /set disabledynamictick yes
    
    Write-Output "info: BCD settings has been configured." 
}

# Create settings.reg and apply it
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

; disable language bar

[HKEY_CURRENT_USER\Keyboard Layout\Toggle]
"Layout Hotkey"="3"
"Language Hotkey"="3"
"Hotkey"="3"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\CTF\LangBar]
"ShowStatus"=dword:00000003

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

; disable remote assistance

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

# All functions are ran in main function 
function Main {
    # Install windows features (NET - Framework 3.5)
    # Windows-features

    # Install Visual C++ Redistributable
    Visual-Cpp-Redistributable

    # Install package manager and applications
    apps 

    # Install firefox
    firefox

    # Disable services
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

    # Configure Power settings
    Power-Settings

    # Configure BCD settings
    BCD-settings

    # Registry settings
    $regSettings = "C:\temp\settings.reg"
    $regFilePath = [System.IO.Path]::ChangeExtension($regSettings, ".reg")
    Apply-RegistrySettings -RegFilePath $regFilePath

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

    Write-Output "" "Windows setup completed!"
}

# execute main function
main


