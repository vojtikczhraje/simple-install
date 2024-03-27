# PowerShell Script Template for Windows Setup

# Run as Administrator check
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "error: Script is not runned as administrator"
    Break
}

<# # Update Windows
Write-Output "Checking for Windows updates..."
Get-WindowsUpdate
Install-WindowsUpdate
cls

# Install Windows Features (example: .NET Framework 3.5)
# Write-Output "Installing Windows features..."
# Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All

# Disable Windows Defender (Note: Be cautious with this setting)
Write-Output "Disabling Windows Defender..."
Set-MpPreference -DisableRealtimeMonitoring $true
cls

# Install scoop and apps
# Check if Scoop is installed by attempting to access its directory
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

if($scoopInstalled){
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
} #>

# Define an array of service names to disable
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

# Iterate over each service and disable it
foreach ($service in $servicesToDisable) {
    $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($serviceObj) {
        Write-Output "info: Disabling service: $service"
        Set-Service -Name $service -StartupType Disabled
    } else {
        Write-Warning "Service $service not found."
    }
}

Write-Output "info: All specified services have been set to disabled."

<# # Create a hashtable of registry paths and values to add
$registryEntries = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" = @{
        "DisableAntiSpyware" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" = @{
        "DisableScanOnRealtimeEnable" = 1
        "DisableOnAccessProtection" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{
        "DisableScanOnRealtimeEnable" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Sense" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" = @{
        "Enabled" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" = @{
        "SpyNetReporting" = 0
        "SubmitSamplesConsent" = 0
    }
}

# Iterate over the hashtable and set the registry entries
foreach ($path in $registryEntries.Keys) {
    foreach ($name in $registryEntries[$path].Keys) {
        Set-ItemProperty -Path $path -Name $name -Value $registryEntries[$path][$name]
    }
}

# Delete the SecurityHealth registry entry
Remove-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue

Write-Output "Windows Defender and related services have been disabled." #>



# Configure powerplan
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

    Write-Output "info: Power plan has been set."

# Configure the BCD Store
    bcdedit /set nx AlwaysOff

    bcdedit /set disabledynamictick yes

    Write-Output "info: BCD settings has been configured."


# Disable Windows Defender
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
        Write-Host "Successfully set $Name at $Path to $Value."
    } catch {
        # Corrected the variable reference in the string
        Write-Error "Failed to set $Name at ${Path}: $_"
    }
}

function Remove-RegistryValue {
    param (
        [string]$Path,
        [string]$Name
    )
    try {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        Write-Host "Successfully removed $Name from $Path."
    } catch {
        # Corrected the variable reference in the string
        Write-Error "Failed to remove $Name from ${Path}: $_"
    }
}

# Disable Windows Update
$windowsUpdateSettings = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" = @{
        "WUServer" = " "
        "WUStatusServer" = " "
        "UpdateServiceUrlAlternate" = " "
        "DisableWindowsUpdateAccess" = 1
        "DoNotConnectToWindowsUpdateInternetLocations" = 1
        "DisableOSUpgrade" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
        "NoAutoUpdate" = 1
        "UseWUServer" = 1
        "AUOptions" = 2
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" = @{
        "Start" = 4
    }
}

foreach ($path in $windowsUpdateSettings.Keys) {
    foreach ($name in $windowsUpdateSettings[$path].Keys) {
        Set-RegistryValue -Path $path -Name $name -Value $windowsUpdateSettings[$path][$name]
    }
}

# Disable Windows Defender and Related Security Features
$windowsDefenderSettings = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" = @{
        "DisableAntiSpyware" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{
        "DisableBehaviorMonitoring" = 1
        "DisableScanOnRealtimeEnable" = 1
        "DisableOnAccessProtection" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Sense" = @{
        "Start" = 4
    }
}

foreach ($path in $windowsDefenderSettings.Keys) {
    foreach ($name in $windowsDefenderSettings[$path].Keys) {
        Set-RegistryValue -Path $path -Name $name -Value $windowsDefenderSettings[$path][$name]
    }
}

# Disable UAC
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# Disable Automatic Maintenance
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1

# Allocate processor resources primarily to programs
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38

# Prevent Windows from marking file attachments with information about their zone of origin
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1

# Disable Search Indexing
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" -Name "Start" -Value 4

# Disable Program Compatibility Assistant
Set-RegistryValue -Path "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1

# Disable Language Bar
Set-RegistryValue -Path "HKCU\Keyboard Layout\Toggle" -Name "Layout Hotkey" -Value 3
Set-RegistryValue -Path "HKCU\Keyboard Layout\Toggle" -Name "Language Hotkey" -Value 3
Set-RegistryValue -Path "HKCU\Keyboard Layout\Toggle" -Name "Hotkey" -Value 3
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\CTF\LangBar" -Name "ShowStatus" -Value 3

# Disable Customer Experience Improvement Program
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0
Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0
Set-RegistryValue -Path "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Value 0

# Disable Fault Tolerant Heap
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\FTH" -Name "Enabled" -Value 0

# Disable Sticky Keys
Set-RegistryValue -Path "HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"

# Disable PowerShell Telemetry
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "POWERSHELL_TELEMETRY_OPTOUT" -Value 1

# Disable Pointer Acceleration
Set-RegistryValue -Path "HKCU\Control Panel\Mouse" -Name "MouseSpeed" -Value 0
Set-RegistryValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold1" -Value 0
Set-RegistryValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold2" -Value 0

# Disable Hibernation
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0

# Disable Fast Startup
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0

# Disable Windows Error Reporting
Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Value 0
Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1

# Reserve 10% of CPU resources for low-priority tasks
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 10

# Disable Remote Assistance
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

# Show File Extensions
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# Disable GameBarPresenceWriter
Remove-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType"

# Disable Telemetry
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -Value 4
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0

# Disable Retrieval of Online Tips and Help
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0

# Enable the Legacy Photo Viewer
$photoViewerAssociations = @(
    ".tif", ".tiff", ".bmp", ".dib", ".gif", ".jfif", ".jpe", ".jpeg", ".jpg", ".jxr", ".png"
)
foreach ($extension in $photoViewerAssociations) {
    Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" -Name $extension -Value "PhotoViewer.FileAssoc.Tiff"
}

# Additional associations for the current user
foreach ($extension in $photoViewerAssociations) {
    Set-RegistryValue -Path "HKCU\SOFTWARE\Classes\$extension" -Name "(Default)" -Value "PhotoViewer.FileAssoc.Tiff"
}

# Disable Typing Insights
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\input\Settings" -Name "InsightsEnabled" -Value 0

# Disable Transparency
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0

# Disable Suggestions in the Search Box and in Search Home
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDynamicSearchBoxEnabled" -Value 0

# Restore Old Context Menu
Remove-RegistryValue -Path "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "(Default)"
Remove-RegistryValue -Path "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)"

# Disable Sign-in and Lock Last Interactive User after a Restart
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1

# Disable Search the Web or Display Web Results in Search
Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0

# Disable Notifications Network Usage
Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1







Write-Output "Windows setup completed!"