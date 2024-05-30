param (
    [string]$tempFolder = "$env:TEMP\smpl"
)


function TempFolder {
    # Remove Old Temporary Folder if exist
    if (Test-Path -Path $tempFolder) {
        Remove-Item -Path $tempFolder -Force -Recurse -Confirm:$false 2>&1 | Out-Null
    }

    # Create Temporary Folder
    New-Item -Path $tempFolder -ItemType Directory 2>&1 | Out-Null
}

# Function to activate Windows
function Activate-Windows {

    # Create variables for further use
    $URL = "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/assets/Win-Activation.cmd"
    $FileName = "Win-Activation.cmd"
    $Path = Join-Path -Path $tempFolder -ChildPath $FileName
    

    # Download the file
    $Content = Invoke-RestMethod -Uri $URL -ErrorAction Stop
    $Content | Out-File -FilePath $Path -Encoding UTF8

    # Run file -WindowStyle Minimized
    Start-Process "cmd.exe" -ArgumentList "/c `"$Path`"" -WindowStyle Minimized

}

# Function to install Visual C++ Redistributables
function Install-VisualCppRedistributables {

    # Create variables for further use
    $URL = "https://github.com/abbodi1406/vcredist/releases/download/v0.79.0/VisualCppRedist_AIO_x86_x64.exe"
    $FileName = "VisualCppRedist_AIO_x86_x64.exe"
    $Path = Join-Path -Path $tempFolder -ChildPath $FileName

    # Add -UseBasicParsing to work on systems without IE or with IE not fully configured
    Invoke-WebRequest -Uri $URL -OutFile $Path -UseBasicParsing 2>&1 | Out-Null

    # Now that $Path is correctly defined, Start-Process should work without issues
    Start-Process -FilePath $Path -ArgumentList "/ai /gm2" -Wait

    Write-Output "Visual C++ Redistributable was installed succesfuly"
}

# Function to install Firefox
function Install-Firefox {

    # Create variables for further use
    $URL = "irm https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/assets/Firefox.ps1 | iex"
    $Path = "C:\Program Files\Mozilla Firefox"

    # Install Firefox
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $URL -Wait 

    if(Test-path $Path) {
        Write-Output "Firefox was installed succefully." 
    } else {
        Write-Output "Firefox wasn't installed succefully." 
    }
}

# Function to remove bloatware
function Remove-Bloatware {

    # Create variables for further use
        $Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "Microsoft.BingNews"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.RemoteDesktop"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Office.Todo.List"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
            
        #Optional: Typically not removed but you can if you need to for some reason
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        "*Microsoft.BingWeather*"
        #"*Microsoft.MSPaint*"
        "*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        "*Microsoft.WindowsStore*"
    )

    $Services = @(

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
            'VerifierExt',
            'wisvc',
            'AxInstSV',
            'lfsvc',
            'SharedAccess',
            'CscService',
            'PhoneSvc',
            'RemoteAccess',
            'upnphost',
            'UevAgentService',
            'WalletService',
            'FrameServer'
    )

    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Output "Trying to remove $Bloat."
    }

    # Disable services that are in list
    foreach ($Service in $Services) {
        $ServiceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($ServiceObj) {
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Output "Trying to disable $Service."
        }
    }
}

# Function to configure power settings
function Configure-PowerSettings {

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

    # Disable USB Power Savings Settings
    powercfg.exe /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
    powercfg.exe /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    powercfg.exe /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
    powercfg.exe /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

    Write-Output "Configured Windows Power Settings."
}

# Function to disable scheduled Tasks
function Disable-ScheduledTasks {

        $Tasks = @(
        # Windows base scheduled Tasks
        "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319"
        "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64"
        "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical"
        "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical"

        #"\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)"
        #"\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)"

        #"\Microsoft\Windows\AppID\EDP Policy Manager"
        #"\Microsoft\Windows\AppID\PolicyConverter"
        "\Microsoft\Windows\AppID\SmartScreenSpecific"
        #"\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck"

        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
        #"\Microsoft\Windows\Application Experience\StartupAppTask"

        #"\Microsoft\Windows\ApplicationData\CleanupTemporaryState"
        #"\Microsoft\Windows\ApplicationData\DsSvcCleanup"

        #"\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup"

        "\Microsoft\Windows\Autochk\Proxy"

        #"\Microsoft\Windows\Bluetooth\UninstallDeviceTask"

        #"\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask"
        #"\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask"
        #"\Microsoft\Windows\CertificateServicesClient\SystemTask"
        #"\Microsoft\Windows\CertificateServicesClient\UserTask"
        #"\Microsoft\Windows\CertificateServicesClient\UserTask-Roam"

        #"\Microsoft\Windows\Chkdsk\ProactiveScan"

        #"\Microsoft\Windows\Clip\License Validation"

        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"

        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"

        #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan"
        #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery"

        "\Microsoft\Windows\Defrag\ScheduledDefrag"

        #"\Microsoft\Windows\Diagnosis\Scheduled"

        #"\Microsoft\Windows\DiskCleanup\SilentCleanup"

        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        #"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"

        "\Microsoft\Windows\DiskFootprint\Diagnostics"

        "\Microsoft\Windows\Feedback\Siuf\DmClient"

        #"\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync"

        "\Microsoft\Windows\FileHistory\File History"

        #"\Microsoft\Windows\LanguageComponentsInstaller\Installation"
        #"\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation"

        "\Microsoft\Windows\Location\Notifications"
        "\Microsoft\Windows\Location\WindowsActionDialog"

        #"\Microsoft\Windows\Maintenance\WinSAT"

        "\Microsoft\Windows\Maps\MapsToastTask"
        "\Microsoft\Windows\Maps\MapsUpdateTask"

        #"\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
        #"\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"

        "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"

        #"\Microsoft\Windows\MUI\LPRemove"

        #"\Microsoft\Windows\Multimedia\SystemSoundsService"

        #"\Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler"

        #"\Microsoft\Windows\NetTrace\GatherNetworkInfo"

        #"\Microsoft\Windows\Offline Files\Background Synchronization"
        #"\Microsoft\Windows\Offline Files\Logon Synchronization"

        #"\Microsoft\Windows\PI\Secure-Boot-Update"
        #"\Microsoft\Windows\PI\Sqm-Tasks"

        #"\Microsoft\Windows\Plug and Play\Device Install Group Policy"
        #"\Microsoft\Windows\Plug and Play\Device Install Reboot Required"
        #"\Microsoft\Windows\Plug and Play\Plug and Play Cleanup"
        #"\Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers"

        #"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"

        #"\Microsoft\Windows\Ras\MobilityManager"

        #"\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"

        #"\Microsoft\Windows\Registry\RegIdleBackup"

        #"\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask"

        #"\Microsoft\Windows\RemovalTools\MRT_HB"

        #"\Microsoft\Windows\Servicing\StartComponentCleanup"

        #"\Microsoft\Windows\SettingSync\NetworkStateChangeTask"

        #"\Microsoft\Windows\Shell\CreateObjectTask"
        #"\Microsoft\Windows\Shell\FamilySafetyMonitor"
        #"\Microsoft\Windows\Shell\FamilySafetyRefresh"
        #"\Microsoft\Windows\Shell\IndexerAutomaticMaintenance"

        #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"
        #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
        #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork"

        #"\Microsoft\Windows\SpacePort\SpaceAgentTask"

        #"\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate"
        #"\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance"
        #"\Microsoft\Windows\Sysmain\ResPriStaticDbSync"
        #"\Microsoft\Windows\Sysmain\WsSwapAssessmentTask"

        #"\Microsoft\Windows\SystemRestore\SR"

        #"\Microsoft\Windows\Task Manager\Interactive"

        #"\Microsoft\Windows\TextServicesFramework\MsCtfMonitor"

        #"\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime"
        #"\Microsoft\Windows\Time Synchronization\SynchronizeTime"

        #"\Microsoft\Windows\Time Zone\SynchronizeTimeZone"

        #"\Microsoft\Windows\TPM\Tpm-HASCertRetr"
        #"\Microsoft\Windows\TPM\Tpm-Maintenance"

        #"\Microsoft\Windows\UpdateOrchestrator\Maintenance Install"
        #"\Microsoft\Windows\UpdateOrchestrator\Policy Install"
        #"\Microsoft\Windows\UpdateOrchestrator\Reboot"
        #"\Microsoft\Windows\UpdateOrchestrator\Resume On Boot"
        #"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
        #"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display"
        #"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot"

        #"\Microsoft\Windows\UPnP\UPnPHostConfig"

        #"\Microsoft\Windows\User Profile Service\HiveUploadTask"

        #"\Microsoft\Windows\WCM\WiFiTask"

        #"\Microsoft\Windows\WDI\ResolutionHost"

        "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
        "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
        "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
        "\Microsoft\Windows\Windows Defender\Windows Defender Verification"

        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
        "\Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate"

        #"\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"

        #"\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"

        #"\Microsoft\Windows\WindowsColorSystem\Calibration Loader"

        #"\Microsoft\Windows\WindowsUpdate\Automatic App Update"
        #"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
        #"\Microsoft\Windows\WindowsUpdate\sih"
        #"\Microsoft\Windows\WindowsUpdate\sihboot"

        #"\Microsoft\Windows\Wininet\CacheTask"

        #"\Microsoft\Windows\WOF\WIM-Hash-Management"
        #"\Microsoft\Windows\WOF\WIM-Hash-Validation"

        #"\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
        #"\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"

        #"\Microsoft\Windows\Workplace Join\Automatic-Device-Join"

        #"\Microsoft\Windows\WS\License Validation"
        #"\Microsoft\Windows\WS\WSTask"

        # Scheduled Tasks which cannot be disabled
        #"\Microsoft\Windows\Device Setup\Metadata Refresh"
        #"\Microsoft\Windows\SettingSync\BackgroundUploadTask"

        
    )

    foreach ($Task in $Tasks) {
        $Parts = $Task.split('\')
        $Name = $Parts[-1]
        $Path = $Parts[0..($Parts.length-2)] -join '\'

        Disable-ScheduledTask -TaskName "$Name" -TaskPath "$Path" -ErrorAction SilentlyContinue

        Write-Output "Trying to disable $Task."
    }

}

# Function to replace wallpapers
function Replace-Wallpapers {

    $URL = "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/assets/Win-Wallpaper.exe"

    # Download the file and start the process
    Invoke-WebRequest -Uri $URL -OutFile "C:\Windows\win-wallpaper.exe" | Out-Null
    Start-Process "cmd.exe" -ArgumentList "/c win-wallpaper --dir 'C:' --rgb #000000" -WindowStyle Minimized

    Write-Output "Trying to replace Windows Default wallpapers."

}

function Tweaks {
    # Disable " - Shortcut" text for created shortcuts
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" -Name "ShortcutNameTemplate" -Value "%s.lnk" -Type String -Force

    # Disable Cortana and associated features
    $cortanaPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Experience",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    )
    foreach ($path in $cortanaPaths) {
        Set-ItemProperty -Path $path -Name "AllowCortana" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DisableWebSearch" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "ConnectedSearchUseWebOverMeteredConnections" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "AllowCloudSearch" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "HistoryViewEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DeviceHistoryEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "BingSearchEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "CortanaConsent" -Value 0 -Type DWord -Force
    }

    # Disable Paging files
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Type MultiString -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 0 -Type DWord -Force

    # Power saving features for USB devices using PowerShell
    Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -like "USB\VID_*" } | ForEach-Object {
        $Path = "HKLM:\System\CurrentControlSet\Enum\$($_.DeviceID)\Device Parameters"
        Set-ItemProperty -Path $Path -Name "EnhancedPowerManagementEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $Path -Name "AllowIdleIrpInD3" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $Path -Name "EnableSelectiveSuspend" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $Path -Name "DeviceSelectiveSuspended" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $Path -Name "SelectiveSuspendEnabled" -Value 0 -Type DWord -Force
    }

    # Disable Sticky Keys
    $stickyKeysPaths = @(
        "HKCU:\Control Panel\Accessibility\StickyKeys",
        "HKCU:\Control Panel\Accessibility\Keyboard Response",
        "HKCU:\Control Panel\Accessibility\ToggleKeys",
        "HKEY_USERS:\.DEFAULT\Control Panel\Accessibility\StickyKeys",
        "HKEY_USERS:\.DEFAULT\Control Panel\Accessibility\Keyboard Response",
        "HKEY_USERS:\.DEFAULT\Control Panel\Accessibility\ToggleKeys"
    )
    foreach ($path in $stickyKeysPaths) {
        Set-ItemProperty -Path $path -Name "Flags" -Value "506" -Type String -Force
    }

    # Disable Superfetch
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "SfTracingState" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Type DWord -Force

    # Taskbar/Start Menu Tracking & Telemetry
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Type DWord -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Stickers" -Name "EnableStickers" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWord -Force

    # Disable Task Offload
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" -Name "DisableTaskOffload" -Value 1 -Type DWord -Force

    # Disable Windows Error Reporting
    $werPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport",
        "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports",
        "HKLM:\SOFTWARE\Microsoft\PCHealth\ErrorReporting",
        "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting",
        "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    )

    foreach ($path in $werPaths) {
        Set-ItemProperty -Path $path -Name "Start" -Value 4 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DoReport" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "Disabled" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DontSendAdditionalData" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "ShowUI" -Value 0 -Type DWord -Force
    }

    # Additional settings specific for Error Reporting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Assert Filtering Policy" -Name "ReportAndContinue" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Value 0 -Type DWord -Force

    # Disable GameBar
    $gameBarPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR",
        "HKCU:\System\GameConfigStore",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR",
        "HKCU:\Software\Microsoft\GameBar"
    )

    foreach ($path in $gameBarPaths) {
        Set-ItemProperty -Path $path -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "AudioCaptureEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "CursorCaptureEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "AllowGameDVR" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "ShowStartupPanel" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -Force
    }

    # Disabling Windows Power throttling
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord -Force

    # Disable Compatibility Assistant
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc" -Name "Start" -Value 4 -Type DWord -Force

    # Disable Windows Tracking & Telemetry services
    $telemetryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc",
        "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger",
        "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack",
        "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service",
        "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice",
        "HKLM:\SYSTEM\CurrentControlSet\Services\diagsvc",
        "HKLM:\SYSTEM\CurrentControlSet\Services\DcpSvc",
        "HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost",
        "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener",
        "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener"
    )

    foreach ($path in $telemetryPaths) {
        Set-ItemProperty -Path $path -Name "Start" -Value 4 -Type DWord -Force
    }

    # Disable Windows Update/Store AutoUpdate and Telemetry
    $deliveryOptimizationPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv"
    )
    foreach ($path in $deliveryOptimizationPaths) {
        Set-ItemProperty -Path $path -Name "DODownloadMode" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "Start" -Value 3 -Type DWord -Force
    }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Name "AutoDownload" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type DWord -Force

    # Disable Xbox
    $xboxServices = @(
        "XboxNetApiSvc",
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "xbgm"
    )
    foreach ($service in $xboxServices) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" -Name "Start" -Value 4 -Type DWord -Force
    }

    # Classic Right Click Menu
    Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force

    # Explorer Compact mode
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseCompactMode" -Value 1 -Type DWord -Force

    # Nvidia Optimization
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PlatformSupportMiracast" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" -Name "DisplayPowerSaving" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" -Name "DisableWriteCombining" -Value 1 -Type DWord -Force
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" -Name "DisablePreemption" -Force
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" -Name "DisableCudaContextPreemption" -Force
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" -Name "EnableCEPreemption" -Force
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" -Name "DisablePreemptionOnS3S4" -Force
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" -Name "ComputePreemption" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" -Name "EnableRID61684" -Value 1 -Type DWord -Force

    # Nvidia additional settings
    $registryKeys = (Invoke-Expression -Command 'reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA"')
    foreach ($key in $registryKeys) {
        Set-ItemProperty -Path $key -Name "EnableTiledDisplay" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "TCCSupported" -Value 0 -Type DWord -Force
    }

    # Privacy Settings
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\AppUrlAssociations\share.microsoft.com\AppX6bvervyj4dbgfhwjaqdvcttzfgz9rvpv\UserChoice" -Name "Hash" -Value "hhJ5zpMlfwI=" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\AppUrlAssociations\share.microsoft.com\AppX6bvervyj4dbgfhwjaqdvcttzfgz9rvpv\UserChoice" -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportinfectioninformation" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" -Name "AllowTailoredExperiencesWithDiagnosticData" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceAppSuggestionsEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DusmSvc\Settings" -Name "DisableSystemBucket" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "POWERSHELL_TELEMETRY_OPTOUT" -Value "1" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearchMode" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "RSoPLogging" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSync" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSyncUserOverride" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "DiagnosticErrorText" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" -Name "DiagnosticErrorText" -Value " " -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" -Name "DiagnosticLinkText" -Value " " -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Value "Deny" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" -Name "AllowAddressBarDropdown" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Personalization\Settings" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\OneDrive" -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Type DWord -Force
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser" > $null 2>&1

    # Windows
    Invoke-Expression -Command "fsutil behavior set disablecompression 1 > $null 2>&1"

    $deepCStatesPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0001",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0002",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0003"
    )

    foreach ($path in $deepCStatesPaths) {
        Set-ItemProperty -Path $path -Name "AllowDeepCStates" -Value 0 -Type DWord -Force
    }

    Set-ItemProperty -Path "HKLM:\Software\Microsoft\FTH" -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ForegroundLockTimeout" -Value 150000 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "HungAppTimeout" -Value "1500" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillAppTimeout" -Value "1500" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Value "1500" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Value "1500" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value "1500" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "0" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AlwaysKeepMemoryDump" -Value 0 -Type DWord -Force

    # Net accounts setting
    Invoke-Expression -Command "net accounts /maxpwage:unlimited > $null 2>&1"

    # Optimize AMD
    $registryKeys = Invoke-Expression -Command 'reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "AMD" | findstr "HKEY"'
    foreach ($key in $registryKeys) {
        Set-ItemProperty -Path $key -Name "3D_Refresh_Rate_Override_DEF" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "3to2Pulldown_NA" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "AAF_NA" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "Adaptive De-interlacing" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "AllowRSOverlay" -Value "false" -Type String -Force
        Set-ItemProperty -Path $key -Name "AllowSkins" -Value "false" -Type String -Force
        Set-ItemProperty -Path $key -Name "AllowSnapshot" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "AllowSubscription" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "AntiAlias_NA" -Value "0" -Type String -Force
        Set-ItemProperty -Path $key -Name "AreaAniso_NA" -Value "0" -Type String -Force
        Set-ItemProperty -Path $key -Name "ASTT_NA" -Value "0" -Type String -Force
        Set-ItemProperty -Path $key -Name "AutoColorDepthReduction_NA" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DisableSAMUPowerGating" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DisableUVDPowerGatingDynamic" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DisableVCEPowerGating" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "EnableAspmL0s" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "EnableAspmL1" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "EnableUlps" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "EnableUlps_NA" -Value "0" -Type String -Force
        Set-ItemProperty -Path $key -Name "KMD_DeLagEnabled" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "KMD_FRTEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DisableDMACopy" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DisableBlockWrite" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "StutterMode" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "PP_SclkDeepSleepDisable" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "PP_ThermalAutoThrottlingEnable" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DisableDrmdmaPowerGating" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "KMD_EnableComputePreemption" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "$key\UMD" -Name "Main3D_DEF" -Value "1" -Type String -Force
        Set-ItemProperty -Path "$key\UMD" -Name "Main3D" -Value "3100" -Type Binary -Force
        Set-ItemProperty -Path "$key\UMD" -Name "FlipQueueSize" -Value "3100" -Type Binary -Force
        Set-ItemProperty -Path "$key\UMD" -Name "ShaderCache" -Value "3200" -Type Binary -Force
        Set-ItemProperty -Path "$key\UMD" -Name "Tessellation_OPTION" -Value "3200" -Type Binary -Force
        Set-ItemProperty -Path "$key\UMD" -Name "Tessellation" -Value "3100" -Type Binary -Force
        Set-ItemProperty -Path "$key\UMD" -Name "VSyncControl" -Value "3000" -Type Binary -Force
        Set-ItemProperty -Path "$key\UMD" -Name "TFQ" -Value "3200" -Type Binary -Force
        Set-ItemProperty -Path "$key\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" -Name "ProtectionControl" -Value "0100000001000000" -Type Binary -Force
    }

    # BCD Edit Settings
    $bcdCommands = @(
        "bcdedit /set tscsyncpolicy enhanced",
        "bcdedit /timeout 0",
        "bcdedit /set bootux disabled",
        "bcdedit /set bootmenupolicy standard",
        "bcdedit /set quietboot yes",
        "bcdedit /set nx alwaysoff",
        "bcdedit /set hypervisorlaunchtype off",
        "bcdedit /set vsmlaunchtype Off",
        "bcdedit /set vm No",
        "bcdedit /set x2apicpolicy Enable",
        "bcdedit /set uselegacyapicmode No",
        "bcdedit /set configaccesspolicy Default",
        "bcdedit /set usephysicaldestination No",
        "bcdedit /set usefirmwarepcisettings No",
        "bcdedit /set disabledynamictick yes",
        "bcdedit /deletevalue useplatformclock"
        )

    foreach ($command in $bcdCommands) {
        Invoke-Expression -Command "$command > $null 2>&1"
    }

    # CSRSS Realtime priority
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "CpuPriorityClass" -Value 4 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "IoPriority" -Value 3 -Type DWord -Force

    # Device Affinity
    $NumberOfCores = (Get-WmiObject Win32_Processor | Select-Object -ExpandProperty NumberOfCores)
    $NumberOfThreads = (Get-WmiObject Win32_Processor | Select-Object -ExpandProperty NumberOfLogicalProcessors)

    if ($NumberOfCores -gt 4) {
        # More Than 4 Cores
        Get-WmiObject Win32_VideoController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 3 -Type DWord -Force
                Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Force
            }
        }
        Get-WmiObject Win32_NetworkAdapter | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 5 -Type DWord -Force
                Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Force
            }
        }
    } elseif (($NumberOfThreads -ne $NumberOfCores) -and ($NumberOfCores -gt 2)) {
        # 3-4 cores, Hyperthreading ON
        Get-WmiObject Win32_USBController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 4 -Type DWord -Force
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Value ([byte[]](0xC0)) -Type Binary -Force
            }
        }
        Get-WmiObject Win32_VideoController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 4 -Type DWord -Force
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Value ([byte[]](0xC0)) -Type Binary -Force
            }
        }
        Get-WmiObject Win32_NetworkAdapter | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 4 -Type DWord -Force
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Value ([byte[]](0x30)) -Type Binary -Force
            }
        }
    } else {
        # 1-4 cores, Hyperthreading OFF
        Get-WmiObject Win32_USBController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 4 -Type DWord -Force
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Value ([byte[]](0x08)) -Type Binary -Force
            }
        }
        Get-WmiObject Win32_VideoController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 4 -Type DWord -Force
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Value ([byte[]](0x02)) -Type Binary -Force
            }
        }
        Get-WmiObject Win32_NetworkAdapter | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "DevicePolicy" -Value 4 -Type DWord -Force
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" -Name "AssignmentSetOverride" -Value ([byte[]](0x04)) -Type Binary -Force
            }
        }
    }

    # Drives
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunStartupScriptSync" -Value 0 -Type DWord -Force
    Invoke-Expression -Command "DISM /Online /Set-ReservedStorageState /State:Disabled > $null 2>&1"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -Value 1 -Type DWord -Force
    Invoke-Expression -Command "fsutil behavior set encryptpagingfile 0 > $null 2>&1"
    Invoke-Expression -Command "fsutil behavior set mftzone 2 > $null 2>&1"
    Invoke-Expression -Command "fsutil behavior set disable8dot3 1 > $null 2>&1"
    Invoke-Expression -Command "fsutil behavior set disabledeletenotify 0 > $null 2>&1"
    Try { Set-PhysicalDisk -DeviceID "0" -MediaType RemovableDisk -Usage WriteCache } Catch {}
    Try { Set-PhysicalDisk -DeviceID "1" -MediaType RemovableDisk -Usage WriteCache } Catch {}
    Try { Set-PhysicalDisk -DeviceID "2" -MediaType RemovableDisk -Usage WriteCache } Catch {}
    Try { Set-PhysicalDisk -DeviceID "3" -MediaType RemovableDisk -Usage WriteCache } Catch {}
    Try { Set-PhysicalDisk -DeviceID "4" -MediaType RemovableDisk -Usage WriteCache } Catch {}
    Try { Get-PhysicalDisk | Where-Object {$_.MediaType -eq "Fixed"} | Set-PhysicalDisk -WriteCacheEnabled $true } Catch {}

    # iGPU
    $registryKeys = Invoke-Expression -Command 'reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" | findstr "HKEY"'
    foreach ($key in $registryKeys) {
        Set-ItemProperty -Path $key -Name "Disable_OverlayDSQualityEnhancement" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "IncreaseFixedSegment" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "AdaptiveVsyncEnable" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DisablePFonDP" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "EnableCompensationForDVI" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "NoFastLinkTrainingForeDP" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "ACPowerPolicyVersion" -Value 16898 -Type DWord -Force
        Set-ItemProperty -Path $key -Name "DCPowerPolicyVersion" -Value 16642 -Type DWord -Force
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Intel\GMM" -Name "DedicatedSegmentSize" -Value 512 -Type DWord -Force

    # Optimize I/O operations
    $ram = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory -ErrorAction SilentlyContinue
    $IOPageLimit = ((($ram / 1GB) * 1024) * 1024) * 128
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IOPageLockLimit" -Value $IOPageLimit -Type DWord -Force
    Invoke-Expression -Command "fsutil behavior set disablelastaccess 1 > $null 2>&1"

    # Set JPEG Wallpaper quality to 100%
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord -Force

    # Optimize Memory Management
    Invoke-Expression -Command "fsutil behavior set memoryusage 2 > $null 2>&1"
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SystemPages" -Value 4294967295 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value 4294967295 -Type DWord -Force
    Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
    Disable-MMAgent -PageCombining -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePageCombining" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "HeapDeCommitFreeBlockThreshold" -Value 262144 -Type DWord -Force

    # Message signals interrupts
    Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.PNPDeviceID -like "*VEN_*" } | ForEach-Object {
        $path = "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        Set-ItemProperty -Path $path -Name "MSISupported" -Value 1 -Type DWord -Force
    }

    Get-WmiObject -Class Win32_VideoController | Where-Object { $_.PNPDeviceID -like "*VEN_*" } | ForEach-Object {
        $path = "HKLM:\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        Set-ItemProperty -Path $path -Name "MSISupported" -Value 1 -Type DWord -Force
    }

    # Network Settings
    $networkCommands = @(
        "netsh int tcp set global dca=enabled",
        "netsh int tcp set global netdma=enabled",
        "netsh int isatap set state disabled",
        "netsh int tcp set global timestamps=disabled",
        "netsh int tcp set global rss=enabled",
        "netsh int tcp set global nonsackrttresiliency=disabled",
        "netsh int tcp set global initialRto=2000",
        "netsh int tcp set supplemental template=custom icw=10",
        "netsh int ip set interface ethernet currenthoplimit=64"
    )
    foreach ($command in $networkCommands) {
        Invoke-Expression -Command "$command > $null 2>&1"
    }

    # Network Card Optimizations
    foreach ($line in (Invoke-Expression -Command "reg query 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards' /k /v /f 'Description' /s /e | findstr /ri 'REG_SZ'")) {
        $line = ($line -split 'REG_SZ')[1].Trim()
        foreach ($result in (Invoke-Expression -Command "reg query 'HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' /s /f '$line' /d | findstr /C:'HKEY'")) {
            Set-ItemProperty -Path $result -Name "MIMOPowerSaveMode" -Value 3 -Type String -Force
            Set-ItemProperty -Path $result -Name "PowerSavingMode" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "EnableGreenEthernet" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "*EEE" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "EnableConnectedPowerGating" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $result -Name "EnableDynamicPowerGating" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "EnableSavePowerNow" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "PnPCapabilities" -Value 24 -Type DWord -Force
            Set-ItemProperty -Path $result -Name "*NicAutoPowerSaver" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "ULPMode" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "EnablePME" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "AlternateSemaphoreDelay" -Value 0 -Type String -Force
            Set-ItemProperty -Path $result -Name "AutoPowerSaveModeEnabled" -Value 0 -Type String -Force
        }
    }

    # Explorer Optimizations
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "0" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NoNetCrawling" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableBalloonTips" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLowDiskSpaceChecks" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "LinkResolveIgnoreLinkInfo" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoResolveSearch" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoResolveTrack" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name "Append Completion" -Value "yes" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name "AutoSuggest" -Value "yes" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -Value 10 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name "Auto" -Value "0" -Type String -Force

    # Disable Network Bandwidth Limiters
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 10 -Type DWord -Force

}


# Call functions as per your setup requirements
TempFolder
Activate-Windows
Install-VisualCppRedistributables
Install-Firefox
Remove-Bloatware
Configure-PowerSettings
Disable-ScheduledTasks
Replace-Wallpapers

# Add more function calls as needed
