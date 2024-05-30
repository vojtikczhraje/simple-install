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
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" /v "ShortcutNameTemplate" /t REG_SZ /d '\"%s.lnk\"' /f > $null 2>&1

    # Disable Cortana
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowCortana" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f > $null 2>&1

    # Disable Paging files
    Reg.exe --% Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "" /f | Out-Null
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f > $null 2>&1

    # Disable Power Saving features
    Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -like "USB\VID_*" } | ForEach-Object {
    $Path = "HKLM:\System\CurrentControlSet\Enum\$($_.DeviceID)\Device Parameters"
    Reg.exe Add "$Path" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "$Path" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "$Path" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "$Path" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "$Path" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    }

    Get-ChildItem -Path "HKLM:\System\CurrentControlSet\Enum" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Property -contains "IdleInWorkingState" } | ForEach-Object { 
        Reg.exe Add "$_.PSPath" /v "IdleInWorkingState" /t REG_DWORD /d "0" /f > $null 2>&1
    }

    Get-ChildItem -Path "HKLM:\System\CurrentControlSet\Enum" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Property -contains "D3ColdSupported" } | ForEach-Object { 
        Reg.exe Add "$_.PSPath" /v "D3ColdSupported" /t REG_DWORD /d "0" /f > $null 2>&1
    }	

    Get-ChildItem -Path "HKLM:\System\CurrentControlSet\Enum" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Property -contains "EnableIdlePowerManagement" } | ForEach-Object { 
        Reg.exe Add "$_.PSPath" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f > $null 2>&1
    }

    Get-ChildItem -Path "HKLM:\System\CurrentControlSet\Enum" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Property -contains "RemoteWakeEnabled" } | ForEach-Object { 
        Reg.exe Add "$_.PSPath" /v "RemoteWakeEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    }

    # Disable Sticky Keys
    Reg.exe Add  "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /d "506" /f > $null 2>&1
    Reg.exe Add  "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /d "122" /f > $null 2>&1
    Reg.exe Add  "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /d "58" /f > $null 2>&1
    Reg.exe Add  "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /d "506" /f > $null 2>&1
    Reg.exe Add  "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "Flags" /d "122" /f > $null 2>&1
    Reg.exe Add  "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v "Flags" /d "58" /f > $null 2>&1

    # Disable Superfetch
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f > $null 2>&1

    # Disable Taskbar/Start Menu Tracking & Telemetry
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Stickers" /v "EnableStickers" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f > $null 2>&1

    # Disable Task Offload
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f > $null

    # Disable Windows Error Reporting
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Assert Filtering Policy" /v "ReportAndContinue" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f > $null 2>&1

    # Disable GameBar
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f > $null 2>&1

    # Disabling Windows Power throttling
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f > $null

    # Disable Compability Assistant
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1

    # Disable Windows Tracking & Telemetry services
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f > $null 2>&1

    # Disable Windows Update/Store AutoUpdate and Telemetry
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f > $null 2>&1

    # Disable Xbox
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f > $null 2>&1

    # Classic Right Click Menu
    Reg.exe --% Add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /d "" /f | Out-Null

    # Explorer Compact mode
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseCompactMode" /t REG_DWORD /d "1" /f > $null 2>&1

    # Nvidia Optimization
    Reg Add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t Reg_DWORD /d "0" /f > $null 2>&1
    Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t Reg_DWORD /d "0" /f > $null 2>&1
    Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t Reg_DWORD /d "1" /f > $null 2>&1
    Reg Delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /f > $null 2>&1
    Reg Delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /f > $null 2>&1
    Reg Delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableCEPreemption" /f > $null 2>&1
    Reg Delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemptionOnS3S4" /f > $null 2>&1
    Reg Delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "ComputePreemption" /f > $null 2>&1
    Try {
        Nvidia-smi -acp UNRESTRICTED > $null 2>&1
    } Catch {}
    Try {
        Nvidia-smi -acp DEFAULT > $null 2>&1
    } Catch {}
    Reg Add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f > $null 2>&1
    $registryKeys = Invoke-Expression -Command 'reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" | findstr "HKEY"'
    foreach ($key in $registryKeys) {
        Reg Add "$key" /v "EnableTiledDisplay" /t REG_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "TCCSupported" /t REG_DWORD /d "0" /f > $null 2>&1
    }

    # Privacy
    Reg.exe Add "HKCU\Software\Microsoft\Windows\Shell\Associations\AppUrlAssociations\share.microsoft.com\AppX6bvervyj4dbgfhwjaqdvcttzfgz9rvpv\UserChoice" /v "Hash" /t REG_SZ /d "hhJ5zpMlfwI=" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\Shell\Associations\AppUrlAssociations\share.microsoft.com\AppX6bvervyj4dbgfhwjaqdvcttzfgz9rvpv\UserChoice" /v "Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictanonymous" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t "REG_DWORD" /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportinfectioninformation" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\DusmSvc\Settings" /v "DisableSystemBucket" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWERSHELL_TELEMETRY_OPTOUT" /t REG_SZ /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableMmx" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "RSoPLogging" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /d "Deny" /f > $null 2>&1
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser" > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d " " /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d " " /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Personalization\Settings" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f > $null 2>&1

    # Windows
    Fsutil behavior set disablecompression 1 > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0001" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0002" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0003" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "150000" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1500" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillAppTimeout" /t REG_SZ /d "1500" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1500" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1500" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1500" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AlwaysKeepMemoryDump" /t REG_DWORD /d "0" /f > $null 2>&1
    Net accounts /maxpwage:unlimited > $null 2>&1

    # Optimize AMD
    $registryKeys = Invoke-Expression -Command 'reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "AMD" | findstr "HKEY"'
    foreach ($key in $registryKeys) {
        Reg Add "$key" /v "3D_Refresh_Rate_Override_DEF" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "3to2Pulldown_NA" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "AAF_NA" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "Adaptive De-interlacing" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "AllowRSOverlay" /t Reg_SZ /d "false" /f > $null 2>&1
        Reg Add "$key" /v "AllowSkins" /t Reg_SZ /d "false" /f > $null 2>&1
        Reg Add "$key" /v "AllowSnapshot" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "AllowSubscription" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "AntiAlias_NA" /t Reg_SZ /d "0" /f > $null 2>&1
        Reg Add "$key" /v "AreaAniso_NA" /t Reg_SZ /d "0" /f > $null 2>&1
        Reg Add "$key" /v "ASTT_NA" /t Reg_SZ /d "0" /f > $null 2>&1
        Reg Add "$key" /v "AutoColorDepthReduction_NA" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "DisableSAMUPowerGating" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "DisableUVDPowerGatingDynamic" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "DisableVCEPowerGating" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "EnableAspmL0s" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "EnableAspmL1" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "EnableUlps" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "EnableUlps_NA" /t Reg_SZ /d "0" /f > $null 2>&1
        Reg Add "$key" /v "KMD_DeLagEnabled" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "KMD_FRTEnabled" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "DisableDMACopy" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "DisableBlockWrite" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "StutterMode" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "EnableUlps" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "PP_SclkDeepSleepDisable" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "PP_ThermalAutoThrottlingEnable" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key" /v "DisableDrmdmaPowerGating" /t Reg_DWORD /d "1" /f > $null 2>&1
        Reg Add "$key" /v "KMD_EnableComputePreemption" /t Reg_DWORD /d "0" /f > $null 2>&1
        Reg Add "$key\UMD" /v "Main3D_DEF" /t Reg_SZ /d "1" /f > $null 2>&1
        Reg Add "$key\UMD" /v "Main3D" /t Reg_BINARY /d "3100" /f > $null 2>&1
        Reg Add "$key\UMD" /v "FlipQueueSize" /t Reg_BINARY /d "3100" /f > $null 2>&1
        Reg Add "$key\UMD" /v "ShaderCache" /t Reg_BINARY /d "3200" /f > $null 2>&1
        Reg Add "$key\UMD" /v "Tessellation_OPTION" /t Reg_BINARY /d "3200" /f > $null 2>&1
        Reg Add "$key\UMD" /v "Tessellation" /t Reg_BINARY /d "3100" /f > $null 2>&1
        Reg Add "$key\UMD" /v "VSyncControl" /t Reg_BINARY /d "3000" /f > $null 2>&1
        Reg Add "$key\UMD" /v "TFQ" /t Reg_BINARY /d "3200" /f > $null 2>&1
        Reg Add "$key\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t Reg_BINARY /d "0100000001000000" /f > $null 2>&1
    }

    # BCD Edit Settings
    BCDEdit /set tscsyncpolicy enhanced > $null 2>&1
    BCDEdit /timeout 0 > $null 2>&1
    BCDEdit /set bootux disabled > $null 2>&1
    BCDEdit /set bootmenupolicy standard > $null 2>&1
    BCDEdit /set quietboot yes > $null 2>&1
    BCDEdit /set nx alwaysoff > $null 2>&1
    BCDEdit /set hypervisorlaunchtype off > $null 2>&1
    BCDEdit /set vsmlaunchtype Off > $null 2>&1
    BCDEdit /set vm No > $null 2>&1
    BCDEdit /set x2apicpolicy Enable > $null 2>&1
    BCDEdit /set uselegacyapicmode No > $null 2>&1
    BCDEdit /set configaccesspolicy Default > $null 2>&1
    BCDEdit /set usephysicaldestination No > $null 2>&1
    BCDEdit /set usefirmwarepcisettings No > $null 2>&1
    BCDEdit /set disabledynamictick yes > $null 2>&1
    BCDEdit /deletevalue useplatformclock > $null 2>&1

    # CSRSS Realtime priority
    Reg Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t Reg_DWORD /d "4" /f > $null
    Reg Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t Reg_DWORD /d "3" /f > $null

    # Device Affinity
    $NumberOfCores = (Get-WmiObject Win32_Processor | Select-Object -ExpandProperty NumberOfCores)
    $NumberOfThreads = (Get-WmiObject Win32_Processor | Select-Object -ExpandProperty NumberOfLogicalProcessors)

    if ($NumberOfCores -gt 4) {
        # More Than 4 Cores
        # AllProcessorsInMachine
        # No Mask
        Get-WmiObject Win32_VideoController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
            Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "3" /f > $null 2>&1
            Reg Delete "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f > $null 2>&1
            }
        }
        # SpreadMessagesAcrossAllProcessors
        # No Mask
        Get-WmiObject Win32_NetworkAdapter | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
            Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "5" /f > $null 2>&1
            Reg Delete "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f > $null 2>&1
            }
        }
    } elseif (($NumberOfThreads -ne $NumberOfCores) -and ($NumberOfCores -gt 2)) {
        # 3-4 cores, Hyperthreading ON
        # SpecifiedProcessors
        # CPU 6-7
        Get-WmiObject Win32_USBController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f > $null 2>&1
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" /f > $null
            }
        }
        # SpecifiedProcessors
        # CPU 6-7
        Get-WmiObject Win32_VideoController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f > $null 2>&1
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" /f > $null
            }
        }
        # SpecifiedProcessors
        # CPU 4-5
        Get-WmiObject Win32_NetworkAdapter | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f > $null 2>&1
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "30" /f > $null
            }
        }
    } else {
        # 1-4 cores, Hyperthreading OFF
        # SpecifiedProcessors
        # CPU 3
        Get-WmiObject Win32_USBController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f > $null 2>&1
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "08" /f > $null
            }
        }
        # SpecifiedProcessors
        # CPU 1
        Get-WmiObject Win32_VideoController | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f > $null 2>&1
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "02" /f > $null
            }
        }
        # SpecifiedProcessors
        # CPU 2
        Get-WmiObject Win32_NetworkAdapter | ForEach-Object {
            if ($_.PNPDeviceID -like "*PCI\VEN_*") {
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f > $null 2>&1
                Reg Add "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f > $null
            }
        }
    }

    # Drives
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "RunStartupScriptSync" /t REG_DWORD /d "0" /f > $null 2>&1
    DISM /Online /Set-ReservedStorageState /State:Disabled > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f > $null 2>&1
    Fsutil behavior set encryptpagingfile 0 > $null 2>&1
    Fsutil behavior set mftzone 2 > $null 2>&1
    Fsutil behavior set disable8dot3 1  > $null 2>&1
    Fsutil behavior set disabledeletenotify 0 > $null 2>&1
    Try{
    Set-PhysicalDisk -DeviceID "0" -MediaType RemovableDisk -Usage WriteCache
    } Catch{}
    Try{
    Set-PhysicalDisk -DeviceID "1" -MediaType RemovableDisk -Usage WriteCache
    } Catch{}
    Try{
    Set-PhysicalDisk -DeviceID "2" -MediaType RemovableDisk -Usage WriteCache
    } Catch{}
    Try{
    Set-PhysicalDisk -DeviceID "3" -MediaType RemovableDisk -Usage WriteCache
    } Catch{}
    Try{
    Set-PhysicalDisk -DeviceID "4" -MediaType RemovableDisk -Usage WriteCache
    } Catch{}
    Try{
    Get-PhysicalDisk | Where-Object {$_.MediaType -eq "Fixed"} | Set-PhysicalDisk -WriteCacheEnabled $true
    } Catch{}

    # iGPU
    $registryKeys = Invoke-Expression -Command 'reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" | findstr "HKEY" > $null 2>&1'
    foreach ($key in $registryKeys) {
        Reg.exe Add "$key" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f > $null 2>&1
        Reg.exe Add "$key" /v "IncreaseFixedSegment" /t REG_DWORD /d "1" /f > $null 2>&1
        Reg.exe Add "$key" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f > $null 2>&1
        Reg.exe Add "$key" /v "DisablePFonDP" /t REG_DWORD /d "1" /f > $null 2>&1
        Reg.exe Add "$key" /v "EnableCompensationForDVI" /t REG_DWORD /d "1" /f > $null 2>&1
        Reg.exe Add "$key" /v "NoFastLinkTrainingForeDP" /t REG_DWORD /d "0" /f > $null 2>&1
        Reg.exe Add "$key" /v "ACPowerPolicyVersion" /t REG_DWORD /d "16898" /f > $null 2>&1
        Reg.exe Add "$key" /v "DCPowerPolicyVersion" /t REG_DWORD /d "16642" /f > $null 2>&1
    }
    Reg.exe Add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "512" /f > $null 2>&1
    
    # Optimize I/O operations
    $ram = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory -ErrorAction SilentlyContinue
    $IOPageLimit = ((($ram / 1GB) * 1024) * 1024) * 128
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "$IOPageLimit" /f > $null 2>&1
    Fsutil behavior set disablelastaccess 1 > $null 2>&1

    # Set JPEG Wallpaper quality to 100%
    Reg.exe Add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f > $null

    # Optimize Memory Management
    Fsutil behavior set memoryusage 2 > $null 2>&1
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f > $null 2>&1
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\System\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4294967295" /f > $null 2>&1
    Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
    Disable-MMAgent -PageCombining -ErrorAction SilentlyContinue
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "HeapDeCommitFreeBlockThreshold" /t REG_DWORD /d "262144" /f > $null 2>&1

    # Message signals interrupts
    Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.PNPDeviceID -like "*VEN_*" } | ForEach-Object {
        $path = "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        Reg Add "$path" /v "MSISupported" /t REG_DWORD /d "1" /f > $null 2>&1
    }
    
    Get-WmiObject -Class Win32_VideoController | Where-Object { $_.PNPDeviceID -like "*VEN_*" } | ForEach-Object {
        $path = "HKLM\System\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        Reg Add "$path" /v "MSISupported" /t REG_DWORD /d "1" /f > $null 2>&1
    }

    # Network Settings
    Netsh int tcp set global dca=enabled > $null 2>&1
    Netsh int tcp set global netdma=enabled > $null 2>&1
    Netsh int isatap set state disabled > $null 2>&1
    Netsh int tcp set global timestamps=disabled > $null 2>&1
    Netsh int tcp set global rss=enabled > $null 2>&1
    Netsh int tcp set global nonsackrttresiliency=disabled > $null 2>&1
    Netsh int tcp set global initialRto=2000 > $null 2>&1
    Netsh int tcp set supplemental template=custom icw=10 > $null 2>&1
    Netsh int ip set interface ethernet currenthoplimit=64 > $null 2>&1

    # Network Card Optimizations
    foreach ($line in (reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /k /v /f "Description" /s /e | findstr /ri "REG_SZ")) {
        $line = ($line -split 'REG_SZ')[1].Trim()
        foreach ($result in (reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f $line /d | findstr /C:"HKEY")) {
            reg add $result /v "MIMOPowerSaveMode" /t REG_SZ /d "3" /f > $null 2>&1
            reg add $result /v "PowerSavingMode" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "EnableGreenEthernet" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "*EEE" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "EnableConnectedPowerGating" /t REG_DWORD /d "0" /f > $null 2>&1
            reg add $result /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "EnableSavePowerNow" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "PnPCapabilities" /t REG_DWORD /d "24" /f > $null 2>&1
            reg add $result /v "*NicAutoPowerSaver" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "ULPMode" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "EnablePME" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "AlternateSemaphoreDelay" /t REG_SZ /d "0" /f > $null 2>&1
            reg add $result /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f > $null 2>&1
        }
    }

    # Explorer Optimizations
    Reg.exe Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoRestartShell" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NoNetCrawling" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /d "yes" /f > $null 2>&1
    Reg.exe Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "AutoSuggest" /d "yes" /f > $null 2>&1
    Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d "10" /f > $null 2>&1
    Reg.exe Add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f > $null 2>&1

    # Disable Network Bandwidth Limiters
    Reg.exe Add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f > $null 2>&1
    Reg.exe Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f > $null 2>&1
    
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
