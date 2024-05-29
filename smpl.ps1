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
            'VerifierExt'
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
