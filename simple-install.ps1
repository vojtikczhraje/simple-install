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
    [switch]$RegistrySettings = $true,
    [switch]$DisableScheduledTasks = $true,
    [switch]$MemoryCompression = $true,
    [switch]$RemoveEdge = $true,
    [switch]$RemoveOneDrive = $true,
    [switch]$ReplaceWallpapers = $true,
    [switch]$7zip = $true,
    [switch]$ReplaceTaskManager = $true,
    [string]$tempFile = "C:\temp",
    [string]$configFile = "C:\config.ini"
)

# Configure console
[console]::WindowWidth=75; [console]::WindowHeight=25; [console]::BufferWidth=[console]::WindowWidth
$host.UI.RawUI.WindowTitle = "simple-install | https://github.com/vojtikczhraje/simple-install"

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
        "RegistrySettings" { $RegistrySettings = [convert]::ToBoolean($setting.Value) }
        "DisableScheduledTasks" { $DisableScheduledTasks = [convert]::ToBoolean($setting.Value) }
        "MemoryCompression" { $MemoryCompression = [convert]::ToBoolean($setting.Value) }
        "RemoveEdge" { $RemoveEdge = [convert]::ToBoolean($setting.Value) } 
        "RemoveOneDrive" { $RemoveOneDrive = [convert]::ToBoolean($setting.Value) } 
        "ReplaceWallpapers" { $ReplaceWallpapers = [convert]::ToBoolean($setting.Value) }   
        "7zip" { $7zip = [convert]::ToBoolean($setting.Value) }   
        "ReplaceTaskManager" { $ReplaceTaskManager = [convert]::ToBoolean($setting.Value) }   
        default { Write-Host "Unknown setting: $($_)" }
    }
}


# Run as Administrator check
function Admin-Check {
    If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "error:" -NoNewline -ForegroundColor Red; Write-Host "  Script is not runned as administrator"
        Break
    }
    
}

# UI at start
function menu {
    # Change console size to width = 75 & height = 25
    [console]::WindowWidth=75; [console]::WindowHeight=25; [console]::BufferWidth=[console]::WindowWidth

    # Loop for updating 
    while ($true) {
    $host.UI.RawUI.WindowTitle = "simple-install | https://github.com/vojtikczhraje/simple-install"

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
            "RegistrySettings" { $RegistrySettings = [convert]::ToBoolean($setting.Value) }
            "DisableScheduledTasks" { $DisableScheduledTasks = [convert]::ToBoolean($setting.Value) }
            "MemoryCompression" { $MemoryCompression = [convert]::ToBoolean($setting.Value) }
            "RemoveEdge" { $RemoveEdge = [convert]::ToBoolean($setting.Value) } 
            "RemoveOneDrive" { $RemoveOneDrive = [convert]::ToBoolean($setting.Value) } 
            "ReplaceWallpapers" { $ReplaceWallpapers = [convert]::ToBoolean($setting.Value) }   
            "7zip" { $7zip = [convert]::ToBoolean($setting.Value) }   
            "ReplaceTaskManager" { $ReplaceTaskManager = [convert]::ToBoolean($setting.Value) }   
            default { Write-Host "Unknown setting: $($_)" }
        }
    }

    Clear-Host

    Write-Host ""
    Write-Host ""
    Write-Host "                              |    Windows Update = " -NoNewline; Write-Host $WindowsUpdate -ForegroundColor $(if ($WindowsUpdate) {'Green'} else {'Red'})
    Write-Host "                              |    Windows Activation = " -NoNewline; Write-Host $WindowsActivation -ForegroundColor $(if ($WindowsActivation) {'Green'} else {'Red'})
    Write-Host "                              |    Windows Features = " -NoNewline; Write-Host $WindowsFeatures -ForegroundColor $(if ($WindowsFeatures) {'Green'} else {'Red'})
    Write-Host "                              |    Visual Cpp Redistributable = " -NoNewline; Write-Host $VisualCppRedistributable -ForegroundColor $(if ($VisualCppRedistributable) {'Green'} else {'Red'})
    Write-Host "                              |    Install Applications = " -NoNewline; Write-Host $InstallApplications -ForegroundColor $(if ($InstallApplications) {'Green'} else {'Red'})
    Write-Host "                              |    Install & configure 7-zip  = " -NoNewline; Write-Host $7zip -ForegroundColor $(if ($7zip) {'Green'} else {'Red'})
    Write-Host "                              |    Install Firefox = " -NoNewline; Write-Host $InstallFirefox -ForegroundColor $(if ($InstallFirefox) {'Green'} else {'Red'})
    Write-Host "                              |    Remove Bloat Applications = " -NoNewline; Write-Host $RemoveBloatApplications -ForegroundColor $(if ($RemoveBloatApplications) {'Green'} else {'Red'})
    Write-Host "          simple-install      |    Disable Services = " -NoNewline; Write-Host $DisableServices -ForegroundColor $(if ($DisableServices) {'Green'} else {'Red'})
    Write-Host "                              |    Power Settings = " -NoNewline; Write-Host $PowerSettings -ForegroundColor $(if ($PowerSettings) {'Green'} else {'Red'})
    Write-Host "                              |    Registry Settings = " -NoNewline; Write-Host $RegistrySettings -ForegroundColor $(if ($RegistrySettings) {'Green'} else {'Red'})
    Write-Host "                              |    Disable Scheduled Tasks = " -NoNewline; Write-Host $DisableScheduledTasks -ForegroundColor $(if ($DisableScheduledTasks) {'Green'} else {'Red'})
    Write-Host "                              |    Memory Compression = " -NoNewline; Write-Host $MemoryCompression -ForegroundColor $(if ($MemoryCompression) {'Green'} else {'Red'})
    Write-Host "                              |    Remove Edge = " -NoNewline; Write-Host $RemoveEdge -ForegroundColor $(if ($RemoveEdge) {'Green'} else {'Red'})
    Write-Host "                              |    Remove OneDrive = " -NoNewline; Write-Host $RemoveOneDrive -ForegroundColor $(if ($RemoveOneDrive) {'Green'} else {'Red'})
    Write-Host "                              |    Replace Wallpapers = " -NoNewline; Write-Host $ReplaceWallpapers -ForegroundColor $(if ($ReplaceWallpapers) {'Green'} else {'Red'})
    Write-Host "                              |    Replace Task Manager = " -NoNewline; Write-Host $ReplaceTaskManager -ForegroundColor $(if ($ReplaceTaskManager) {'Green'} else {'Red'})
    Write-Host ""
    Write-Host ""

    Write-Host          "                Do you wish to change configuration? [y]/[n]"

    # Read input
    $input =  Read-Host "                                    >" 

    # If input is Y or N conitnue else restart
    if($input -eq "y" -or $input -eq "Y" -or $input -eq "n" -or $input -eq "N") {

        # If input is Y configure settings else continue
        if($input -eq "y" -or $input -eq "Y") {
        # Check if config.ini exists
        if (-Not (Test-Path "C:\config.ini")) {
            # Download the file
            irm "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/config.ini" -OutFile "C:\config.ini"
            Start-Sleep -s 5
        }

        # Open config.ini and wait for it to be closed
        $process = Start-Process "notepad.exe" "C:\config.ini" -PassThru
        Write-Host "           info:" -NoNewline -ForegroundColor Cyan; Write-Host "  config.ini opened. Waiting for it to be closed..."
        $process.WaitForExit()

        } else {
            # Break of the loop if the input is n/N
            break
        }
    } else {
        # Wrong input restarting

        Write-Host "                    error:" -NoNewline -ForegroundColor Red; Write-Host "  Wrong input, restarting..."
        Start-Sleep -s 2
    }

    }
    

}

# Ensure the C:\temp directory is cleaned up and recreated
function Create-TempFolder{
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Create Temp Folder"
    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Deleting old simple-install path if exists."

    try {
        if (Test-Path -Path $tempFile) {
            Remove-Item -Path $tempFile -Force -Recurse -Confirm:$false | Out-Null
            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Path deleted succesfully."
        }
    }
    catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Path wasn't deleted succesfully."
    }

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Creating new simple-install path."
    New-Item -Path $tempFile -ItemType Directory | Out-Null

    if (Test-Path -Path $tempFile) {
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Path created succesfully."
    } else {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Path wasn't created succesfully."
    }
        
    Write-Host "" # Create a space between categories

}

# Install Windows Updates
function Install-WindowsUpdates {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Windows Update"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Running Windows Update."

    try {
        # Get packages for Windows update
        Install-PackageProvider -Name NuGet -Force | Out-Null

        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Packages for Windows update were downloaded succesfully."
    }
    catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Packages for Windows update weren't downloaded succesfully."
    }

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Attempt to update Windows."
    try {
	
        # Windows Update PS Module
        Install-Module -Name PSWindowsUpdate -Force | Out-Null
    
        # Get all Updates
        Get-WindowsUpdate -Confirm -AcceptAll | Out-Null
    
        # Do all upgrades
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Confirm -IgnoreReboot | Out-Null

        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Was updated succesfully."
    }
    catch {
        # Attempt to catch an error (doesn't work :))
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Windows wasn't updated succesfully."
    }

    Write-Host "" # Create a space between categories

}

# Install Windows Features (example: .NET Framework 3.5)
function Windows-features {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Windows Features"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Installing Windows features..."

    try {
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All | Out-Null
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Windows features succesfully downloaded."
    }
    catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Windows features weren't succesfully downloaded."
    }

    Write-Host "" # Create a space between categories
    
}

# Install Visual C++ Redistributable
function Install-VisualCppRedistributable {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Install Visual C++ Redistributable"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Installing Visual C++ Redistributable." 
    $url = "https://github.com/abbodi1406/vcredist/releases/download/v0.79.0/VisualCppRedist_AIO_x86_x64.exe"

    # Use a predefined temporary directory path
    $fileName = "VisualCppRedist_AIO_x86_x64.exe"
    $path = Join-Path -Path $tempFile -ChildPath $fileName

    try {
        # Add -UseBasicParsing to work on systems without IE or with IE not fully configured
        Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing | Out-Null

        # Now that $path is correctly defined, Start-Process should work without issues
        Start-Process -FilePath $path -ArgumentList "/ai /gm2" -Wait

        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Visual C++ Redistributables succesfully downloaded."
    }
    catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Visual C++ Redistributables weren't downloaded succesfully."
    }
    
    Write-Host "" # Create a space between categories
}

# Activate Windows
function Activate-Windows {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Activate Windows"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Activating windows." 

    # Create variables for further use
    $url = "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/assets/HWID_Activation.cmd"
    $fileName = "hwid_activation.cmd"
    $path = Join-Path -Path $tempFile -ChildPath $fileName
    
    # Try to download the file
    Try {
        # Download the file
        $content = Invoke-RestMethod -Uri $url -ErrorAction Stop
        $content | Out-File -FilePath $path -Encoding UTF8

        # Verify the file is downloaded and has content
        if ((Test-Path -Path $path) -and ((Get-Content -Path $path).Length -gt 0)) {
            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  $fileName downloaded successfully."
        } else {
            Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  $fileName file is empty or missing."
        }

        # Run file -WindowStyle Minimized
        Start-Process "cmd.exe" -ArgumentList "/c `"$path`"" -WindowStyle Minimized
    }

    # Error handling
    Catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  An error occurred while trying to download $fileName. $_"
    }

    Write-Host "" # Create a space between categories
    
}

# Install scoop(package manager), apps
function apps {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Applications & Package manager"

    try {
        # Test if scoop is installed, if not install it
        $scoopInstalled = Test-Path -Path "$env:USERPROFILE\scoop"
        if ($scoopInstalled) {
            # Scoop is installed
            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Scoop is already installed."
    } else {
        # Scoop is not installed, install scoop
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Scoop is not installed, installing now..."
    
        # Scoop doesn't directly suport running as admin so bypass it with -RunAsAdmin
        iex "& {$(irm get.scoop.sh)} -RunAsAdmin"
    
        # Update the check for Scoop installation after the installation attempt
        $scoopInstalled = Test-Path -Path "$env:USERPROFILE\scoop"
    
        # Check if scoop was installed succesufully
        if ($scoopInstalled) {
            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Scoop has been successfully installed."
        } else {
            Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Scoop installation failed."
        }
    }

    }
    catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  There was a problem with installing scoop."
    }

    # Install apps
    if ($scoopInstalled) {
        # Configure repositories
        scoop bucket add main

        Clear-Host

        # Present a menu for selecting which development tools to install
        $toolsToInstall = @("git", "python", "nodejs", "mingw")
        Write-Host "Select the tools you want to install. Use commas to separate multiple choices (e.g., 1,2)."
        for ($i=0; $i -lt $toolsToInstall.Length; $i++) {
            Write-Host "$($i+1): $($toolsToInstall[$i])"
        }
        
        # Read input
        $userInput = Read-Host "Enter your choices"

        # Convert user choice to index
        $selectedIndexes = $userInput.Split(',') | ForEach-Object { [int]$_ - 1 }

        # Installs selected tools & handles invalid selections
        foreach ($index in $selectedIndexes) {
            if ($index -ge 0 -and $index -lt $toolsToInstall.Length) {
                $tool = $toolsToInstall[$index]
                Write-Host "Installing $tool..."
                scoop install main/$tool
            }
            else {
                Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Invalid selection: $index"
            }
        }
    
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Applications installation completed."
    }

    Write-Host "" # Create a space between categories
}

# Install and configure 7-zip
function 7zip {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  7-zip"

    Invoke-Command -ScriptBlock {
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Installing & configuring 7-zip"

        # Corrected file path with environment variable
        $FileName = "$env:TEMP\7z2404-x64.exe"
        
        # Downloading the 7-Zip installer
        Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z2404-x64.exe" -OutFile $FileName | Out-Null
        
        # Direct use of the full InstallerPath
        $InstallerPath = $FileName
        
        # Install 7zip in silent mode
        Start-Process -FilePath $InstallerPath -ArgumentList '/S' -Wait
        
        # Get 7-Zip install location
        $sevenZipPath = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' | `
            Where-Object { $_.GetValue('DisplayName') -like '*7-zip*' -and $_.GetValue('InstallLocation') } | `
            Get-ItemPropertyValue -Name 'InstallLocation'
        
        # Handle array or missing path
        if ($sevenZipPath -is [System.Array]) {
            $sevenZipPath = $sevenZipPath[0]
        }
        if (-not $sevenZipPath) {
            $sevenZipPath = 'C:\Program Files\7-Zip\'
        }
        
        # Construct paths to executable and DLL
        $sevenZipExePath = Join-Path -Path $sevenZipPath -ChildPath '7zFM.exe'
        $sevenZipDllPath = Join-Path -Path $sevenZipPath -ChildPath '7z.dll'
        
        # Backup existing CompressedFolder registry settings if it exists
        if (Test-Path -Path 'HKLM:\SOFTWARE\Classes\CompressedFolder') {
            Rename-Item -Path 'HKLM:\SOFTWARE\Classes\CompressedFolder' -NewName 'CompressedFolder.BackUp' | Out-Null
        }
        

            $fileTypes = @{
                '7z'       = '0'
                'zip'      = '1'
                'rar'      = '3'
                '001'      = '9'
                #'cab'      = '7'
                #'iso'      = '8'
                'xz'       = '23'
                'txz'      = '23'
                'lzma'     = '16'
                'tar'      = '13'
                'cpio'     = '12'
                'bz2'      = '2'
                'bzip2'    = '2'
                'tbz2'     = '2'
                'tbz'      = '2'
                'gz'       = '14'
                'gzip'     = '14'
                'tgz'      = '14'
                'tpz'      = '14'
                'z'        = '5'
                'taz'      = '5'
                'lzh'      = '6'
                'lha'      = '6'
                'rpm'      = '10'
                'deb'      = '11'
                'arj'      = '4'
                #'vhd'      = '20'
                #'vhdx'     = '20'
                'wim'      = '15'
                'swm'      = '15'
                'esd'      = '15'
                'fat'      = '21'
                'ntfs'     = '22'
                'dmg'      = '17'
                'hfs'      = '18'
                'xar'      = '19'
                'squashfs' = '24'
                'apfs'     = '25'
            }
        
        
            # Create registry entries
            foreach ($entry in $fileTypes.GetEnumerator()) {
                $fileType = $entry.Key
                $iconIndex = $entry.Value
        
                # Paths
                $fileTypePath = "HKLM:\SOFTWARE\Classes\.$fileType"
                $progIdPath = "HKLM:\SOFTWARE\Classes\7-Zip.$fileType"
                $defaultIconPath = "$progIdPath\DefaultIcon"
                $shellPath = "$progIdPath\shell"
                $openPath = "$shellPath\open"
                $commandPath = "$openPath\command"
        
                # FileType
                if (-not (Test-Path -Path $fileTypePath)) {
                    New-Item -Path $fileTypePath -Force | Out-Null
                }
                Set-ItemProperty -Path $fileTypePath -Name '(Default)' -Value "7-Zip.$fileType" -Force | Out-Null
        
                if ((Test-Path -Path "$fileTypePath\PersistentHandler")) {
                    Remove-Item -Path "$fileTypePath\PersistentHandler" -Force | Out-Null
                }
        
                # ProgId
                if (-not (Test-Path -Path $progIdPath)) {
                    New-Item -Path $progIdPath -Force | Out-Null
                }
                Set-ItemProperty -Path $progIdPath -Name '(Default)' -Value "$fileType Archive" -Force | Out-Null
        
                # DefaultIcon
                if (-not (Test-Path -Path $defaultIconPath)) {
                    New-Item -Path $defaultIconPath -Force | Out-Null
                }
                Set-ItemProperty -Path $defaultIconPath -Name '(Default)' -Value "$sevenZipDllPath,$iconIndex" -Force | Out-Null
        
                # shell
                if (-not (Test-Path -Path $shellPath)) {
                    New-Item -Path $shellPath -Force | Out-Null
                }
                Set-ItemProperty -Path $shellPath -Name '(Default)' -Value 'open' -Force | Out-Null
        
                # open
                if (-not (Test-Path -Path $openPath)) {
                    New-Item -Path $openPath -Force | Out-Null
                }
        
                # command
                if (-not (Test-Path -Path $commandPath)) {
                    New-Item -Path $commandPath -Force | Out-Null
                }
                Set-ItemProperty -Path $commandPath -Name '(Default)' -Value "`"$sevenZipExePath`" `"%1`"" -Force | Out-Null
            }
        }
    
        Write-Host "" # Create a space between categories
}

# Install firefox
function firefox {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Firefox"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Installing firefox." 
    $scriptCommand = "irm https://raw.githubusercontent.com/amitxv/firefox/main/setup.ps1 | iex"
    $path = "C:\Program Files\Mozilla Firefox"
    
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", $scriptCommand -Wait 

    if(Test-path $path) {
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Firefox was installed succefully" 
    } else {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Firefox wasn't installed succefully" 
    }

    Write-Host "" # Create a space between categories
}

# Remove bloat apps
function Remove-Apps {
    param (
        [string[]]$AppList
    )

    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Remove Applications"


    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Removing unwatend Apps"

    # Delete apps that are in list
    foreach($App in $AppList) {
        Get-AppxPackage "*$App*" | Remove-AppxPackage -AllUsers -ErrorAction 'SilentlyContinue' | Out-Null
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Removing: $App" 
    }
    Write-Host "" # Create a space between categories
}

# Disable windows bloat services
 function Disable-Services {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ServiceNames
    )

    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Disable services"

    # Disable services that are in list
    foreach ($service in $ServiceNames) {
        $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceObj) {
            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Disabling service: $service"
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        } else {
            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Service $service not found."
        }
    }

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  All specified services have been set to disabled."

    Write-Host "" # Create a space between categories
}

# Configure power settings
function Power-Settings {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Power Settings"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Configuring Windows Power Settings." 

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

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Power settings has been configured." 

    Write-Host "" # Create a space between categories
}

# Create settings.reg and apply it (
function Apply-RegistrySettings {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Windows Settings"

    param (
        [string]$RegFilePath
    )
    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Configuring Windows settings via registry" 

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

; set font size for command Prompt
[HKEY_CURRENT_USER\Console]
"FontSize"=dword:000e0000

; set font size for powershell
[HKEY_CURRENT_USER\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe]
"FontSize"=dword:000c0000

; add 7-zip to context menu
[HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\7-Zip]
@="{23170F69-40C1-278A-1000-000100020000}"

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

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Windows settings changes have been applied."

    Write-Host "" # Create a space between categories
}

# Disable scheduled tasks
function Disable-ScheduledTasksByWildcard {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Wildcards
    )

    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Disable Scheduled Tasks"

    # Retrieve all scheduled tasks
    $allTasks = Get-ScheduledTask

    foreach ($wildcard in $Wildcards) {
        # Filter tasks by wildcard pattern
        $filteredTasks = $allTasks | Where-Object { $_.TaskName -like "*$wildcard*" } 2>$null | Out-Null

        if ($filteredTasks.Count -eq 0) {
            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  No tasks match the pattern: $wildcard" #>
            continue
        }

        foreach ($task in $filteredTasks) {
            # Disable each task
            try {
                Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false 2>$null | Out-Null
                Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Successfully disabled task: $($task.TaskName)" #>
            } catch {
                Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Failed to disable task: $($task.TaskName). error:" -NoNewline -ForegroundColor Red; Write-Host "  $_" #>
            }
        }
    }

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Scheduled tasks were succesfully disabled."

    Write-Host "" # Create a space between categories
}

# Disable Edge
function Disable-Edge {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Disable Edge"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Disabling Microsoft Edge."
    
    # Set edge path
    $edgeUpdatePath = "C:\Program Files (x86)\Microsoft\EdgeUpdate"

    # Test if path exists
    if (Test-Path $edgeUpdatePath) {
        Remove-Item -Path $edgeUpdatePath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  EdgeUpdate directory removed."
    } else {
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  EdgeUpdate directory not found."
    }
    
    # Search for and delete all shortcuts related to Edge across the C: drive
    Get-ChildItem -Path C:\ -Filter *edge.lnk* -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Deleted shortcut: $($_.FullName)"
    }

    Write-Host "" # Create a space between categories
}

# Remove OneDrive
function Remove-OneDrive {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Remove OneDrive"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Removing OneDrive."

    # Kill OneDrive process
    taskkill.exe /f /im "OneDrive.exe" 2>$null | Out-Null

    try {

        # Test if the path exist
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
        
        # info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Disable OneDrive via Group Policies
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
        
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  OneDrive was uninstalled succesfully." 
    }

    # Error handling
    catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  OneDrive wasn't uninstalled succesfully." 
    }   

    Write-Host "" # Create a space between categories
}

# Replace Windows default wallpapers
function black-wallpapers {
    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Black wallpapers"

    # Replace Windows default wallpapers with solid black
    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Replacing Windows default wallpapers with solid black images."
    try {
        # Download the file and start the process
        Invoke-WebRequest -Uri "https://github.com/amitxv/win-wallpaper/releases/download/0.4.0/win-wallpaper.exe" -OutFile "C:\Windows\win-wallpaper.exe" | Out-Null
        Start-Process "cmd.exe" -ArgumentList "/c win-wallpaper --dir 'C:' --rgb #000000" -WindowStyle Minimized

        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Wallpapes were succesfully replaced."
    }

    # Error handling
    catch {
        Write-Host "error:" -NoNewline -ForegroundColor Red; Write-Host "  Wallpapers weren't replaced succesfully."
    }

    Write-Host "" # Create a space between categories

}

function Replace-TaskManager {

    Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Replace Task Manager"
    # If path already exists remove them
    if ((Test-Path -Path "C:\temp\ProcessExplorer") -or (Test-Path -Path "C:\temp\ProcessExplorer.zip") -or (Test-Path -Path "C:\Windows\procexp.exe")) {
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Removing already created folders and files."
        Remove-Item -LiteralPath "C:\temp\ProcessExplorer" -Force -Recurse 2>&1 | Out-Null
        Remove-Item -LiteralPath "C:\temp\ProcessExplorer.zip" -Force -Recurse 2>&1 | Out-Null
        Remove-Item -LiteralPath "C:\Windows\procexp.exe" -Force -Recurse 2>&1 | Out-Null
    }

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Download and extract Process Explorer."
    # Define the URL for downloading Process Explorer
    $url = "https://download.sysinternals.com/files/ProcessExplorer.zip"
    # Specify the path where the ZIP file will be saved
    $destination = "C:\temp\ProcessExplorer.zip"

    # Download the file
    Invoke-WebRequest -Uri $url -OutFile $destination

    # Specify the path where to extract the contents
    $extractPath = "C:\temp\ProcessExplorer"

    # Extract the ZIP file
    Expand-Archive -LiteralPath $destination -DestinationPath $extractPath -Force

    # Move the it to right directory
    Move-Item "C:\temp\ProcessExplorer\procexp64.exe" "C:\Windows\procexp.exe"

    # Path to Process Explorer
    $procExpPath = "C:\Windows\procexp.exe"

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Replace Task Manager with Process Explorer"
    # Add registry key to override default task manager
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" -Name "Debugger" -Value "`"$procExpPath`""

    Write-Host "" # Create a space between categories
}

# All functions are ran in main function 
function Main {
    # Admin check
    Admin-Check

    # Menu
    menu
    Write-Host "                       info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Starting in 3 sec..."
    Start-Sleep -s 3
    Clear-Host


    # Create temp folder
    Create-TempFolder

    # Activate Windows
    if($WindowsActivation) {
        Activate-Windows
    }
    

    # Install Windows update
    if($WindowsUpdate) {
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

    if($7zip) {
        7zip
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

    # Disable memory compression
    if($MemoryCompression){
        Write-Host "category:" -NoNewline -ForegroundColor yellow; Write-Host "  Memory Compression"
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Disabling Memory Compression"
        PowerShell -Command "Disable-MMAgent -MemoryCompression" | Out-Null
        Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  Memory Compression disabled"
        Write-Host "" # Create a space between categories
    }
    
    # Remove edge
    if($RemoveEdge) {
        Disable-Edge
    }

    if($RemoveOneDrive) {
        Remove-OneDrive
    }

    if($ReplaceWallpapers) {
        black-wallpapers
    }

    if($ReplaceTaskManager) {
        Replace-TaskManager
    }

    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host " Windows setup completed! Do you wish to optimize more? [y]/[n]"

    $input = Read-Host ">"
    Clear-Host

    if($input -eq "y" -or $input -eq "Y" -or $input -eq "n" -or $input -eq "N") {
        if($input -eq "y" -or $input -eq "Y") {

            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host " Do you wish to configure settings? [y]/[n]"
            $settings = Read-Host ">"

            if($settings -eq "y" -or $settings -eq "Y" -or $settings -eq "n" -or $settings -eq "N") {
                if($settings -eq "y" -or $settings -eq "Y") {
                    New-Item -Path "C:\Vitality" -ItemType Directory -Force | Out-Null; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/vojtikczhraje/Vitality/main/config.ini" -OutFile "C:\Vitality\config.ini"
                    $process = Start-Process "notepad.exe" "C:\Vitality\config.ini" -PassThru
                    Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host "  config.ini opened. Waiting for it to be closed..."
                    $process.WaitForExit()
                }
            }

            Write-Host "info:" -NoNewline -ForegroundColor Cyan; Write-Host " Starting Vitality, closing in 5s"
            $url = "https://raw.githubusercontent.com/vojtikczhraje/Vitality/main/Vitality.bat"; $tempFilePath = "temp_Vitality.bat"; $newFilePath = "Vitality.bat"; Invoke-WebRequest -Uri $url -OutFile $tempFilePath; $content = Get-Content -Path $tempFilePath; $content | Out-File -FilePath $newFilePath -Encoding Default; Start-Process cmd.exe -ArgumentList "/c .\$newFilePath"; Remove-Item -Path $tempFilePath

            Start-Sleep -s 5
            Clear-Host
            exit
            
        } 
    }
}



# execute main function
main


