# simple-install
- PowerShell script that makes setup of Windows easier.

## Usage
Open PowerShell as administrator and enter the command below. <br />
```powershell
irm "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/simple-install.ps1" | iex
```
---
## Default settings

| Option | Notes | Value |
|----------|----------|----------|
| `$WindowsUpdate` | Downloads all necessery stuff for updating Windows and then updates Windows | `false` |
| `$WindowsActivation` | Donwloads windows activation file from [here](https://github.com/massgravel/Microsoft-Activation-Scripts) | `true` |
| `$WindowsFeatures` | Install Windows Features (example: .NET Framework 3.5) | `true` |
| `$VisualCppRedistributable` | Install Visual C++ Redistributable from [here](https://github.com/abbodi1406/vcredist) | `true` |
| `$InstallApplications` | Install scoop(package manager) and then install applications that are mention in features | `true` |
| `$InstallFirefox` | Install minimal version of firefox from [here](https://github.com/amitxv/firefox) | `true` |
| `$RemoveBloatApplications` | Uninstall Windows pre-installed bloat (solitaire, 3d paint etc..) | `true` |
| `$DisableServices` | Disable some unnecessary Windows services (fax, beep, diagrack etc..) | `true` |
| `$PowerSettings` | Configure Windows power settings for better performance | `true` |
| `$BootSettings` | Configure boot options (loading circle etc..) | `true` |
| `$RegistrySettings` | Configure Windows settings via registry | `true` |
| `$DisableScheduledTasks` | Disable windows scheduled tasks. This task can be running in background without you knowing it | `true` |
| `$TaskbarSettings` | Configure taskbar settings for better appearance | `false` |
| `$DisableMitigations ` | Disable Windows mitigations. Can lead to better performance but worse security | `true` |
| `$MemoryCompression ` | Disable memory compression on Windows. Can reduce CPU load but may increase physical memory usage and impact overall performance. | `true` |

### How to update settings in the table ^
- Clone this repository to your PC.
```git
git clone https://github.com/vojtikczhraje/simple-install.git
cd simple-install
```

- Find a file named `simple-install.ps1` and open it using a program for writing or editing text, like Notepad, VSCode, or Vim.
- At the beginning of the file, you'll see `param` followed by some options. Change the options here to what you need.

### Example:
```powershell
param (
    [switch]$WindowsUpdate = $true,  # This turns Windows updates on.
    [switch]$WindowsActivation = $true,  # This turns Windows activation on.
    # Don't change this: [string]$tempFile = "C:\temp"
)
```

---

## Features
> [!WARNING]  
> Please be aware, the following applications are installed automatically without permission: <br />
> `git, python, nodejs, mingw, 7zip`
- Activates Windows
- Installs Windows update
- Installs Windows features (NET Framework 3.5)
- Installs Visual C++ Redistributable
- Installs package manager and applications
- Installs Firefox
- Removes bloat apps
- Disables bloat services
- Configures power settings (power plan)
- Configures boot options
- Changes Windows settings
- Disables scheduled tasks
- Configures taskbar
- Disables memory compression
  

## Resources
> [!NOTE]  
> I would like to acknowledge that not all the work presented here is solely my own. Below, I've listed credits to the authors of certain contributions.
- [PC-Tunning](https://github.com/amitxv/PC-Tuning)
- [Vitality](https://github.com/vojtikczhraje/Vitality)
- [WinPostInstall](https://github.com/jhx0/WinPostInstall)
- [WindowsDesktopPostInstall](https://gist.github.com/elipriaulx/afab55846e4ebc8854466c439a79fccc)
