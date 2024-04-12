# simple-install
- PowerShell script that makes setup of Windows easier.

## Getting Started
Open PowerShell as administrator and enter the command below. <br />
```powershell
irm "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/simple-install.ps1" | iex
```
---
## Default settings

| Option | Notes | Value |
|----------|----------|----------|
| `WindowsUpdate` | Downloads all necessery stuff for updating Windows and then updates Windows. | `false` |
| `WindowsActivation` | Donwloads windows activation file from [here](https://github.com/massgravel/Microsoft-Activation-Scripts) | `true` |
| `WindowsFeatures` | Install Windows Features (example: .NET Framework 3.5). | `true` |
| `VisualCppRedistributable` | Install Visual C++ Redistributable from [here](https://github.com/abbodi1406/vcredist). | `true` |
| `InstallApplications` | Install scoop(package manager) and then install applications that are mention in features. | `true` |
| `InstallFirefox` | Install minimal version of firefox from [here](https://github.com/amitxv/firefox). | `true` |
| `RemoveBloatApplications` | Uninstall Windows pre-installed bloat (solitaire, 3d paint etc..). | `true` |
| `DisableServices` | Disable some unnecessary Windows services (fax, beep, diagrack etc..). | `true` |
| `PowerSettings` | Configure Windows power settings for better performance .| `true` |
| `BootSettings` | Configure boot options (loading circle etc..). | `true` |
| `RegistrySettings` | Configure Windows settings via registry. | `true` |
| `DisableScheduledTasks` | Disable windows scheduled tasks. This task can be running in background without you knowing it. | `true` |
| `TaskbarSettings` | Configure taskbar settings for better appearance. | `false` |
| `DisableMitigations ` | Disable Windows mitigations. Can lead to better performance but worse security. | `true` |
| `MemoryCompression ` | Disable memory compression on Windows. Can reduce CPU load but may increase physical memory usage and impact overall performance. | `true` |
| `RemoveEdge ` | Disable Chromium Microsoft Edge. | `false` |

### How to update settings in the table ^
- Paste command below to PowerShell:
```powershell
irm "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/assets/config.ini" -OutFile "C:\config.ini"; C:\config.ini
```

- Change the values to `true` for enabling option or `false` for disabling option.
- Then run the [download command ^](#getting-started) to execute the PowerShell script with changed options.

### Example:
```ini
WindowsUpdate=false  # This turns Windows updates on.
WindowsActivation=true  # This turns Windows activation on.
...
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
- [Firefox](https://github.com/amitxv/firefox)
