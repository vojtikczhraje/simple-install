# Competely broken needs to be re-done

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
| `RegistrySettings` | Configure Windows settings via registry. | `true` |
| `DisableScheduledTasks` | Disable windows scheduled tasks. This task can be running in background without you knowing it. | `true` |
| `MemoryCompression ` | Disable memory compression on Windows. Can reduce CPU load but may increase physical memory usage and impact overall performance. | `true` |
| `RemoveEdge ` | Disable Chromium Microsoft Edge. | `true` |
| `RemoveOneDrive ` | Remove OneDrive as another Windows bloatware but separately (some people use it that's why). | `true` |
| `ReplaceWallpapers ` | Replace Windows default wallpapers with solid black images. | `true` |

### How to update settings in the table ^
- Paste command below to PowerShell:
```powershell
irm "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/config.ini" -OutFile "C:\config.ini"; C:\config.ini
```

- Change the values to `true` for enabling option or `false` for disabling option.
- Then run the [download command ^](#getting-started) to execute the PowerShell script with changed options.

### Example:
```ini
WindowsUpdate=false  # This turns Windows updates off.
WindowsActivation=true  # This turns Windows activation on.
...
```

---



<details open> 
<summary><h2>Features</h2></summary>

- Activates Windows
- Installs Windows update
- Installs Windows features (NET Framework 3.5)
- Installs Visual C++ Redistributable
- Installs package manager and applications
- Installs Firefox
- Removes bloat apps
- Disables bloat services
- Configures power settings (power plan)
- Changes Windows settings
- Disables scheduled tasks
- Disables memory compression
- Removes OneDrive
- Removes Edge
- Replaces Wallpapers

</details>


## Resources
> [!NOTE]  
> I would like to acknowledge that not all the work presented here is solely my own. Below, I've listed credits to the authors of certain contributions.
- [PC-Tunning](https://github.com/amitxv/PC-Tuning) - Not accessible 
- [WinPostInstall](https://github.com/jhx0/WinPostInstall)
- [Firefox](https://github.com/amitxv/firefox)
- [OneDrive Uninstaller](https://github.com/ionuttbara/one-drive-uninstaller)
- [Wallpaper replacer](https://github.com/amitxv/win-wallpaper)
- [7-zip installer](https://github.com/MichaelMasuch/Silent-Install-of-7-Zip)


<details> 
<summary><h2>TODO</h2></summary>

- Add 7-zip to context menu via powershell and not .reg and in SAME FUNCTION

</details>

