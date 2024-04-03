# simple-install
- PowerShell script that makes setup of Windows easier.

## Usage
Open PowerShell as administrator and enter the command below. <br />
```powershell
irm "https://raw.githubusercontent.com/vojtikczhraje/simple-install/main/simple-install.ps1" | iex
```

## Features
> [!WARNING]  
> Please be aware, the following applications are installed automatically without permission: <br />
> `git, python, nodejs, mingw, vscode, 7zip, lightshot, spotify, qbittorrent, discord, steam`
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
