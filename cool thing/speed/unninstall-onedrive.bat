@echo off
SETLOCAL EnableExtensions

:: uninstall onedrive
%systemroot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1

:: remove onedrive leftovers
if exist "%userprofile%\OneDrive" rmdir /s /q "%userprofile%\OneDrive"
if exist "%localappdata%\Microsoft\OneDrive" rmdir /s /q "%localappdata%\Microsoft\OneDrive" >nul 2>&1
if exist "%programdata%\Microsoft OneDrive" rmdir /s /q "%programdata%\Microsoft OneDrive" >nul 2>&1
if exist "%systemdrive%\OneDriveTemp" rmdir /s /q "%systemdrive%\OneDriveTemp" >nul 2>&1

:: remove onedrive shortcuts
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /s /f /q >nul 2>&1
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q >nul 2>&1
del "%USERPROFILE%\Links\OneDrive.lnk" /s /f /q >nul 2>&1
