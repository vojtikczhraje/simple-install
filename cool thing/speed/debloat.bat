@echo off
setlocal EnableDelayedExpansion

:: create list of appx packages that we want to remove
set "appx=3dbuilder zunevideo zunemusic bingweather bingnews bingsports bingfinance xboxapp getstarted officehub skypeapp gethelp solitairecollection messaging people"

:: remove packages
for %%i in (%appx%) do (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage *%%i* | Remove-AppxPackage" >nul 2>&1
)

