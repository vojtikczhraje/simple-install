@echo off
setlocal EnableDelayedExpansion

:: create list of services that we want to remove
set "services=DiagTrack DialogBlockingService MsKeyboardFilter NetMsmqActivator  PcaSvc  SEMgrSvc  ShellHWDetection shpamsvc  SysMain Themes TrkWks  tzautoupdate uhssvc W3SVC OneSyncSvc WdiSystemHost  WdiServiceHost  SCardSvr  ScDeviceEnum  SCPolicySvc SensorDataService  SensrSvc  Beep cdfs  cdrom  cnghwassist  GpuEnergyDrv  GpuEnergyDr  Telemetry  VerifierExt WaaSMedicSvc UsoSvc WinDefend wscsvc SecurityHealthService Sense"

:: set services start to 4 (disable)
for %%i in (%services%) do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%i" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
)
