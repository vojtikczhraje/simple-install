@echo off    
:: Set High Performance profile
powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    
:: disable monitor timeout
powercfg.exe /change monitor-timeout-ac 0
powercfg.exe /change monitor-timeout-dc 0

:: disable standby timeout
powercfg.exe /change standby-timeout-ac 0
powercfg.exe /change standby-timeout-dc 0

:: disable hibernate timeout
powercfg.exe /change hibernate-timeout-ac 0
powercfg.exe /change hibernate-timeout-dc 0

:: disable hibernate
powercfg.exe /hibernate off