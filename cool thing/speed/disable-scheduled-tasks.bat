@echo off
setlocal

:: define the list of scheduled tasks to disable
set "tasks=update helloface customer experience improvement program microsoft compatibility appraiser startupapptask dssvccleanup bitlocker chkdsk data integrity scan defrag languagecomponentsinstaller upnp windows filtering platform tpm speech spaceport power efficiency cloudexperiencehost diagnosis file history bgtaskregistrationmaintenancetask autochk\proxy siuf device information edp policy manager defender marebackup"

:: Disable the scheduled tasks matching the patterns
for %%i in (%tasks%) do (
    for /f "tokens=*" %%T in ('schtasks /query /fo list ^| findstr /i "%%i"') do (
        schtasks /change /tn "%%T" /disable
    )
)
