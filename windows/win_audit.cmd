@echo off
:: =============================================================================
:: SysAudit-Hardener v1.0.0 -- Windows Server Audit Script
:: Pure Batch (cmd.exe) -- NO PowerShell required
:: Run as:    Administrator (right-click -> Run as administrator)
:: Log output: C:\SysAudit-Hardener\reports\win_audit_<date>_<time>.log
:: Event log archive: C:\SysAudit-Hardener\reports\eventlogs\
:: =============================================================================

:: Require delayed expansion for variable updates inside loops
setlocal EnableDelayedExpansion EnableExtensions

:: ---------------------------------------------------------------------------
:: CONFIGURATION
:: ---------------------------------------------------------------------------
set "SCRIPT_VERSION=1.0.0"
set "BASE_DIR=C:\SysAudit-Hardener"
set "REPORT_DIR=%BASE_DIR%\reports"
set "EVTLOG_DIR=%REPORT_DIR%\eventlogs"

:: Build a timestamp string for the log filename (YYYYMMDD_HHMMSS)
:: wmic and %date%/%time% formats vary by locale -- use a safe method
for /f "tokens=1-3 delims=/ " %%a in ("%date%") do (
    set "DD=%%a"
    set "MM=%%b"
    set "YY=%%c"
)
:: Fallback: if locale puts year first, the above may still work.
:: We normalize to YYYYMMDD by using WMIC which always returns YYYYMMDDHHMMSS.ss
for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value 2^>nul') do (
    set "WMIC_DT=%%a"
)
set "DATESTAMP=!WMIC_DT:~0,8!"
set "TIMESTAMP_H=!WMIC_DT:~8,2!"
set "TIMESTAMP_M=!WMIC_DT:~10,2!"
set "TIMESTAMP_S=!WMIC_DT:~12,2!"
set "TIMESTAMP=!DATESTAMP!_!TIMESTAMP_H!!TIMESTAMP_M!!TIMESTAMP_S!"

set "LOG_FILE=%REPORT_DIR%\win_audit_!TIMESTAMP!.log"

:: Counters -- track check results
set /a COUNT_TOTAL=0
set /a COUNT_OK=0
set /a COUNT_WARN=0
set /a COUNT_FAIL=0

:: ---------------------------------------------------------------------------
:: EARLY: Create output directories before anything else
:: ---------------------------------------------------------------------------
if not exist "%REPORT_DIR%"  mkdir "%REPORT_DIR%"  2>nul
if not exist "%EVTLOG_DIR%" mkdir "%EVTLOG_DIR%" 2>nul

:: ---------------------------------------------------------------------------
:: ADMIN PRIVILEGE CHECK
:: ---------------------------------------------------------------------------
:: Attempt to read a protected key that only Administrators can access
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [FAIL]  This script must be run as Administrator. Aborting.
    echo         Right-click the script and select "Run as administrator".
    pause
    exit /b 1
)

:: ---------------------------------------------------------------------------
:: HEADER
:: ---------------------------------------------------------------------------
call :print_header

:: ---------------------------------------------------------------------------
:: RUN ALL AUDIT MODULES
:: ---------------------------------------------------------------------------
call :audit_local_admins
call :audit_firewall
call :audit_services
call :audit_eventlog_backup

:: ---------------------------------------------------------------------------
:: FOOTER & EXIT
:: ---------------------------------------------------------------------------
call :print_footer
echo.
echo Log saved to: %LOG_FILE%
echo.
endlocal
exit /b 0


:: ============================================================================
:: SUBROUTINE: print_header
:: ============================================================================
:print_header
    set "BAR================================================================================
"
    call :log_plain "================================================================================"
    call :log_plain "  SysAudit-Hardener v%SCRIPT_VERSION% ^| Windows Server Audit Report"
    for /f "tokens=2 delims==" %%a in ('wmic computersystem get name /value 2^>nul') do (
        call :log_plain "  Host     : %%a"
    )
    call :log_plain "  Date     : !DATESTAMP:~0,4!-!DATESTAMP:~4,2!-!DATESTAMP:~6,2! !TIMESTAMP_H!:!TIMESTAMP_M!:!TIMESTAMP_S!"
    for /f "tokens=2 delims==" %%a in ('wmic computersystem get username /value 2^>nul') do (
        call :log_plain "  Run by   : %%a"
    )
    call :log_plain "  Log      : %LOG_FILE%"
    call :log_plain "================================================================================"
    call :log_plain ""
    goto :eof


:: ============================================================================
:: SUBROUTINE: print_footer
:: ============================================================================
:print_footer
    call :log_plain ""
    call :log_plain "================================================================================"
    call :log_plain "  Audit complete."
    call :log_plain "  Total checks : !COUNT_TOTAL!"
    call :log_plain "  OK           : !COUNT_OK!"
    call :log_plain "  WARN         : !COUNT_WARN!"
    call :log_plain "  FAIL         : !COUNT_FAIL!"
    call :log_plain "================================================================================"
    goto :eof


:: ============================================================================
:: SUBROUTINE: log_plain  <message>
::   Writes a raw line to both console and log file (no tag prefix)
:: ============================================================================
:log_plain
    echo %~1
    echo %~1 >> "%LOG_FILE%"
    goto :eof


:: ============================================================================
:: SUBROUTINE: log_tag  <TAG> <message>
::   Formats [TAG]  message to console and log file; updates counters
:: ============================================================================
:log_tag
    set "_TAG=%~1"
    set "_MSG=%~2"
    echo [!_TAG!]  !_MSG!
    echo [!_TAG!]  !_MSG! >> "%LOG_FILE%"
    :: Update relevant counter based on tag
    if /i "!_TAG!"=="OK"   ( set /a COUNT_OK=COUNT_OK+1     & set /a COUNT_TOTAL=COUNT_TOTAL+1 )
    if /i "!_TAG!"=="WARN" ( set /a COUNT_WARN=COUNT_WARN+1 & set /a COUNT_TOTAL=COUNT_TOTAL+1 )
    if /i "!_TAG!"=="FAIL" ( set /a COUNT_FAIL=COUNT_FAIL+1 & set /a COUNT_TOTAL=COUNT_TOTAL+1 )
    goto :eof


:: ============================================================================
:: CONVENIENCE WRAPPERS
:: ============================================================================
:log_info
    echo [INFO]  %~1
    echo [INFO]  %~1 >> "%LOG_FILE%"
    goto :eof

:log_ok
    call :log_tag "OK" "%~1"
    goto :eof

:log_warn
    call :log_tag "WARN" "%~1"
    goto :eof

:log_fail
    call :log_tag "FAIL" "%~1"
    goto :eof

:log_section
    call :log_plain "--------------------------------------------------------------------------------"
    call :log_info "=== %~1 ==="
    call :log_plain "--------------------------------------------------------------------------------"
    goto :eof


:: ============================================================================
:: AUDIT MODULE 1: LOCAL ADMINISTRATORS GROUP
:: ============================================================================
:audit_local_admins
    call :log_section "LOCAL ADMINISTRATORS GROUP"

    call :log_info "Enumerating members of BUILTIN\Administrators..."
    call :log_plain ""

    :: 'net localgroup Administrators' lists members after the dashed separator line
    :: We skip the header lines and capture only the account names
    set "_found_members=0"
    for /f "skip=6 tokens=*" %%a in ('net localgroup Administrators 2^>nul') do (
        set "_line=%%a"
        :: The command output ends with "The command completed successfully."
        :: Detect that line and stop processing
        if "!_line!"=="The command completed successfully." (
            goto :admins_done
        )
        if not "!_line!"=="" (
            call :log_info "  Member: !_line!"
            set /a _found_members=_found_members+1
        )
    )
    :admins_done
    call :log_plain ""

    if !_found_members! gtr 0 (
        call :log_ok "Local Administrators group enumerated — !_found_members! member(s) found (review above)"
    ) else (
        call :log_warn "Local Administrators group appears empty or could not be read"
    )
    goto :eof


:: ============================================================================
:: AUDIT MODULE 2: WINDOWS FIREWALL STATUS
:: ============================================================================
:audit_firewall
    call :log_section "WINDOWS FIREWALL STATUS"

    :: netsh advfirewall show allprofiles outputs blocks for Domain, Private, Public
    :: We extract the State lines for each profile

    set "_profiles=Domain Private Public"
    for %%P in (!_profiles!) do (
        set "_state=UNKNOWN"
        for /f "tokens=2 delims= " %%s in ('netsh advfirewall show %%Pprofile state 2^>nul ^| findstr /i "State"') do (
            set "_state=%%s"
        )
        if /i "!_state!"=="ON" (
            call :log_ok    "%%P Profile Firewall : ON"
        ) else if /i "!_state!"=="OFF" (
            call :log_warn  "%%P Profile Firewall : OFF -- firewall is disabled for this profile"
        ) else (
            call :log_warn  "%%P Profile Firewall : state could not be determined (!_state!)"
        )
    )

    :: Also report the default inbound/outbound actions for the Domain profile
    call :log_info "Default inbound/outbound actions (Domain profile):"
    for /f "tokens=1,* delims= " %%a in ('netsh advfirewall show domainprofile firewallpolicy 2^>nul ^| findstr /i "Firewall Policy"') do (
        call :log_info "  %%a %%b"
    )
    goto :eof


:: ============================================================================
:: AUDIT MODULE 3: CRITICAL WINDOWS SERVICES
:: ============================================================================
:audit_services
    call :log_section "CRITICAL WINDOWS SERVICES"

    :: Services to check: format is "ServiceName:FriendlyDescription"
    :: Add or remove entries to match your environment
    set "SVC_LIST=LanmanServer:Server (File and Printer Sharing)"
    set "SVC_LIST=!SVC_LIST! W32Time:Windows Time"
    set "SVC_LIST=!SVC_LIST! EventLog:Windows Event Log"
    set "SVC_LIST=!SVC_LIST! WinDefend:Windows Defender Antivirus"
    set "SVC_LIST=!SVC_LIST! wuauserv:Windows Update"
    set "SVC_LIST=!SVC_LIST! Dnscache:DNS Client"

    for %%S in (!SVC_LIST!) do (
        :: Each token in SVC_LIST is "Name:Description" -- split on ':'
        for /f "tokens=1,2 delims=:" %%A in ("%%S") do (
            set "_svc_name=%%A"
            set "_svc_desc=%%B"
        )

        :: Query service state using 'sc query'
        set "_svc_state=UNKNOWN"
        for /f "tokens=3" %%t in ('sc query "!_svc_name!" 2^>nul ^| findstr /i "STATE"') do (
            set "_svc_state=%%t"
        )

        if "!_svc_state!"=="RUNNING" (
            call :log_ok   "!_svc_name! (!_svc_desc!) : RUNNING"
        ) else if "!_svc_state!"=="STOPPED" (
            call :log_warn "!_svc_name! (!_svc_desc!) : STOPPED -- manual review required"
        ) else if "!_svc_state!"=="UNKNOWN" (
            :: Service may not be installed on this OS version
            call :log_info "!_svc_name! (!_svc_desc!) : not found or not installed"
        ) else (
            call :log_warn "!_svc_name! (!_svc_desc!) : state = !_svc_state!"
        )
    )
    goto :eof


:: ============================================================================
:: AUDIT MODULE 4: EVENT LOG BACKUP (ROBOCOPY)
:: ============================================================================
:audit_eventlog_backup
    call :log_section "EVENT LOG BACKUP"

    :: Windows event logs are stored at %SystemRoot%\System32\winevt\Logs\
    :: We export selected logs using wevtutil to .evtx files in a temp staging
    :: folder, then archive the folder using robocopy.

    set "_EVTLOG_SRC=%SystemRoot%\System32\winevt\Logs"
    set "_EXPORT_STAGE=%REPORT_DIR%\evtexport_!DATESTAMP!"

    if not exist "!_EXPORT_STAGE!" mkdir "!_EXPORT_STAGE!" 2>nul

    call :log_info "Exporting event logs to staging: !_EXPORT_STAGE!"
    call :log_plain ""

    :: Logs to export: Application, System, Security
    :: Note: Security log export requires Administrator rights
    set "_LOGS_TO_EXPORT=Application System Security"

    for %%L in (!_LOGS_TO_EXPORT!) do (
        set "_export_file=!_EXPORT_STAGE!\!DATESTAMP!_%%L.evtx"
        call :log_info "  Exporting '%%L' log..."

        :: wevtutil epl exports the log to a .evtx file
        wevtutil epl "%%L" "!_export_file!" /ow:true >nul 2>&1
        if !ERRORLEVEL! equ 0 (
            call :log_ok "  %%L log exported: !DATESTAMP!_%%L.evtx"
        ) else (
            :: Fallback: Security log sometimes needs explicit /q flag
            wevtutil epl "%%L" "!_export_file!" /ow:true /q:*[System] >nul 2>&1
            if !ERRORLEVEL! equ 0 (
                call :log_ok "  %%L log exported (fallback): !DATESTAMP!_%%L.evtx"
            ) else (
                call :log_warn "  %%L log: export failed (check Administrator rights or log lock)"
            )
        )
    )

    :: Use robocopy to archive the staged export folder to the final archive location
    call :log_plain ""
    call :log_info "Archiving staged exports to: %EVTLOG_DIR%"

    :: robocopy flags:
    ::   /E   -- copy all subdirectories (including empty)
    ::   /Z   -- restartable mode (handles large files safely)
    ::   /NP  -- do not show progress percentage (cleaner log output)
    ::   /LOG -- write robocopy output to its own log
    ::   /NFL -- do not log file names (reduces noise)
    ::   /NDL -- do not log directory names

    set "_ROBO_LOG=%REPORT_DIR%\robocopy_evtlog_!TIMESTAMP!.log"

    robocopy "!_EXPORT_STAGE!" "%EVTLOG_DIR%" /E /Z /NP /NFL /NDL /LOG:"!_ROBO_LOG!" 2>nul

    :: robocopy exit codes: 0=no files, 1=files copied OK, 2-7=various (still success), 8+=error
    if !ERRORLEVEL! leq 7 (
        call :log_ok   "Robocopy archive completed to: %EVTLOG_DIR%"
        call :log_info "Robocopy log: !_ROBO_LOG!"
    ) else (
        call :log_fail "Robocopy reported errors (exit code !ERRORLEVEL!) -- check: !_ROBO_LOG!"
    )

    :: Clean up the staging directory after successful archive
    if exist "!_EXPORT_STAGE!" (
        rd /s /q "!_EXPORT_STAGE!" 2>nul
        call :log_info "Staging directory cleaned up"
    )
    goto :eof
