@echo off
rem One-command scan: scan.cmd TARGET [TARGET ...]
rem A target is a file (hashed locally, then the hash is looked up) or an
rem indicator: IP, domain, URL or hash. Works from any directory.
setlocal
if "%~1"=="" (
    echo usage: scan FILE-OR-INDICATOR [...]   e.g. scan setup.exe 8.8.8.8 example.com
    exit /b 2
)
rem Capture the project folder now: shift below would otherwise change %0.
set "ROOT=%~dp0"
set "ARGS="
set "INDICATORS="
:next
if "%~1"=="" goto run
rem An existing file is hashed; anything else is looked up as an indicator.
rem (goto, not an if-block: parentheses in a path would break the block.)
if exist "%~f1" goto file
set "INDICATORS=%INDICATORS% "%~1""
goto shifted
:file
set "ARGS=%ARGS% --hash-file "%~f1""
:shifted
shift /1
goto next
:run
rem Run from the project folder so the venv and .env are found.
pushd "%ROOT%"
rem Indicators go first: the CLI does not accept them after --hash-file.
".venv\Scripts\python.exe" -m enricher %INDICATORS% %ARGS%
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
