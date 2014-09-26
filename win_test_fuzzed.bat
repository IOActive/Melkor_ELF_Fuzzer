@echo off
cls

if -%1-==-- goto USAGE
if -%2-==-- goto USAGE

@echo on
for /F %%i in ('dir /b %1\*') do %2 %1\%%i

:USAGE
echo.
echo Usage: %0 dir_with_malformed_ELFs_aka_orcs program.exe
echo.
echo Examples:
echo         %0 orcs_foo_standalone foov2\foo.exe
echo.
exit /b
:END