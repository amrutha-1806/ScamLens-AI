@echo off
setlocal
title SCAMLENS AI - Stop Services
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stop_scamlens.ps1" %*
exit /b %ERRORLEVEL%
