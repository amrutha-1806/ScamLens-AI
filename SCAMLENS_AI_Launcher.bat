@echo off
setlocal
title SCAMLENS AI Launcher
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\launch_scamlens.ps1" %*
exit /b %ERRORLEVEL%
