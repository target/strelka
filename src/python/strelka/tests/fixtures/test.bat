@echo off
SETLOCAL

SET AVRDUDE="avrdude"

IF NOT "%AVR32_HOME%" == "" SET AVRDUDE="%AVR32_HOME%\bin\avrdude.exe"

REM Simple batch script for calling avrdude with options for USBtinyISP
REM (C) 2012, 2013 Michael Bemmerl
REM License: WTFPL-2.0

IF "%1" == "" GOTO help

%AVRDUDE% -c usbtiny -P usb %*
GOTO exit

:help
echo You probably want to add at least the part option
echo -p [partno]
echo.
echo and some other AVRDUDE command line option like
echo -U flash:w:[file]
GOTO exit

:exit
