@echo off
REM Windows build script for MSSPI Examples
REM Usage: make_windows.bat [stub|full] [clean|test|test-tls|test-dtls]

setlocal enabledelayedexpansion

REM Default build mode
set BUILD_MODE=stub
if not "%1"=="" set BUILD_MODE=%1

REM Create build directory
if not exist build mkdir build
if not exist build\obj mkdir build\obj

REM Set compiler and flags
set CC=cl
set CFLAGS=/nologo /O2 /W3 /EHsc /I..\src /I..\third_party\cprocsp\include
set BUILD_DIR=build
set OBJ_DIR=%BUILD_DIR%\obj
set EXAMPLE_TARGET=%BUILD_DIR%\msspi_example.exe

REM Handle clean
if "%2"=="clean" (
    echo Cleaning build files...
    if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
    goto :eof
)

echo Building MSSPI examples in %BUILD_MODE% mode...

if "%BUILD_MODE%"=="stub" (
    echo Using stub implementation
    
    REM Compile stub library
    echo Compiling stub library...
    %CC% %CFLAGS% /c msspi_stub.c /Fo%OBJ_DIR%\msspi_stub.obj
    if !errorlevel! neq 0 (
        echo Failed to compile stub library
        exit /b 1
    )
    
    REM Create stub library
    lib /nologo %OBJ_DIR%\msspi_stub.obj /out:%BUILD_DIR%\libmsspi_stub.lib
    if !errorlevel! neq 0 (
        echo Failed to create stub library
        exit /b 1
    )
    
    REM Compile example
    echo Compiling example application...
    %CC% %CFLAGS% /c msspi_example.c /Fo%OBJ_DIR%\msspi_example.obj
    if !errorlevel! neq 0 (
        echo Failed to compile example application
        exit /b 1
    )
    
    REM Link example with stub
    echo Linking example application...
    link /nologo %OBJ_DIR%\msspi_example.obj %BUILD_DIR%\libmsspi_stub.lib ws2_32.lib /out:%EXAMPLE_TARGET%
    if !errorlevel! neq 0 (
        echo Failed to link example application
        exit /b 1
    )
    
) else if "%BUILD_MODE%"=="full" (
    echo Using full MSSPI library with Windows SSP interface
    
    REM Build MSSPI library first
    echo Building MSSPI library...
    pushd ..\build_windows
    call make.bat
    if !errorlevel! neq 0 (
        echo Failed to build MSSPI library
        popd
        exit /b 1
    )
    popd
    
    REM Copy library to examples build directory
    copy ..\build_windows\msspi.dll %BUILD_DIR%\
    copy ..\build_windows\msspi.lib %BUILD_DIR%\
    
    REM Compile example
    echo Compiling example application...
    %CC% %CFLAGS% /c msspi_example.c /Fo%OBJ_DIR%\msspi_example.obj
    if !errorlevel! neq 0 (
        echo Failed to compile example application
        exit /b 1
    )
    
    REM Link example with full library
    echo Linking example application...
    link /nologo %OBJ_DIR%\msspi_example.obj %BUILD_DIR%\msspi.lib ws2_32.lib crypt32.lib advapi32.lib /out:%EXAMPLE_TARGET%
    if !errorlevel! neq 0 (
        echo Failed to link example application
        exit /b 1
    )
    
) else (
    echo Invalid build mode: %BUILD_MODE%
    echo Use 'stub' or 'full'
    exit /b 1
)

echo Build complete: %EXAMPLE_TARGET%

REM Handle test commands
if "%2"=="test" (
    call :test_tls
    if !errorlevel! neq 0 exit /b 1
    call :test_dtls
    if !errorlevel! neq 0 exit /b 1
) else if "%2"=="test-tls" (
    call :test_tls
) else if "%2"=="test-dtls" (
    call :test_dtls
)

goto :eof

:test_tls
echo Testing TLS functionality...
echo Starting TLS server in background...
start "TLS Server" /min %EXAMPLE_TARGET% --server --tls --port 14433
timeout /t 3 /nobreak > nul
echo Running TLS client...
%EXAMPLE_TARGET% --client --tls --host localhost --port 14433
set CLIENT_EXIT=!errorlevel!
echo Stopping TLS server...
taskkill /fi "WindowTitle eq TLS Server*" /t /f > nul 2>&1
exit /b !CLIENT_EXIT!

:test_dtls
echo Testing DTLS functionality...
echo Starting DTLS server in background...
start "DTLS Server" /min %EXAMPLE_TARGET% --server --dtls --port 14434
timeout /t 3 /nobreak > nul
echo Running DTLS client...
%EXAMPLE_TARGET% --client --dtls --host localhost --port 14434
set CLIENT_EXIT=!errorlevel!
echo Stopping DTLS server...
taskkill /fi "WindowTitle eq DTLS Server*" /t /f > nul 2>&1
exit /b !CLIENT_EXIT!