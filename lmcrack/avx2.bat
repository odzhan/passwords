@echo off
setlocal EnableExtensions

pushd "%~dp0" || exit /b 1

rem Refresh the complete x64 environment even when the parent shell contains
rem a stale or partial VSCMD_VER configuration.
call :setup_msvc
if errorlevel 1 goto :failed

cmake -S . -B build-avx2 -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DLMCRACK_ENABLE_SSE2=ON ^
  -DLMCRACK_ENABLE_AVX2=ON ^
  -DLMCRACK_ENABLE_AVX512=OFF ^
  -DLMCRACK_NATIVE_CPU=OFF ^
  -DLMCRACK_ENABLE_LTO=ON ^
  -DLMCRACK_TEST_AVX2=ON
if errorlevel 1 goto :failed

cmake --build build-avx2
if errorlevel 1 goto :failed

ctest --test-dir build-avx2 --output-on-failure
if errorlevel 1 goto :failed

echo.
echo AVX2 Release build and tests completed successfully.
popd
exit /b 0

:failed
echo.
echo AVX2 build or tests failed.
popd
exit /b 1

:setup_msvc
rem Do not let a removed toolset selected by the parent shell override the
rem current Visual Studio installation's default toolset.
set "VCToolsVersion="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSINSTALL="
set "VSDEVCMD="
if exist "%VSWHERE%" for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
if defined VSINSTALL set "VSDEVCMD=%VSINSTALL%\Common7\Tools\VsDevCmd.bat"
if defined VSDEVCMD goto :have_vsdevcmd

rem Preview/Insiders installations are not always registered with vswhere.
for /f "delims=" %%I in ('where /r "%ProgramFiles%\Microsoft Visual Studio" VsDevCmd.bat 2^>nul') do set "VSDEVCMD=%%I"

:have_vsdevcmd
if not defined VSDEVCMD (
  echo A Visual Studio installation with the x64 C++ tools was not found.
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64
exit /b %errorlevel%
