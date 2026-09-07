@echo off
setlocal

pushd "%~dp0" || exit /b 1

cmake -S . -B build-avx2 -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DLMCRACK_ENABLE_AVX2=ON ^
  -DLMCRACK_ENABLE_AVX512=OFF ^
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
