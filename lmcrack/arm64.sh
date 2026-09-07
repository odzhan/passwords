#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${project_dir}/build-arm64"

cmake -S "${project_dir}" -B "${build_dir}" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLMCRACK_ENABLE_NEON=ON \
  -DLMCRACK_ENABLE_SSE2=OFF \
  -DLMCRACK_ENABLE_AVX2=OFF \
  -DLMCRACK_ENABLE_AVX512=OFF \
  -DLMCRACK_TEST_AVX2=OFF \
  -DLMCRACK_TEST_AVX512=OFF

cmake --build "${build_dir}"
ctest --test-dir "${build_dir}" --output-on-failure

printf '\nARM64 NEON Release build and tests completed successfully.\n'
