#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if command -v ninja >/dev/null 2>&1; then
  generator_args=(-G Ninja)
  build_dir="${project_dir}/build-arm64-ninja"
  generator_name="Ninja"
elif command -v make >/dev/null 2>&1; then
  generator_args=(-G "Unix Makefiles")
  build_dir="${project_dir}/build-arm64-make"
  generator_name="Unix Makefiles"
else
  printf 'Error: neither ninja nor make was found.\n' >&2
  printf 'Install one with: sudo apt install ninja-build\n' >&2
  printf 'Or install the standard toolchain: sudo apt install build-essential\n' >&2
  exit 1
fi

printf 'Using %s; build directory: %s\n' "${generator_name}" "${build_dir}"

cmake -S "${project_dir}" -B "${build_dir}" "${generator_args[@]}" \
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
