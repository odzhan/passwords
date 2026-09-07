cmake_minimum_required(VERSION 3.16)
project(lmcrack LANGUAGES C CXX)

include(CTest)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(LmcrackSimd)
include(LmcrackTests)

option(LMCRACK_ENABLE_SSE2 "Enable SSE2 optimizations" ON)
option(LMCRACK_ENABLE_AVX2 "Enable AVX2 optimizations" OFF)
option(LMCRACK_ENABLE_AVX512 "Enable AVX-512 optimizations" OFF)
option(LMCRACK_ENABLE_NEON "Enable ARM NEON optimizations" ON)
option(LMCRACK_NATIVE_CPU "Optimize for the CPU performing the build" OFF)
option(LMCRACK_ENABLE_LTO "Enable link-time optimization in Release builds" ON)
option(LMCRACK_ENABLE_PAIR256 "Use the 256 KiB pair-merged DES tables" OFF)
option(LMCRACK_ENABLE_PAIR64 "Use the dense 64 KiB pair-merged DES tables" OFF)
option(LMCRACK_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(LMCRACK_TEST_AVX2 "Build and run the AVX2 bitslice differential test" OFF)
option(LMCRACK_TEST_AVX512 "Build and run the AVX-512 bitslice differential test" OFF)

add_library(lmcrack_internal INTERFACE)
target_include_directories(lmcrack_internal INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/legacy"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/bitslice/common"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/bitslice/v7"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/bitslice/v8"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/bitslice/v9")

add_executable(lmcrack src/lmcrack.cpp)
add_executable(lmhash src/lmhash.c)
add_executable(v9_profile tools/v9_profile.cpp)
target_compile_features(v9_profile PRIVATE cxx_std_11)
target_link_libraries(lmcrack PRIVATE lmcrack_internal)
target_link_libraries(lmhash PRIVATE lmcrack_internal)
target_link_libraries(v9_profile PRIVATE lmcrack_internal)

if(BUILD_TESTING)
  add_test(NAME v8_cli
    COMMAND lmcrack 7584248B8D2C9F9E -v8 -s A -e A -t 1)
  set_tests_properties(v8_cli PROPERTIES
    PASS_REGULAR_EXPRESSION "found password : A")
  add_test(NAME v8_cli_normalized_alphabet
    COMMAND lmcrack 7584248B8D2C9F9E -v8
            -c zyxwvutsrqponmlkjihgfedcba -s A -e A -t 1)
  set_tests_properties(v8_cli_normalized_alphabet PROPERTIES
    PASS_REGULAR_EXPRESSION "found password : A")
  add_test(NAME v8_cli_reject_alphabet
    COMMAND lmcrack 7584248B8D2C9F9E -v8 -c ABC -s A -e A -t 1)
  set_tests_properties(v8_cli_reject_alphabet PROPERTIES WILL_FAIL TRUE)
  add_test(NAME v9_cli
    COMMAND lmcrack 25AD3B83FA6627C7 -v9 -s 0 -e 0 -t 1)
  set_tests_properties(v9_cli PROPERTIES
    PASS_REGULAR_EXPRESSION "found password : 0")
  add_test(NAME v9_cli_normalized_alphabet
    COMMAND lmcrack 25AD3B83FA6627C7 -v9
            -c zyxwvutsrqponmlkjihgfedcba9876543210 -s 0 -e 0 -t 1)
  set_tests_properties(v9_cli_normalized_alphabet PROPERTIES
    PASS_REGULAR_EXPRESSION "found password : 0")
  add_test(NAME v9_cli_reject_alphabet
    COMMAND lmcrack 25AD3B83FA6627C7 -v9 -c ABCDEFGHIJKLMNOPQRSTUVWXYZ
            -s A -e A -t 1)
  set_tests_properties(v9_cli_reject_alphabet PROPERTIES WILL_FAIL TRUE)
  add_test(NAME v9_cli_differential
    COMMAND ${CMAKE_COMMAND} -DLMCRACK_EXE=$<TARGET_FILE:lmcrack>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/v9_cli_differential.cmake)
  lmcrack_add_cpp_test(v8_uppercase_test v8_uppercase_test.cpp)
  lmcrack_add_cpp_test(v9_alnum_test v9_alnum_test.cpp)
  lmcrack_add_cpp_test(v9_bitslice_counter_test v9_bitslice_counter_test.cpp)
  lmcrack_add_cpp_test(v9_key_planes_test v9_key_planes_test.cpp)
  lmcrack_add_cpp_test(v9_generator_diff_test v9_generator_diff_test.cpp)
  lmcrack_add_cpp_test(fixed_bitslice_des_test fixed_bitslice_des_test.cpp)
  lmcrack_add_cpp_test(v9_worker_test v9_worker_test.cpp)
  lmcrack_add_cpp_test(v8_bitslice_counter_test v8_bitslice_counter_test.cpp)
  lmcrack_add_cpp_test(v8_key_planes_test v8_key_planes_test.cpp)
  lmcrack_add_cpp_test(v8_generator_diff_test v8_generator_diff_test.cpp)
  lmcrack_add_cpp_test(v8_direct_des_test v8_direct_des_test.cpp)
  lmcrack_add_cpp_test(v8_target_test v8_target_test.cpp)
  lmcrack_add_cpp_test(v8_worker_test v8_worker_test.cpp)
  lmcrack_add_cpp_test(bitslice_vec_test bitslice_vec_test.cpp)
  lmcrack_add_cpp_test(bitslice_batch_test bitslice_batch_test.cpp)
  lmcrack_add_cpp_test(bitslice_transpose_test bitslice_transpose_test.cpp)
  lmcrack_add_cpp_test(bitslice_key_test bitslice_key_test.cpp)
  lmcrack_add_cpp_test(bitslice_sbox_test bitslice_sbox_test.cpp)
  lmcrack_add_cpp_test(bitslice_des_test bitslice_des_test.cpp)
  lmcrack_add_cpp_test(bitslice_block_test bitslice_block_test.cpp)
  lmcrack_add_cpp_test(bitslice_match_test bitslice_match_test.cpp)
  lmcrack_add_cpp_test(bitslice_lm_test bitslice_lm_test.cpp)
endif()

target_compile_features(lmcrack PRIVATE cxx_std_11)
set_target_properties(lmhash PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)

find_package(Threads REQUIRED)
target_link_libraries(lmcrack PRIVATE Threads::Threads)

if(LMCRACK_ENABLE_PAIR256 AND LMCRACK_ENABLE_PAIR64)
  message(FATAL_ERROR "PAIR256 and PAIR64 cannot be enabled together")
elseif(LMCRACK_ENABLE_PAIR64)
  target_compile_definitions(lmcrack PRIVATE LMCRACK_PAIR64)
elseif(LMCRACK_ENABLE_PAIR256)
  target_compile_definitions(lmcrack PRIVATE LMCRACK_PAIR256)
endif()

if(LMCRACK_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT LMCRACK_LTO_SUPPORTED OUTPUT LMCRACK_LTO_ERROR)
  if(LMCRACK_LTO_SUPPORTED)
    set_property(TARGET lmcrack lmhash PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
  else()
    message(WARNING "LTO is not supported by this toolchain: ${LMCRACK_LTO_ERROR}")
  endif()
endif()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" LMCRACK_PROCESSOR)
set(LMCRACK_ARM64 FALSE)
set(LMCRACK_X86 FALSE)
if (LMCRACK_PROCESSOR MATCHES "^(aarch64|arm64|arm64ec)$")
  set(LMCRACK_ARM64 TRUE)
elseif (LMCRACK_PROCESSOR MATCHES "^(x86_64|amd64|x86|i[3-6]86)$")
  set(LMCRACK_X86 TRUE)
endif()

if(BUILD_TESTING)
  lmcrack_add_cpp_compile_test(bitslice_compile_scalar bitslice_lm_test.cpp SCALAR)
  lmcrack_add_cpp_test(v8_generator_diff_scalar_test v8_generator_diff_test.cpp
    TEST_NAME v8_generator_diff_scalar BACKEND SCALAR)
  lmcrack_add_cpp_test(v9_bitslice_counter_scalar_test v9_bitslice_counter_test.cpp
    TEST_NAME v9_bitslice_counter_scalar BACKEND SCALAR)
  lmcrack_add_cpp_test(v9_key_planes_scalar_test v9_key_planes_test.cpp
    TEST_NAME v9_key_planes_scalar BACKEND SCALAR)
  lmcrack_add_cpp_test(v9_generator_diff_scalar_test v9_generator_diff_test.cpp
    TEST_NAME v9_generator_diff_scalar BACKEND SCALAR)
  lmcrack_add_cpp_test(v9_worker_scalar_test v9_worker_test.cpp
    TEST_NAME v9_worker_scalar BACKEND SCALAR)
  lmcrack_add_cpp_test(v8_target_scalar_test v8_target_test.cpp
    TEST_NAME v8_target_scalar BACKEND SCALAR)
  lmcrack_add_cpp_test(v8_worker_scalar_test v8_worker_test.cpp
    TEST_NAME v8_worker_scalar BACKEND SCALAR)
  lmcrack_add_cpp_test(bitslice_lm_scalar_test bitslice_lm_test.cpp
    TEST_NAME bitslice_lm_scalar BACKEND SCALAR)
  if(LMCRACK_X86)
    lmcrack_add_cpp_compile_test(bitslice_compile_sse2 bitslice_lm_test.cpp SSE2)
    lmcrack_add_cpp_compile_test(bitslice_compile_avx2 bitslice_lm_test.cpp AVX2)
    lmcrack_add_cpp_compile_test(bitslice_compile_avx512 bitslice_lm_test.cpp AVX512)
    lmcrack_add_cpp_compile_test(v8_generator_diff_compile_avx2
      v8_generator_diff_test.cpp AVX2)
    lmcrack_add_cpp_compile_test(v9_bitslice_counter_compile_avx512
      v9_bitslice_counter_test.cpp AVX512)
    lmcrack_add_cpp_compile_test(v9_key_planes_compile_avx512
      v9_key_planes_test.cpp AVX512)
    lmcrack_add_cpp_compile_test(v9_generator_diff_compile_avx512
      v9_generator_diff_test.cpp AVX512)
    lmcrack_add_cpp_compile_test(v9_worker_compile_avx512
      v9_worker_test.cpp AVX512)
    lmcrack_add_cpp_compile_test(v8_generator_diff_compile_avx512
      v8_generator_diff_test.cpp AVX512)
    lmcrack_add_cpp_compile_test(v8_target_compile_avx2
      v8_target_test.cpp AVX2)
    lmcrack_add_cpp_compile_test(v8_target_compile_avx512
      v8_target_test.cpp AVX512)
    lmcrack_add_cpp_compile_test(v8_worker_compile_avx2
      v8_worker_test.cpp AVX2)
    lmcrack_add_cpp_compile_test(v8_worker_compile_avx512
      v8_worker_test.cpp AVX512)
    lmcrack_add_cpp_test(bitslice_lm_sse2_test bitslice_lm_test.cpp
      TEST_NAME bitslice_lm_sse2 BACKEND SSE2)
    lmcrack_add_cpp_test(v8_generator_diff_sse2_test v8_generator_diff_test.cpp
      TEST_NAME v8_generator_diff_sse2 BACKEND SSE2)
    lmcrack_add_cpp_test(v9_bitslice_counter_sse2_test v9_bitslice_counter_test.cpp
      TEST_NAME v9_bitslice_counter_sse2 BACKEND SSE2)
    lmcrack_add_cpp_test(v9_key_planes_sse2_test v9_key_planes_test.cpp
      TEST_NAME v9_key_planes_sse2 BACKEND SSE2)
    lmcrack_add_cpp_test(v9_generator_diff_sse2_test v9_generator_diff_test.cpp
      TEST_NAME v9_generator_diff_sse2 BACKEND SSE2)
    lmcrack_add_cpp_test(v9_worker_sse2_test v9_worker_test.cpp
      TEST_NAME v9_worker_sse2 BACKEND SSE2)
    lmcrack_add_cpp_test(v8_target_sse2_test v8_target_test.cpp
      TEST_NAME v8_target_sse2 BACKEND SSE2)
    lmcrack_add_cpp_test(v8_worker_sse2_test v8_worker_test.cpp
      TEST_NAME v8_worker_sse2 BACKEND SSE2)
    if(LMCRACK_TEST_AVX2)
      lmcrack_add_cpp_test(bitslice_lm_avx2_test bitslice_lm_test.cpp
        TEST_NAME bitslice_lm_avx2 BACKEND AVX2)
      lmcrack_add_cpp_test(v9_bitslice_counter_avx2_test v9_bitslice_counter_test.cpp
        TEST_NAME v9_bitslice_counter_avx2 BACKEND AVX2)
      lmcrack_add_cpp_test(v9_key_planes_avx2_test v9_key_planes_test.cpp
        TEST_NAME v9_key_planes_avx2 BACKEND AVX2)
      lmcrack_add_cpp_test(v9_generator_diff_avx2_test v9_generator_diff_test.cpp
        TEST_NAME v9_generator_diff_avx2 BACKEND AVX2)
      lmcrack_add_cpp_test(v9_worker_avx2_test v9_worker_test.cpp
        TEST_NAME v9_worker_avx2 BACKEND AVX2)
      lmcrack_add_cpp_test(v8_generator_diff_avx2_test v8_generator_diff_test.cpp
        TEST_NAME v8_generator_diff_avx2 BACKEND AVX2)
      lmcrack_add_cpp_test(v8_target_avx2_test v8_target_test.cpp
        TEST_NAME v8_target_avx2 BACKEND AVX2)
      lmcrack_add_cpp_test(v8_worker_avx2_test v8_worker_test.cpp
        TEST_NAME v8_worker_avx2 BACKEND AVX2)
    endif()
    if(LMCRACK_TEST_AVX512)
      lmcrack_add_cpp_test(bitslice_lm_avx512_test bitslice_lm_test.cpp
        TEST_NAME bitslice_lm_avx512 BACKEND AVX512)
    endif()
  elseif(LMCRACK_ARM64)
    lmcrack_add_cpp_compile_test(bitslice_compile_neon bitslice_lm_test.cpp NEON)
    lmcrack_add_cpp_test(bitslice_lm_neon_test bitslice_lm_test.cpp
      TEST_NAME bitslice_lm_neon BACKEND NEON)
    lmcrack_add_cpp_test(v9_bitslice_counter_neon_test v9_bitslice_counter_test.cpp
      TEST_NAME v9_bitslice_counter_neon BACKEND NEON)
    lmcrack_add_cpp_test(v9_key_planes_neon_test v9_key_planes_test.cpp
      TEST_NAME v9_key_planes_neon BACKEND NEON)
    lmcrack_add_cpp_test(v9_generator_diff_neon_test v9_generator_diff_test.cpp
      TEST_NAME v9_generator_diff_neon BACKEND NEON)
    lmcrack_add_cpp_test(v9_worker_neon_test v9_worker_test.cpp
      TEST_NAME v9_worker_neon BACKEND NEON)
    lmcrack_add_cpp_test(v8_generator_diff_neon_test v8_generator_diff_test.cpp
      TEST_NAME v8_generator_diff_neon BACKEND NEON)
    lmcrack_add_cpp_test(v8_target_neon_test v8_target_test.cpp
      TEST_NAME v8_target_neon BACKEND NEON)
    lmcrack_add_cpp_test(v8_worker_neon_test v8_worker_test.cpp
      TEST_NAME v8_worker_neon BACKEND NEON)
  endif()
endif()

if(LMCRACK_ENABLE_SANITIZERS)
  if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang)$" AND
     CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    foreach(target lmcrack lmhash v8_uppercase_test v8_bitslice_counter_test
                   v9_alnum_test
                   v9_bitslice_counter_test
                   v9_key_planes_test
                   v9_generator_diff_test
                   fixed_bitslice_des_test
                   v9_worker_test
                   v8_key_planes_test v8_generator_diff_test v8_direct_des_test
                   v8_target_test
                   v8_worker_test
                   bitslice_vec_test bitslice_batch_test
                   bitslice_transpose_test bitslice_key_test bitslice_sbox_test
                   bitslice_des_test)
      if(TARGET ${target})
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
      endif()
    endforeach()
  else()
    message(FATAL_ERROR "LMCRACK_ENABLE_SANITIZERS requires GCC or Clang")
  endif()
endif()

if(LMCRACK_NATIVE_CPU)
  if(CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "LMCRACK_NATIVE_CPU cannot be used while cross-compiling")
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    if(LMCRACK_ARM64)
      target_compile_options(lmcrack PRIVATE -mcpu=native)
      target_compile_options(lmhash PRIVATE -mcpu=native)
    elseif(LMCRACK_X86)
      target_compile_options(lmcrack PRIVATE -march=native)
      target_compile_options(lmhash PRIVATE -march=native)
    endif()
  elseif(NOT MSVC)
    message(WARNING "Native CPU tuning is not configured for this compiler")
  endif()
endif()

if (LMCRACK_ARM64 AND LMCRACK_ENABLE_NEON)
  # Advanced SIMD is part of AArch64, so no extra compiler flag is needed.
  target_compile_definitions(lmcrack PRIVATE LMCRACK_NEON)
  target_compile_definitions(v9_profile PRIVATE LMCRACK_NEON)
elseif (LMCRACK_X86 AND LMCRACK_ENABLE_AVX512)
  target_compile_definitions(lmcrack PRIVATE AVX512)
  target_compile_definitions(v9_profile PRIVATE AVX512)
  if (MSVC)
    target_compile_options(lmcrack PRIVATE /arch:AVX512)
    target_compile_options(v9_profile PRIVATE /arch:AVX512)
  else()
    target_compile_options(lmcrack PRIVATE -mavx512f)
    target_compile_options(v9_profile PRIVATE -mavx512f)
    if(MINGW)
      target_compile_options(lmcrack PRIVATE -mstackrealign)
      target_compile_options(v9_profile PRIVATE -mstackrealign)
    endif()
  endif()
elseif (LMCRACK_X86 AND LMCRACK_ENABLE_AVX2)
  target_compile_definitions(lmcrack PRIVATE AVX2)
  if (MSVC)
    target_compile_options(lmcrack PRIVATE /arch:AVX2)
    target_compile_options(v9_profile PRIVATE /arch:AVX2)
  else()
    target_compile_options(lmcrack PRIVATE -mavx2)
    target_compile_options(v9_profile PRIVATE -mavx2)
    if(MINGW)
      target_compile_options(lmcrack PRIVATE -mstackrealign)
      target_compile_options(v9_profile PRIVATE -mstackrealign)
    endif()
  endif()
  target_compile_definitions(v9_profile PRIVATE AVX2)
elseif (LMCRACK_X86 AND LMCRACK_ENABLE_SSE2)
  target_compile_definitions(lmcrack PRIVATE SSE2)
  if (MSVC)
    target_compile_options(lmcrack PRIVATE /arch:SSE2)
    target_compile_options(v9_profile PRIVATE /arch:SSE2)
  else()
    target_compile_options(lmcrack PRIVATE -msse2)
    target_compile_options(v9_profile PRIVATE -msse2)
  endif()
  target_compile_definitions(v9_profile PRIVATE SSE2)
endif()
