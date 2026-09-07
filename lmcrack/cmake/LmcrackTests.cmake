include(CMakeParseArguments)

function(lmcrack_resolve_test_source output_variable source)
  if(IS_ABSOLUTE "${source}" AND EXISTS "${source}")
    set(${output_variable} "${source}" PARENT_SCOPE)
    return()
  endif()

  foreach(test_group bitslice destool v8 v9 v11)
    set(candidate "${PROJECT_SOURCE_DIR}/tests/${test_group}/${source}")
    if(EXISTS "${candidate}")
      set(${output_variable} "${candidate}" PARENT_SCOPE)
      return()
    endif()
  endforeach()

  message(FATAL_ERROR "Could not locate lmcrack test source: ${source}")
endfunction()

# Register a C++ executable test with an optional compile-time SIMD backend.
function(lmcrack_add_cpp_test target source)
  cmake_parse_arguments(ARG "" "TEST_NAME;BACKEND" "" ${ARGN})

  lmcrack_resolve_test_source(source_path "${source}")
  add_executable(${target} "${source_path}")
  target_compile_features(${target} PRIVATE cxx_std_11)
  target_link_libraries(${target} PRIVATE lmcrack_internal Threads::Threads)
  # The tests use assert() as their lightweight check mechanism. Keep those
  # checks active even when the tested implementation is optimized as Release.
  target_compile_options(${target} PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/UNDEBUG>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-UNDEBUG>)
  if(ARG_BACKEND)
    lmcrack_configure_simd(${target} "${ARG_BACKEND}")
  endif()

  if(ARG_TEST_NAME)
    set(test_name "${ARG_TEST_NAME}")
  else()
    string(REGEX REPLACE "_test$" "" test_name "${target}")
  endif()
  add_test(NAME ${test_name} COMMAND ${target})
endfunction()

# Compile a source for a backend without registering a runtime test. This is
# used for AVX-512 validation on hosts that cannot execute AVX-512 binaries.
function(lmcrack_add_cpp_compile_test target source backend)
  lmcrack_resolve_test_source(source_path "${source}")
  add_library(${target} OBJECT "${source_path}")
  target_compile_features(${target} PRIVATE cxx_std_11)
  target_link_libraries(${target} PRIVATE lmcrack_internal)
  lmcrack_configure_simd(${target} "${backend}")
endfunction()
