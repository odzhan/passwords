# Apply one of lmcrack's compile-time bitslice backends to a target.
function(lmcrack_configure_simd target backend)
  string(TOUPPER "${backend}" backend_upper)

  if(backend_upper STREQUAL "SCALAR")
    target_compile_definitions(${target} PRIVATE LMCRACK_BITSLICE_SCALAR)
  elseif(backend_upper STREQUAL "SSE2")
    target_compile_definitions(${target} PRIVATE SSE2)
    if(NOT MSVC)
      target_compile_options(${target} PRIVATE -msse2)
    endif()
  elseif(backend_upper STREQUAL "AVX2")
    target_compile_definitions(${target} PRIVATE AVX2)
    target_compile_options(${target} PRIVATE
      $<$<CXX_COMPILER_ID:MSVC>:/arch:AVX2>
      $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-mavx2>)
  elseif(backend_upper STREQUAL "AVX512")
    target_compile_definitions(${target} PRIVATE AVX512)
    target_compile_options(${target} PRIVATE
      $<$<CXX_COMPILER_ID:MSVC>:/arch:AVX512>
      $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-mavx512f>)
  elseif(backend_upper STREQUAL "NEON")
    target_compile_definitions(${target} PRIVATE LMCRACK_NEON)
  else()
    message(FATAL_ERROR "Unknown lmcrack SIMD backend: ${backend}")
  endif()
endfunction()
