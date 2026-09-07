if(NOT DEFINED DESTOOL_EXE)
  message(FATAL_ERROR "DESTOOL_EXE is required")
endif()

function(run_destool expected_exit expected_text)
  execute_process(
    COMMAND "${DESTOOL_EXE}" ${ARGN}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  string(CONCAT combined "${output}" "${error}")
  if(NOT result EQUAL expected_exit)
    message(FATAL_ERROR
      "destool returned ${result}, expected ${expected_exit}\n${combined}")
  endif()
  if(NOT combined MATCHES "${expected_text}")
    message(FATAL_ERROR
      "destool output did not match '${expected_text}'\n${combined}")
  endif()
endfunction()

run_destool(0 "Usage:" --help)

# FIPS 46-3/NIST canonical DES example. The raw alphabet-1 endpoint is the
# seven effective key bytes corresponding to odd-parity DES key
# 133457799BBCDFF1.
run_destool(0 "DES key hex   : 133457799BBCDFF1"
  0123456789ABCDEF 85E813540F0AB405 -a 1 -l 7
  -s 12695BC9B7B7F8 -e 12695BC9B7B7F8 -t 1)

# LM plaintext encrypted by one-byte candidate "0".
run_destool(0 "found key hex : 30"
  4B47532140232425 25AD3B83FA6627C7 -a 2 -l 1 -t 3)
run_destool(0 "found key text: .0."
  4B47532140232425 25AD3B83FA6627C7 -a 2 -l 1 -t 1 -s 30 -e 30)
run_destool(0 "M k/s [0-9]+% complete. ETA: [0-9]+ days"
  4B47532140232425 25AD3B83FA6627C7 -a 2 -l 1 -t 1 -s 30 -e 30)

# Uppercase "A" is not in the one-byte decimal search space.
run_destool(1 "key space exhausted"
  4B47532140232425 7584248B8D2C9F9E -a 2 -l 1 -t 3)

run_destool(2 "exactly 16 hexadecimal"
  00 7584248B8D2C9F9E -a 3 -l 1)
run_destool(2 "start key follows end key"
  4B47532140232425 7584248B8D2C9F9E -a 3 -l 1 -s 5A -e 41)
run_destool(2 "selected alphabet"
  4B47532140232425 7584248B8D2C9F9E -a 3 -l 1 -s 30)
run_destool(2 "thread count must be between"
  4B47532140232425 7584248B8D2C9F9E -a 3 -l 1 -t 33)
run_destool(2 "unknown option"
  4B47532140232425 7584248B8D2C9F9E -a 3 -l 1 --unknown value)
