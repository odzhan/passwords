if(NOT DEFINED LMCRACK_EXE)
  message(FATAL_ERROR "LMCRACK_EXE is required")
endif()

set(V9_ALPHA "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")

function(check_all_versions password hash start_password end_password threads)
  execute_process(
    COMMAND "${LMCRACK_EXE}" "${hash}" -v4 -v7 -v9 -c "${V9_ALPHA}"
            -s "${start_password}" -e "${end_password}" -t "${threads}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
    TIMEOUT 60)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${password}: lmcrack failed (${result})\n${output}\n${error}")
  endif()
  string(REGEX MATCHALL "found password : ${password}" matches "${output}")
  list(LENGTH matches match_count)
  if(NOT match_count EQUAL 3)
    message(FATAL_ERROR
      "${password}: expected v4, v7, and v9 to find the password\n${output}\n${error}")
  endif()
endfunction()

# One digits-only, letters-only, or mixed password at every supported length.
check_all_versions("0"       "25AD3B83FA6627C7" "0"       "0"       1)
check_all_versions("A9"      "25AB6815ADDE7619" "A9"      "A9"      1)
check_all_versions("0A9"     "2608578BA0BBB0E1" "0A9"     "0A9"     1)
check_all_versions("A0B9"    "DC1F55316392D8F7" "A0B9"    "A0B9"    1)
check_all_versions("12ABC"   "339AB50DA9125AC1" "12ABC"   "12ABC"   1)
check_all_versions("A1B2C3"  "9C2A030F0B086B69" "A1B2C3"  "A1B2C3"  1)
check_all_versions("0A1B2C3" "DB6609125398C817" "0A1B2C3" "0A1B2C3" 1)

# Every password-length transition.
check_all_versions("00"      "41A86CC7FA9D87FE" "Z"      "00"      1)
check_all_versions("000"     "AE91A15A9FDF9D77" "ZZ"     "000"     1)
check_all_versions("0000"    "41163B31FF9B73BB" "ZZZ"    "0000"    1)
check_all_versions("00000"   "39D0AFA8D7343A40" "ZZZZ"   "00000"   1)
check_all_versions("000000"  "283CF1EB6EC4CCDA" "ZZZZZ"  "000000"  1)
check_all_versions("0000000" "6040ADAF16D5D555" "ZZZZZZ" "0000000" 1)

# An uneven 12,101-candidate range split among three workers.
check_all_versions("0A1B2C3" "DB6609125398C817" "O0SA2C3" "SC1B2C3" 3)
