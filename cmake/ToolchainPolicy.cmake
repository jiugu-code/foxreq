function(foxreq_apply_c_policy target)
  set_target_properties(
    "${target}"
    PROPERTIES
      C_STANDARD 11
      C_STANDARD_REQUIRED YES
      C_EXTENSIONS NO
  )

  if(MSVC)
    target_compile_options("${target}" PRIVATE /W4 /WX /permissive-)
  else()
    target_compile_options("${target}" PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endfunction()
