dnl Simulated malicious configure script
dnl simulating CVE-2024-3094 style obfuscation

AC_DEFUN([gl_TEST_MACRO], [
  dnl The payload is hidden in a variable
  gl_path_map='H4sIAAAAAAAAA+3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAOA4y7X7wCgAA'
  
  dnl suspicious execution chain: eval + pipe + tr/sed/head
  dnl This matches the generic heuristic we added
  eval $gl_path_map | base64 -d | tr "A-Z" "a-z" | sh
])
