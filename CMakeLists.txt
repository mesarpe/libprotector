cmake_minimum_required (VERSION 3.0)
project (prime)

#add_library(src/lib/user.cc src/lib/kms.cc src/lib/user.cc src/lib/hashtable.cc src/tools/prime.cc)

SET(GCC_COVERAGE_COMPILE_FLAGS "-fpermissive -g -std=c++11 -I /usr/include/openssl/ -lcrypto")
SET(GCC_COVERAGE_LINK_FLAGS    "")

SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )
SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}" )


add_executable(prime src/tools/prime.cc src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/prime.cc)
add_executable(kms_server src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/kms_server.cc)
add_executable(kms_client src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/kms_client.cc)
add_executable(servicetime_encrypt src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/servicetime_encrypt.cc)
add_executable(names src/tools/names.cc src/lib/kms.cc src/lib/hashtable.cc)
add_executable(test_runner src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc test/runner.cc)

add_library(protector SHARED src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc)
