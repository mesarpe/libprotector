cmake_minimum_required (VERSION 3.0)
project (prime)
#cmake -DCMAKE_BUILD_TYPE=Debug .
#add_library(src/lib/user.cc src/lib/kms.cc src/lib/user.cc src/lib/hashtable.cc src/tools/prime.cc)

#SET(GCC_COVERAGE_COMPILE_FLAGS "-fpermissive -g -std=c++11 -I /usr/include/openssl/ -lcrypto")
SET(GCC_COVERAGE_COMPILE_FLAGS "-fpermissive -std=c++11 -I /usr/include/openssl/")
SET(GCC_COVERAGE_LINK_FLAGS    "-lcrypto -lssl")

SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )
SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}" )
find_library (CRYPTO_LIBRARY crypto ssl)

add_executable(prime src/tools/prime.cc src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/prime.cc)
add_executable(kms_server src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/kms_server.cc)
add_executable(kms_client src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/kms_client.cc)
add_executable(servicetime_encrypt src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc src/tools/servicetime_encrypt.cc)
add_executable(names src/tools/names.cc src/lib/kms.cc src/lib/hashtable.cc src/lib/hashtable.cc src/lib/user.cc src/lib/utils.cc)
add_executable(test_runner src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc test/runner.cc)

target_link_libraries (prime crypto ssl)
target_link_libraries (kms_server crypto ssl)
target_link_libraries (kms_client crypto ssl)
target_link_libraries (servicetime_encrypt crypto ssl)
target_link_libraries (names crypto ssl)
target_link_libraries (test_runner crypto ssl)

add_library(protector SHARED src/lib/user.cc src/lib/kms.cc src/lib/ccn.cc src/lib/hashtable.cc src/lib/utils.cc)
target_link_libraries (protector crypto ssl)
