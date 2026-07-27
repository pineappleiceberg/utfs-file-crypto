cmake_minimum_required(VERSION 3.16)


project(utfs_xchacha20_provider C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_STANDARD_REQUIRED ON)

option(XCP_ENABLE_ASAN "builds with address sanitizer" OFF)

if(XCP_ENABLE_ASAN)
 if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
  message(FATAL_ERROR "XCP_ENABLE_ASAN requires GCC")
 endif()
add_compile_options(-fsanitize=address -fno-omit-frame-pointer)

add_link_options(-fsanitize=address)
endif()

add_library(
xcp
STATIC
src/xcp.c
)


target_include_directories(xcp PUBLIC include)

if(MSVC)
target_compile_options(xcp PRIVATE /W4)
else()
target_compile_options(xcp PRIVATE -Wall -Wextra -Wpedantic)
endif()


enable_testing()

add_executable(xcp_chacha20_block_test
tests/chacha20_block_test.c)

target_link_libraries(xcp_chacha20_block_test PRIVATE xcp)

add_test(NAME xcp_chacha20_block_test
COMMAND xcp_chacha20_block_test)

add_executable(xcp_chacha20_xor_limit_test
tests/chacha20_xor_limit_test.c)

target_link_libraries(xcp_chacha20_xor_limit_test PRIVATE xcp)

add_test(NAME xcp_chacha20_xor_limit_test COMMAND xcp_chacha20_xor_limit_test)



add_executable(xcp_chacha20_xor_api_test
tests/chacha20_xor_api_test.c)

target_link_libraries(xcp_chacha20_xor_api_test PRIVATE xcp)

add_test(NAME xcp_chacha20_xor_api_test COMMAND xcp_chacha20_xor_api_test)
