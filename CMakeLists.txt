cmake_minimum_required(VERSION 3.16)


project(utfs_xchacha20_provider C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_STANDARD_REQUIRED ON)


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

