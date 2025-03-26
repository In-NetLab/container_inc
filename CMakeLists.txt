cmake_minimum_required(VERSION 3.10)

project(iccl C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug)
add_compile_options(-O0 -g -Wall -Wextra -pedantic)

add_library(libiccl STATIC flow.c group.c transfer.c termination_api.c)

add_executable(host host.c)
target_link_directories(host PUBLIC /home/ruizhe/netlab/comm_lib)
target_link_libraries(host PUBLIC libiccl ibverbs)
target_include_directories(host PUBLIC /home/ruizhe/netlab/comm_lib)
