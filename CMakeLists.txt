cmake_minimum_required(VERSION 3.10)
project(SwitchHostProject C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

include_directories(include)

set(COMMON_SRCS
    src/api.c
    src/util.c
    src/log.c
    src/rule.c
)

# switch
add_executable(switch src/switch.c ${COMMON_SRCS})
target_link_libraries(switch ibverbs pthread pcap)

# host
add_executable(host src/host.c ${COMMON_SRCS})
target_link_libraries(host ibverbs pthread)
