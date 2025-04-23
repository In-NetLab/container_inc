project(INC C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

include_directories(include)

set(COMMON_SRCS
    src/api.c
    src/util.c
    src/log.c
    src/rule.c
)

set(CONFIG_PARSER src/topo_parser.cpp)

# switch
add_executable(switch src/switch.c ${COMMON_SRCS} ${CONFIG_PARSER})
target_link_libraries(switch ibverbs pthread pcap yaml-cpp)

# host
add_executable(host src/host.c ${COMMON_SRCS} ${CONFIG_PARSER})
target_link_libraries(host ibverbs pthread yaml-cpp)
