project(INC C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

include_directories(include third_party/C-Thread-Pool)

set(COMMON_SRCS
    src/api.c
    src/util.c
    src/log.c
    src/rule.c
)

set(CONFIG_PARSER src/topo_parser.cpp)

# 优化编译选项
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(OPT_FLAGS -O3 -march=native -funroll-loops)
endif()

# switch
add_executable(switch src/switch.c third_party/C-Thread-Pool/thpool.c ${COMMON_SRCS} ${CONFIG_PARSER})
target_link_libraries(switch ibverbs pthread pcap yaml-cpp)
if(OPT_FLAGS)
    target_compile_options(switch PRIVATE ${OPT_FLAGS})
endif()

# host
add_executable(host src/host.c ${COMMON_SRCS} ${CONFIG_PARSER})
target_link_libraries(host ibverbs pthread yaml-cpp)
if(OPT_FLAGS)
    target_compile_options(host PRIVATE ${OPT_FLAGS})
endif()
