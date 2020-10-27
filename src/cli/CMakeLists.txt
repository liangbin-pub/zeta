# SPDX-License-Identifier: MIT
#
# Copyright (c) 2020 The Authors.
# Authors: Bin Liang         <@liangbin>
#
# Summary: cli CMake listfile for zeta project

message("Processing src/cli/CMakeList.txt")

file(GLOB SOURCE ${CMAKE_CURRENT_LIST_DIR}/*.c)

add_executable(transit ${RPCGEN_CLNT} ${SOURCE})
add_dependencies(transit rpcgen)
target_link_libraries(transit extern)
set_target_properties(transit PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin
                      RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin
)

file(GLOB TEST_SOURCE ${CMAKE_CURRENT_LIST_DIR}/test/*.c ${CMAKE_CURRENT_LIST_DIR}/*.c)
list(REMOVE_ITEM TEST_SOURCE ${CMAKE_CURRENT_LIST_DIR}/trn_cli.c)
set(CLI_MOCKS "-Wl,--wrap=update_vpc_1 \
    -Wl,--wrap=update_net_1 \
    -Wl,--wrap=update_ep_1 \
    -Wl,--wrap=update_agent_ep_1 \
    -Wl,--wrap=update_agent_md_1 \
    -Wl,--wrap=load_transit_xdp_1 \
    -Wl,--wrap=unload_transit_xdp_1 \
    -Wl,--wrap=load_transit_agent_xdp_1 \
    -Wl,--wrap=unload_transit_agent_xdp_1 \
    -Wl,--wrap=get_vpc_1 \
    -Wl,--wrap=get_net_1 \
    -Wl,--wrap=get_ep_1 \
    -Wl,--wrap=get_agent_ep_1 \
    -Wl,--wrap=get_agent_md_1 \
    -Wl,--wrap=delete_vpc_1 \
    -Wl,--wrap=delete_net_1 \
    -Wl,--wrap=delete_ep_1 \
    -Wl,--wrap=delete_agent_ep_1 \
    -Wl,--wrap=delete_agent_md_1 \
    -Wl,--wrap=setrlimit")

add_executable(test_cli ${RPCGEN_CLNT} ${TEST_SOURCE})
# Add test coverage compiler flags
target_compile_options(test_cli PRIVATE -fprofile-arcs -ftest-coverage)
# Add CMocka unit test and cJSON to linker flags
target_link_libraries(test_cli extern -lgcov --coverage -lcmocka ${CLI_MOCKS})
set_target_properties(test_cli PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/tests
                      RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME test_cli COMMAND test_cli)