cmake_minimum_required(VERSION 3.5.1)
project(lws-module-sdk-c)

set(CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_DIR})

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)

# main
set(src main.c lwc_module.c lwc_module.h)
add_executable(lwcm ${src})
target_link_libraries(lwcm)