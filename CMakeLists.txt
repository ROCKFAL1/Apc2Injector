cmake_minimum_required(VERSION 3.20)
project(Apc2Injector)

find_package(wil)
find_package(xbyak CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(Apc2Injector "main.cpp")
target_compile_definitions(Apc2Injector PRIVATE NOMINMAX)
target_link_libraries(Apc2Injector PRIVATE WIL::WIL xbyak::xbyak)


add_library(Apc2Dll SHARED "dll.cpp")

