cmake_minimum_required(VERSION 3.20)
project(WindowsProcessMemoryReadWrite)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME}
        src/PEProcess.cpp src/PEProcess.h)
