cmake_minimum_required(VERSION 3.30)

project(apt_detection)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(src/common src/software)

add_executable(${PROJECT_NAME} main.cpp)
