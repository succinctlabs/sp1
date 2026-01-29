cmake_minimum_required(VERSION 3.18)
project(sp1-gpu-sys-cuda LANGUAGES CXX CUDA)

# Set the project root directory
set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# Include the main CUDA build
add_subdirectory(${PROJECT_ROOT} ${CMAKE_CURRENT_BINARY_DIR}/cuda-build)
