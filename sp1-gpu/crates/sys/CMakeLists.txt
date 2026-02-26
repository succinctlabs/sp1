cmake_minimum_required(VERSION 3.30)
project(sp1-gpu-cuda LANGUAGES CXX CUDA)

# Require CUDA 12.0+
find_package(CUDAToolkit 12.0 REQUIRED)

# Get CUDA version for architecture selection
set(CUDA_VERSION_MAJOR ${CUDAToolkit_VERSION_MAJOR})
set(CUDA_VERSION_MINOR ${CUDAToolkit_VERSION_MINOR})

# C++20 for both host and CUDA code
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 20)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# Don't use response files for CUDA includes - this breaks clangd IDE support
# because clangd can't parse the --options-file flag
set(CMAKE_CUDA_USE_RESPONSE_FILE_FOR_INCLUDES OFF)

# Architecture flags
if(DEFINED CUDA_ARCHS)
    # Convert comma-separated string to CMake list (semicolon-separated)
    string(REPLACE "," ";" CUDA_ARCHS_LIST "${CUDA_ARCHS}")
    set(CMAKE_CUDA_ARCHITECTURES ${CUDA_ARCHS_LIST})
elseif(CUDA_VERSION_MAJOR EQUAL 12 AND CUDA_VERSION_MINOR GREATER_EQUAL 8)
    set(CMAKE_CUDA_ARCHITECTURES 80 86 89 90 100 120)
elseif(CUDA_VERSION_MAJOR GREATER_EQUAL 13)
    set(CMAKE_CUDA_ARCHITECTURES 80 86 89 90 100 120)
else()
    set(CMAKE_CUDA_ARCHITECTURES 80 86 89)
endif()

# Build type defaults to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Common CUDA flags
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -default-stream=per-thread")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --expt-relaxed-constexpr")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --use_fast_math")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -lineinfo")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler -fopenmp")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler -fPIE")

# Enable relocatable device code for cross-file device function calls
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -rdc=true")

# Debug flags
if(PROFILE_DEBUG_DATA)
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -G")
endif()

# Release optimization
set(CMAKE_CUDA_FLAGS_RELEASE "-O3")
set(CMAKE_CUDA_FLAGS_DEBUG "-O3")  # Currently both use O3 per original Makefile

# Get the actual source directory (where this CMakeLists.txt lives)
set(CSL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Create an INTERFACE library for common settings (following CUTLASS pattern)
# All CUDA modules link to this to get proper include paths and definitions
add_library(sp1_gpu_common INTERFACE)
target_include_directories(sp1_gpu_common INTERFACE
    ${CSL_SOURCE_DIR}/include
    ${CSL_SOURCE_DIR}/sppark
    ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
)
target_compile_definitions(sp1_gpu_common INTERFACE SPPARK FEATURE_KOALA_BEAR)

# Add cbindgen include directory if provided
if(DEFINED CBINDGEN_INCLUDE_DIR)
    target_include_directories(sp1_gpu_common INTERFACE ${CBINDGEN_INCLUDE_DIR})
endif()

# Output directories - use the project root's target directory
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CSL_SOURCE_DIR}/target/cuda-build/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CSL_SOURCE_DIR}/target/cuda-build/lib)

# Add subdirectories for each module
add_subdirectory(lib/algebra)
add_subdirectory(lib/basefold)
add_subdirectory(lib/challenger)
add_subdirectory(lib/experimental)
add_subdirectory(lib/jagged_assist)
add_subdirectory(lib/jagged_sumcheck)
add_subdirectory(lib/logup_gkr)
add_subdirectory(lib/merkle_tree)
add_subdirectory(lib/mle)
add_subdirectory(lib/ntt)
add_subdirectory(lib/runtime)
add_subdirectory(lib/scan)
add_subdirectory(lib/sum_and_reduce)
add_subdirectory(lib/tracegen)
add_subdirectory(lib/transpose)
add_subdirectory(lib/zerocheck)

# Sppark sources (external library, kept separate)
# These are C++ files that need CUDA headers
add_library(sppark_objs OBJECT
    ${CSL_SOURCE_DIR}/sppark/lib.cpp
    ${CSL_SOURCE_DIR}/sppark/util/all_gpus.cpp
)
target_link_libraries(sppark_objs PRIVATE sp1_gpu_common)

# Collect all object libraries
set(ALL_CUDA_OBJECTS
    $<TARGET_OBJECTS:algebra_objs>
    $<TARGET_OBJECTS:basefold_objs>
    $<TARGET_OBJECTS:challenger_objs>
    $<TARGET_OBJECTS:experimental_objs>
    $<TARGET_OBJECTS:jagged_assist_objs>
    $<TARGET_OBJECTS:jagged_sumcheck_objs>
    $<TARGET_OBJECTS:logup_gkr_objs>
    $<TARGET_OBJECTS:merkle_tree_objs>
    $<TARGET_OBJECTS:mle_objs>
    $<TARGET_OBJECTS:ntt_objs>
    $<TARGET_OBJECTS:runtime_objs>
    $<TARGET_OBJECTS:scan_objs>
    $<TARGET_OBJECTS:sum_and_reduce_objs>
    $<TARGET_OBJECTS:tracegen_objs>
    $<TARGET_OBJECTS:transpose_objs>
    $<TARGET_OBJECTS:zerocheck_objs>
    $<TARGET_OBJECTS:sppark_objs>
)

# Create static library with device linking
add_library(sys-cuda STATIC ${ALL_CUDA_OBJECTS})
set_target_properties(sys-cuda PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
)

if(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL 13.0)
    # nothing needed
else()
    target_link_libraries(sys-cuda PRIVATE
        CUDA::cudart
        CUDA::nvToolsExt
    )
endif()

# Install rule
install(TARGETS sys-cuda
    ARCHIVE DESTINATION lib
)
