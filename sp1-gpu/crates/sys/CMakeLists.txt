cmake_minimum_required(VERSION 3.30)

# ===========================================================================
# Backend selection: USE_HIP=ON for AMD GPUs, default is NVIDIA CUDA.
# Set from build.rs via -DUSE_HIP=ON when HIP/ROCm is detected.
# ===========================================================================
option(USE_HIP "Build with HIP/ROCm for AMD GPUs instead of CUDA" OFF)

if(USE_HIP)
    # -----------------------------------------------------------------------
    # HIP / ROCm path
    # -----------------------------------------------------------------------
    project(sp1-gpu-hip LANGUAGES CXX HIP)

    # C++20 for both host and HIP device code
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_HIP_STANDARD 20)
    set(CMAKE_HIP_STANDARD_REQUIRED ON)

    # GPU architecture selection
    if(DEFINED HIP_ARCHS)
        string(REPLACE "," ";" HIP_ARCHS_LIST "${HIP_ARCHS}")
        set(CMAKE_HIP_ARCHITECTURES ${HIP_ARCHS_LIST})
    else()
        # Default: RDNA4 (gfx1201) + RDNA3 (gfx1100)
        set(CMAKE_HIP_ARCHITECTURES gfx1100 gfx1201)
    endif()

    # Build type defaults to Release
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()

    # Tell CMake to treat .cu files as HIP sources.
    # By default CMake only associates .hip files with the HIP language.
    # Adding "cu" here lets our existing .cu files compile with hipcc unchanged.
    set(CMAKE_HIP_SOURCE_FILE_EXTENSIONS hip cu)

    # HIP compiler flags
    # -fgpu-rdc: relocatable device code (equivalent to nvcc -rdc=true)
    # -ffast-math: equivalent to --use_fast_math
    # -munsafe-fp-atomics: allow fast atomic fadd on RDNA
    # Note: -fgpu-rdc is NOT used. Each .cu file is compiled as a standalone
    # HIP compilation unit. Cross-TU __constant__ symbols are accessed via
    # cudaGetSymbolAddress() at runtime (not compile-time cross-TU references).
    # This avoids the need for device linking which Rust's cc linker can't do.
    # set(CMAKE_HIP_FLAGS "${CMAKE_HIP_FLAGS} -fgpu-rdc")
    set(CMAKE_HIP_FLAGS "${CMAKE_HIP_FLAGS} -ffast-math")
    set(CMAKE_HIP_FLAGS "${CMAKE_HIP_FLAGS} -munsafe-fp-atomics")
    set(CMAKE_HIP_FLAGS "${CMAKE_HIP_FLAGS} -fopenmp")
    set(CMAKE_HIP_FLAGS "${CMAKE_HIP_FLAGS} -fPIE")

    # HIP's compiler handles CUDA API mapping natively in ROCm 7.2+.
    # No need for cuda2hip.hpp global include.

    # Release optimization
    set(CMAKE_HIP_FLAGS_RELEASE "-O3")
    set(CMAKE_HIP_FLAGS_DEBUG "-O3")

    # Get the actual source directory
    set(CSL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

    # Common settings for all modules
    add_library(sp1_gpu_common INTERFACE)
    target_include_directories(sp1_gpu_common INTERFACE
        ${CSL_SOURCE_DIR}/include
        ${CSL_SOURCE_DIR}/sppark
        ${CSL_SOURCE_DIR}/sppark/util   # for cuda2hip.hpp (included via -include flag)
    )
    target_compile_definitions(sp1_gpu_common INTERFACE SPPARK FEATURE_KOALA_BEAR)

    # Add cbindgen include directory if provided
    if(DEFINED CBINDGEN_INCLUDE_DIR)
        target_include_directories(sp1_gpu_common INTERFACE ${CBINDGEN_INCLUDE_DIR})
    endif()

    # Output directories
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CSL_SOURCE_DIR}/target/hip-build/lib)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CSL_SOURCE_DIR}/target/hip-build/lib)

    # Add subdirectories for each module
    # The per-module CMakeLists.txt files list .cu sources which CMake will
    # compile with hipcc because the HIP language is enabled and .cu is
    # associated with the HIP language when USE_HIP is ON.
    add_subdirectory(lib/algebra)
    add_subdirectory(lib/basefold)
    add_subdirectory(lib/challenger)
    ## add_subdirectory(lib/experimental)  # Dead code
    add_subdirectory(lib/jagged_assist)
    add_subdirectory(lib/jagged_sumcheck)
    add_subdirectory(lib/logup_gkr)
    add_subdirectory(lib/merkle_tree)
    add_subdirectory(lib/mle)
    add_subdirectory(lib/ntt)
    add_subdirectory(lib/runtime)
    add_subdirectory(lib/scan)
    add_subdirectory(lib/sum_and_reduce)
    add_subdirectory(lib/sumcheck)
    add_subdirectory(lib/tracegen)
    add_subdirectory(lib/transpose)
    add_subdirectory(lib/zerocheck)

    # Sppark sources -- compile as HIP (they include cuda2hip.hpp via __HIPCC__ guard)
    add_library(sppark_objs OBJECT
        ${CSL_SOURCE_DIR}/sppark/lib.cpp
        ${CSL_SOURCE_DIR}/sppark/util/all_gpus.cpp
    )
    # Tell CMake to compile .cpp sppark files with hipcc so they see HIP runtime headers
    set_source_files_properties(
        ${CSL_SOURCE_DIR}/sppark/lib.cpp
        ${CSL_SOURCE_DIR}/sppark/util/all_gpus.cpp
        PROPERTIES LANGUAGE HIP
    )
    target_link_libraries(sppark_objs PRIVATE sp1_gpu_common)

    # Force .cu files in all module targets to be compiled as HIP language.
    # CMake 4.x doesn't honor CMAKE_HIP_SOURCE_FILE_EXTENSIONS,
    # so we set the language property on each target's .cu sources.
    set(_hip_targets
        algebra_objs basefold_objs challenger_objs
        jagged_assist_objs jagged_sumcheck_objs
        logup_gkr_objs merkle_tree_objs mle_objs ntt_objs
        runtime_objs scan_objs sum_and_reduce_objs sumcheck_objs
        tracegen_objs transpose_objs zerocheck_objs
    )
    foreach(tgt ${_hip_targets})
        if(TARGET ${tgt})
            get_target_property(_srcs ${tgt} SOURCES)
            foreach(src ${_srcs})
                get_filename_component(ext "${src}" EXT)
                if("${ext}" STREQUAL ".cu")
                    set_source_files_properties(${src}
                        TARGET_DIRECTORY ${tgt}
                        PROPERTIES LANGUAGE HIP
                    )
                endif()
            endforeach()
        endif()
    endforeach()

    # Collect all object libraries
    set(ALL_GPU_OBJECTS
        $<TARGET_OBJECTS:algebra_objs>
        $<TARGET_OBJECTS:basefold_objs>
        $<TARGET_OBJECTS:challenger_objs>
        $<TARGET_OBJECTS:jagged_assist_objs>
        $<TARGET_OBJECTS:jagged_sumcheck_objs>
        $<TARGET_OBJECTS:logup_gkr_objs>
        $<TARGET_OBJECTS:merkle_tree_objs>
        $<TARGET_OBJECTS:mle_objs>
        $<TARGET_OBJECTS:ntt_objs>
        $<TARGET_OBJECTS:runtime_objs>
        $<TARGET_OBJECTS:scan_objs>
        $<TARGET_OBJECTS:sum_and_reduce_objs>
        $<TARGET_OBJECTS:sumcheck_objs>
        $<TARGET_OBJECTS:tracegen_objs>
        $<TARGET_OBJECTS:transpose_objs>
        $<TARGET_OBJECTS:zerocheck_objs>
        $<TARGET_OBJECTS:sppark_objs>
    )

    # Create static library.
    # Device linking is handled by the final executable linker (hipcc/clang++).
    # We don't use HIP_SEPARABLE_COMPILATION here because static libraries
    # can't do device linking — that happens at link time.
    add_library(sys-cuda STATIC ${ALL_GPU_OBJECTS})

    # ROCm runtime libraries
    find_package(hip REQUIRED CONFIG)
    target_link_libraries(sys-cuda PRIVATE hip::device)

    # Install rule
    install(TARGETS sys-cuda
        ARCHIVE DESTINATION lib
    )

else()
    # -----------------------------------------------------------------------
    # NVIDIA CUDA path (original, unchanged)
    # -----------------------------------------------------------------------
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
    ## add_subdirectory(lib/experimental)  # Dead code: look_ahead.cu ~3.7MB GPU memory
    add_subdirectory(lib/jagged_assist)
    add_subdirectory(lib/jagged_sumcheck)
    add_subdirectory(lib/logup_gkr)
    add_subdirectory(lib/merkle_tree)
    add_subdirectory(lib/mle)
    add_subdirectory(lib/ntt)
    add_subdirectory(lib/runtime)
    add_subdirectory(lib/scan)
    add_subdirectory(lib/sum_and_reduce)
    add_subdirectory(lib/sumcheck)
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
        ## $<TARGET_OBJECTS:experimental_objs>  # Dead code removed
        $<TARGET_OBJECTS:jagged_assist_objs>
        $<TARGET_OBJECTS:jagged_sumcheck_objs>
        $<TARGET_OBJECTS:logup_gkr_objs>
        $<TARGET_OBJECTS:merkle_tree_objs>
        $<TARGET_OBJECTS:mle_objs>
        $<TARGET_OBJECTS:ntt_objs>
        $<TARGET_OBJECTS:runtime_objs>
        $<TARGET_OBJECTS:scan_objs>
        $<TARGET_OBJECTS:sum_and_reduce_objs>
        $<TARGET_OBJECTS:sumcheck_objs>
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

    if(CMAKE_CUDA_COMPILER_VERSION VERSION_LESS 12.9)
        target_link_libraries(sys-cuda PRIVATE
            CUDA::cudart
            CUDA::nvToolsExt
        )
    else()
        target_link_libraries(sys-cuda PRIVATE
            CUDA::cudart
        )
    endif()

    # Install rule
    install(TARGETS sys-cuda
        ARCHIVE DESTINATION lib
    )

endif() # USE_HIP
