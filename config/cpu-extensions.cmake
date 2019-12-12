if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR
   CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")
    set(ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    # cmake reports AMD64 on Windows, but we might be building for 32-bit.
    if(CMAKE_CL_64)
        set(ARCH "x86_64")
    else()
        set(ARCH "x86")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL "i386" OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
    set(ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    set(ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(ARCH "arm")
else()
    message(FATAL_ERROR "Unknown or unsupported processor: " ${CMAKE_SYSTEM_PROCESSOR})
endif()

if(ARCH STREQUAL "x86" OR
   ARCH STREQUAL "x86_64")
    try_run(RUN_RESULT COMPILE_RESULT
            "${CMAKE_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/config/detect-cpu-extensions.c"
            RUN_OUTPUT_VARIABLE RUN_OUTPUT)
    foreach(CPU_EXTENSION ${RUN_OUTPUT})
        set(USE_${CPU_EXTENSION}_INSTRUCTIONS TRUE)
    endforeach()
    if(USE_AES_INSTRUCTIONS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
    endif()
    if(USE_AVX_INSTRUCTIONS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx")
    endif()
    if(USE_AVX2_INSTRUCTIONS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
    endif()
    if(USE_AVX512BW_INSTRUCTIONS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512bw")
    endif()
    if(USE_AVX512DQ_INSTRUCTIONS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512dq")
    endif()
    if(USE_AVX512F_INSTRUCTIONS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512f")
    endif()
endif()
