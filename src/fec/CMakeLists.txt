# src/fec/CMakeLists.txt
set(FEC_SOURCES 
    cm256.cpp 
    cm256.h
    gf256.cpp
    gf256.h
    wirehair.cpp
    wirehair.h
    WirehairCodec.cpp
    WirehairCodec.h
    WirehairTools.cpp
    WirehairTools.h)  

# SIMD-specific sources
set(FEC_SSSE3_SOURCES gf256_ssse3.cpp gf256_ssse3.h)
set(FEC_AVX2_SOURCES gf256_avx2.cpp gf256_avx2.h)
set(FEC_NEON_SOURCES gf256_neon.cpp gf256_neon.h)

add_library(bitcoin_fec STATIC ${FEC_SOURCES})

# Enable SIMD optimizations based on the architecture
include(CheckCXXCompilerFlag)

# Check and enable SSSE3
check_cxx_compiler_flag("-mssse3" COMPILER_SUPPORTS_SSSE3)
if(COMPILER_SUPPORTS_SSSE3)
    target_sources(bitcoin_fec PRIVATE ${FEC_SSSE3_SOURCES})
    set_source_files_properties(${FEC_SSSE3_SOURCES} PROPERTIES 
        COMPILE_FLAGS "-mssse3")
    target_compile_definitions(bitcoin_fec PUBLIC ENABLE_SSSE3=1)
endif()

# Check and enable AVX2
check_cxx_compiler_flag("-mavx2" COMPILER_SUPPORTS_AVX2)
if(COMPILER_SUPPORTS_AVX2)
    target_sources(bitcoin_fec PRIVATE ${FEC_AVX2_SOURCES})
    set_source_files_properties(${FEC_AVX2_SOURCES} PROPERTIES 
        COMPILE_FLAGS "-mavx2")
    target_compile_definitions(bitcoin_fec PUBLIC ENABLE_AVX2=1)
endif()

# For ARM NEON (if applicable)
check_cxx_compiler_flag("-mfpu=neon" COMPILER_SUPPORTS_NEON)
if(COMPILER_SUPPORTS_NEON)
    target_sources(bitcoin_fec PRIVATE ${FEC_NEON_SOURCES})
    set_source_files_properties(${FEC_NEON_SOURCES} PROPERTIES 
        COMPILE_FLAGS "-mfpu=neon")
    # Define both HAVE_NEON and ENABLE_NEON for compatibility
    target_compile_definitions(bitcoin_fec PUBLIC 
        HAVE_NEON=1
        ENABLE_NEON=1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    # For 64-bit ARM, NEON is always available
    target_sources(bitcoin_fec PRIVATE ${FEC_NEON_SOURCES})
    target_compile_definitions(bitcoin_fec PUBLIC 
        HAVE_NEON=1
        ENABLE_NEON=1
        ENABLE_NEON64=1)
endif()

# Ensure position independent code for static library
set_target_properties(bitcoin_fec PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Make sure we're using C++17 or later (adjust as needed)
target_compile_features(bitcoin_fec PUBLIC cxx_std_17)