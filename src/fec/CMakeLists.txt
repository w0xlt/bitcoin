# src/fec/CMakeLists.txt
set(FEC_SOURCES 
    cm256.cpp 
    cm256.h
    wirehair.cpp
    wirehair/wirehair.h
    gf256.cpp
    gf256.h
    WirehairCodec.cpp
    WirehairCodec.h
    WirehairTools.cpp
    WirehairTools.h)  

add_library(bitcoin_fec STATIC ${FEC_SOURCES})

# Ensure position independent code for static library
set_target_properties(bitcoin_fec PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Make sure we're using C++17 or later (adjust as needed)
target_compile_features(bitcoin_fec PUBLIC cxx_std_17)