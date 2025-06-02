# src/fec/CMakeLists.txt
set(FEC_SOURCES 
    cm256.cpp 
    cm256.h
    gf256_avx2.cpp
    gf256_avx2.h
    gf256_neon.cpp
    gf256_neon.h
    gf256_ssse3.cpp
    gf256_ssse3.h
    gf256.cpp
    gf256.h
    wirehair.cpp
    wirehair.h
    WirehairCodec.cpp
    WirehairCodec.h
    WirehairTools.cpp
    WirehairTools.h)  
add_library(bitcoin_fec STATIC ${FEC_SOURCES})
