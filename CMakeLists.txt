cmake_minimum_required(VERSION 3.12)

project(cap2csv
        VERSION 0.1.0
        LANGUAGES C)

message(STATUS ${PROJECT_NAME})

set(PCAP_DIR D:/Download/npcap-sdk)
set(TCPDUMP_INCLUDE_DIR D:/Download/tcpdump-master)

set(CMAKE_C_FLAGS "-s -static -Os -Wall")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(PCAP_LIB_DIR ${PCAP_DIR}/Lib/x64)
set(PCAP_INCLUDE_DIR ${PCAP_DIR}/Include)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_PREFIX_PATH ${PCAP_LIB_DIR})
set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR} CACHE PATH "" FORCE)

find_library(LIBRARY_VAR1 wpcap)

add_subdirectory(src)
