cmake_minimum_required(VERSION 3.7)
project(Sniffer)


set(SOURCES main.cpp callback.cpp Output.cpp Timer.cpp)

include(FindPCAP.cmake)
add_executable(Sniffer ${SOURCES})

target_link_libraries(Sniffer ${PCAP_LIBRARY})

