cmake_minimum_required(VERSION 3.8)
project(send_arp)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp sendarp.cpp sendarp.h)
add_executable(send_arp ${SOURCE_FILES})


target_link_libraries(send_arp -lpcap)
