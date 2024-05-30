# Author: David Sidler (david.sidler@inf.ethz.ch)

cmake_minimum_required(VERSION 3.0)

project(fpga-network-stack)

# Include custom Find<Module>.cmake scripts to enable searching for Vitis HLS
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/xilinx-cmake)

#
#set(FNS_CLOCK_PERIOD "3.2" CACHE STRING "Target clock period in nanoseconds")

# Domain options
set(DATA_WIDTH 64 CACHE STRING "Width of data path in bytes")
set(CLOCK_PERIOD 3.2 CACHE STRING "Clock period.")


# HLS IPs
#add_subdirectory(hls/arp_server_subnet)
#add_subdirectory(hls/dhcp_client)
#add_subdirectory(hls/icmp_server)
#add_subdirectory(hls/ip_handler)
#add_subdirectory(hls/ipv4)
#add_subdirectory(hls/mac_ip_encode)
#add_subdirectory(hls/toe)
#add_subdirectory(hls/hash_table)
#add_subdirectory(hls/ethernet_frame_padding)
#add_subdirectory(hls/udp)

# add_subdirectory(hls/echo_server_application)
# add_subdirectory(hls/iperf_client)
# add_subdirectory(hls/iperf_udp)
add_subdirectory(hls/rocev2)
