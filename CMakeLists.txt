cmake_minimum_required(VERSION 3.16)
project(nVPN VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Platform-specific settings
if(APPLE)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Common library
set(COMMON_SOURCES
    src/common/crypto.cpp
    src/common/network.cpp
    src/common/obfuscation.cpp
    src/common/protocol.cpp
    src/common/tun_device.cpp
    src/common/utils.cpp
)

add_library(nvpn_common STATIC ${COMMON_SOURCES})

target_link_libraries(nvpn_common
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

if(APPLE)
    target_link_libraries(nvpn_common
        ${COREFOUNDATION_LIBRARY}
    )
endif()

# Server executable
add_executable(nvpn_server
    src/server/main.cpp
    src/server/server.cpp
    src/server/session.cpp
)

target_link_libraries(nvpn_server
    nvpn_common
)

# Client executable
add_executable(nvpn_client
    src/client/main.cpp
    src/client/client.cpp
    src/client/tun_handler.cpp
)

target_link_libraries(nvpn_client
    nvpn_common
)

# Install targets
install(TARGETS nvpn_server nvpn_client
    RUNTIME DESTINATION bin
)

install(DIRECTORY config/
    DESTINATION etc/nvpn
)