# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.19.0 FATAL_ERROR)

set(MBED_PATH ${CMAKE_CURRENT_SOURCE_DIR}/mbed-os CACHE INTERNAL "")
set(MBED_CONFIG_PATH ${CMAKE_CURRENT_BINARY_DIR} CACHE INTERNAL "")
set(APP_TARGET nu-test-pkcs11-psa)

include(${MBED_PATH}/tools/cmake/app.cmake)

project(${APP_TARGET})

add_subdirectory(${MBED_PATH})

add_executable(${APP_TARGET})

mbed_configure_app_target(${APP_TARGET})

target_include_directories(${APP_TARGET}
    PRIVATE
        .
        aws_credentials
        pkcs11-psa/corePKCS11
        pkcs11-psa/crypto
        pkcs11-psa/FreeRTOS_mbed
        pkcs11-psa/mbedtls
        pkcs11-psa/pkcs11
        pkcs11-psa
        utest
)

target_sources(${APP_TARGET}
    PRIVATE
        aws_credentials/aws_credentials.c
        main.cpp
        pkcs11-psa/corePKCS11/core_pkcs11.c
        pkcs11-psa/corePKCS11/core_pki_utils.c
        pkcs11-psa/crypto/iot_crypto.cpp
        pkcs11-psa/FreeRTOS_mbed/FreeRTOS_mbed.cpp
        pkcs11-psa/iot_pkcs11_psa.c
        pkcs11-psa/iot_pkcs11_psa_input_format.c
        pkcs11-psa/iot_pkcs11_psa_object_management.c
        pkcs11-psa/mbedtls/threading_alt.cpp
        pkcs11-psa/mbedtls_utils/mbedtls_utils.c
        pkcs11-psa-tests/common.cpp
        pkcs11-psa-tests/provision_psa_utils.cpp
        pkcs11-psa-tests/test_advanced.cpp
        pkcs11-psa-tests/test_basic.cpp
        pkcs11-psa-tests/test_provision.cpp
        utest/unity_handler.cpp
)

target_link_libraries(${APP_TARGET}
    PRIVATE
        mbed-os
        mbed-mbedtls
        #mbed-utest
        mbed-unity
)

mbed_set_post_build(${APP_TARGET})

option(VERBOSE_BUILD "Have a verbose build process")
if(VERBOSE_BUILD)
    set(CMAKE_VERBOSE_MAKEFILE ON)
endif()
