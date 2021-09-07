/*
 * AWS IoT Device SDK for Embedded C 202012.01
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

/* Mbed includes */
#include "mbed.h"
#include "unity/unity.h"
/* To include psa/crypto.h > psa/crypto_extra.h > psa/mbedtls_ecc_group_to_psa.h,
 * Mbed TLS configuration must place in front. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "psa/crypto.h"
#include "psa/protected_storage.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"

/* PKCS#11 includes. */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "iot_pkcs11_psa_object_management.h"
#include "iot_pkcs11_psa_input_format.h"

#include "iot_crypto.h"

/* AWS credentials includes. */
#include "aws_credentials.h"

/* FIXME: Check iot_pkcs11_psa_object_management.h to avoid collision */
#define PSA_CODE_VERIFICATION_PRIVATE_KEY_ID    (PSA_CODE_VERIFICATION_KEY_ID + 1)

#ifdef __cplusplus
extern "C" {
#endif

extern CK_FUNCTION_LIST_PTR function_list;
extern CK_SLOT_ID active_slot_id;
extern CK_SESSION_HANDLE active_session;
/* Per test with armclang, this declaration must place in front of its definition.
 * Otherwise, it cannot share across files (undefined symbol). */
extern const char aws_devicePvtKey[];
extern const char aws_codeVerPvtKey[];

/* Provision */
void test_provision_install_rootca_crt(void);
void test_provision_install_device_crt(void);
void test_provision_install_device_pubkey(void);
void test_provision_install_device_pvtkey(void);
void test_provision_check_device_keypair(void);
void test_provision_check_device_crt(void);
void test_provision_install_codever_crt(void);
void test_provision_install_codever_pubkey(void);
void test_provision_install_codever_pvtkey(void);
void test_provision_check_codever_keypair(void);
void test_provision_check_codever_crt(void);

/* PKCS11 basic */
void test_pkcs11_ut_version(void);
void test_pkcs11_ut_init(void);
void test_pkcs11_ut_query(void);
void test_pkcs11_ut_openSession(bool write);
void test_pkcs11_ut_closeSession(void);
void test_pkcs11_ut_fini(void);

/* PKCS11 advanced */
void test_pkcs11_init(void);
void test_pkcs11_findObjects(void);
void test_pkcs11_fini(void);
void test_pkcs11_deviceSignVerify(uint8_t xHashAlgorithm, bool psa_straight);
void test_pkcs11_codeSignVerify(uint8_t xHashAlgorithm, bool psa_straight);

#ifdef __cplusplus
}
#endif

#endif /* _TEST_COMMON_H_ */
