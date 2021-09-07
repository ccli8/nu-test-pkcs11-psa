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

/* Test includes. */
#include "common.h"
#include "core_pki_utils.h"

static CK_FUNCTION_LIST_PTR pxFunctionList = NULL;

static CK_SESSION_HANDLE xSession           = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE xRootCACrt          = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE xDeviceCrt          = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE xDevicePublicKey    = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE xDevicePrivateKey   = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE xCodeVerifyKey      = CK_INVALID_HANDLE;

static void test_pkcs11_signVerify(const uint8_t *pcPrivateKey,
                                   size_t xPrivateKeyLength,
                                   const uint8_t *pcPKCS11PublicKeyLabel,
                                   size_t xPKCS11PublicKeyLabelLength,
                                   psa_key_id_t xPSAPublicKeyId,
                                   uint8_t xHashAlgorithm,
                                   bool psa_straight);

/* TEST: Initialize PKCS11 */
void test_pkcs11_init(void)
{
    TEST_ASSERT_EQUAL(CKR_OK, C_GetFunctionList(&pxFunctionList));
    TEST_ASSERT_NOT_EQUAL(NULL, pxFunctionList);

    TEST_ASSERT_EQUAL(CKR_OK, xInitializePKCS11());
    TEST_ASSERT_EQUAL(CKR_OK, xInitializePkcs11Token());
    TEST_ASSERT_EQUAL(CKR_OK, xInitializePkcs11Session(&xSession));
}

/* TEST: Search for PKCS11 objects */
void test_pkcs11_findObjects(void)
{
    printf("TEST: PKCS11: Search for PKCS11 objects...\r\n");

    /* Root CA certificate */
    TEST_ASSERT_EQUAL(CKR_OK, xFindObjectWithLabelAndClass(xSession,
                                                           (char *) pkcs11configLABEL_ROOT_CERTIFICATE,
                                                           sizeof(pkcs11configLABEL_ROOT_CERTIFICATE) - 1,
                                                           CKO_CERTIFICATE,
                                                           &xRootCACrt));
    /* Device certificate */
    TEST_ASSERT_EQUAL(CKR_OK, xFindObjectWithLabelAndClass(xSession,
                                                           (char *) pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                                           sizeof(pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS) - 1,
                                                           CKO_CERTIFICATE,
                                                           &xDeviceCrt));
    /* Device public key */
    TEST_ASSERT_EQUAL(CKR_OK, xFindObjectWithLabelAndClass(xSession,
                                                           (char *) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                                           sizeof(pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS) - 1,
                                                           CKO_PUBLIC_KEY,
                                                           &xDevicePublicKey));
    /* Device private key */
    TEST_ASSERT_EQUAL(CKR_OK, xFindObjectWithLabelAndClass(xSession,
                                                           (char *) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                           sizeof(pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS) - 1,
                                                           CKO_PRIVATE_KEY,
                                                           &xDevicePrivateKey));
    /* Code verification key */
    TEST_ASSERT_EQUAL(CKR_OK, xFindObjectWithLabelAndClass(xSession,
                                                           (char *) pkcs11configLABEL_CODE_VERIFICATION_KEY,
                                                           sizeof(pkcs11configLABEL_CODE_VERIFICATION_KEY) - 1,
                                                           CKO_PUBLIC_KEY,
                                                           &xCodeVerifyKey));

    printf("TEST: PKCS11: Search for PKCS11 objects...OK\r\n");
}

/* TEST: Finalize PKCS11 */
void test_pkcs11_fini(void)
{
    TEST_ASSERT_EQUAL(CKR_OK, pxFunctionList->C_CloseSession(xSession));
    xSession = CK_INVALID_HANDLE;

    TEST_ASSERT_EQUAL(CKR_OK, C_Finalize(NULL));
    xRootCACrt          = CK_INVALID_HANDLE;
    xDeviceCrt          = CK_INVALID_HANDLE;
    xDevicePublicKey    = CK_INVALID_HANDLE;
    xDevicePrivateKey   = CK_INVALID_HANDLE;
    xCodeVerifyKey      = CK_INVALID_HANDLE;
}

/* TEST: Device sign/verify with PKCS11/PSA or PSA straight */
void test_pkcs11_deviceSignVerify(uint8_t xHashAlgorithm, bool psa_straight)
{
    printf("TEST: PKCS11: Device sign/verify (SHA alg: %s) with PKCS11/PSA or PSA straight...\r\n",
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1 ? "SHA1" :
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256 ? "SHA256" : "Neither SHA1 Nor SHA256");

    if (xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1) {
        printf("Neither PKCS11/PSA nor PSA straight supports SHA1\r\n");
        printf("TEST: PKCS11: Device sign/verify (SHA alg: %s) with PKCS11/PSA or PSA straight...SKIP\r\n",
               xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1 ? "SHA1" :
               xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256 ? "SHA256" : "Neither SHA1 Nor SHA256");
        printf("\r\n");
        return;
    }

    test_pkcs11_signVerify((const uint8_t *) aws_devicePvtKey,  // For PEM, the buffer must contain a null-terminated string.
                           strlen(aws_devicePvtKey) + 1,        // For PEM data, this includes the terminating null byte.
                           (const uint8_t *) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                           sizeof(pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS) - 1,
                           PSA_DEVICE_PUBLIC_KEY_ID,
                           xHashAlgorithm,
                           psa_straight);

    printf("TEST: PKCS11: Device sign/verify (SHA alg: %s) with PKCS11/PSA or PSA straight...OK\r\n",
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1 ? "SHA1" :
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256 ? "SHA256" : "Neither SHA1 Nor SHA256");
    printf("\r\n");
}

/* TEST: Code sign/verify with PKCS11/PSA or PSA straight */
void test_pkcs11_codeSignVerify(uint8_t xHashAlgorithm, bool psa_straight)
{
    printf("TEST: PKCS11: Code sign/verify (SHA alg: %s) with PKCS11/PSA or PSA straight...\r\n",
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1 ? "SHA1" :
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256 ? "SHA256" : "Neither SHA1 Nor SHA256");

    if (xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1) {
        printf("Neither PKCS11/PSA nor PSA straight supports SHA1\r\n");
        printf("TEST: PKCS11: Code sign/verify (SHA alg: %s) with PKCS11/PSA or PSA straight...SKIP\r\n",
               xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1 ? "SHA1" :
               xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256 ? "SHA256" : "Neither SHA1 Nor SHA256");
        printf("\r\n");
        return;
    }

    test_pkcs11_signVerify((const uint8_t *) aws_codeVerPvtKey, // For PEM, the buffer must contain a null-terminated string.
                           strlen(aws_codeVerPvtKey) + 1,       // For PEM data, this includes the terminating null byte.
                           (const uint8_t *) pkcs11configLABEL_CODE_VERIFICATION_KEY,
                           sizeof(pkcs11configLABEL_CODE_VERIFICATION_KEY) - 1,
                           PSA_CODE_VERIFICATION_KEY_ID,
                           xHashAlgorithm,
                           psa_straight);

    printf("TEST: PKCS11: Code sign/verify (SHA alg: %s) with PKCS11/PSA or PSA straight...OK\r\n",
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1 ? "SHA1" :
           xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256 ? "SHA256" : "Neither SHA1 Nor SHA256");
    printf("\r\n");
}

static void test_pkcs11_signVerify(const uint8_t *pcPrivateKey,
                                   size_t xPrivateKeyLength,
                                   const uint8_t *pcPKCS11PublicKeyLabel,
                                   size_t xPKCS11PublicKeyLabelLength,
                                   psa_key_id_t xPSAPublicKeyId,
                                   uint8_t xHashAlgorithm,
                                   bool psa_straight)
{
    TEST_ASSERT_TRUE(xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1 ||
                     xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256);

    /* Digest */
    CK_BYTE knownMessage[] = { "Hello world" };
    /* Allocate buffer with size max(SHA1, SHA256) */
    CK_BYTE digestResult[cryptoSHA256_DIGEST_BYTES] = { 0 };
    CK_ULONG digestLength = 0;

    if (xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1) {
        mbedtls_sha1_context xSHA1Context;

        mbedtls_sha1_init(&xSHA1Context);
        TEST_ASSERT_EQUAL(0, mbedtls_sha1_starts_ret(&xSHA1Context));
        TEST_ASSERT_EQUAL(0, mbedtls_sha1_update_ret(&xSHA1Context, knownMessage, sizeof(knownMessage) - 1));
        TEST_ASSERT_EQUAL(0, mbedtls_sha1_finish_ret(&xSHA1Context, digestResult));
        mbedtls_sha1_free(&xSHA1Context);

        digestLength = cryptoSHA1_DIGEST_BYTES;
    } else {
        mbedtls_sha256_context xSHA256Context;

        mbedtls_sha256_init(&xSHA256Context);
        TEST_ASSERT_EQUAL(0, mbedtls_sha256_starts_ret(&xSHA256Context, 0));
        TEST_ASSERT_EQUAL(0, mbedtls_sha256_update_ret(&xSHA256Context, knownMessage, sizeof(knownMessage) - 1));
        TEST_ASSERT_EQUAL(0, mbedtls_sha256_finish_ret(&xSHA256Context, digestResult));
        mbedtls_sha256_free(&xSHA256Context);

        digestLength = cryptoSHA256_DIGEST_BYTES;
    }

    /* Sign through mbedtls */
    mbedtls_pk_context pvtkey_ctx;
    mbedtls_pk_init(&pvtkey_ctx);
    TEST_ASSERT_EQUAL(0, mbedtls_pk_parse_key(&pvtkey_ctx,
                                              (const unsigned char *) pcPrivateKey,
                                              xPrivateKeyLength,
                                              NULL,
                                              0));

    uint8_t *sig_mbedtls = (uint8_t *) malloc(MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    size_t sig_size_mbedtls = 0;

    TEST_ASSERT_EQUAL(0, mbedtls_pk_sign(&pvtkey_ctx,
                                         (xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1) ? MBEDTLS_MD_SHA1 : MBEDTLS_MD_SHA256,
                                         digestResult,
                                         digestLength,
                                         sig_mbedtls,
                                         &sig_size_mbedtls,
                                         NULL,
                                         NULL));
    TEST_ASSERT_TRUE(sig_size_mbedtls <= MBEDTLS_PK_SIGNATURE_MAX_SIZE);

    /* Clean up */
    mbedtls_pk_free(&pvtkey_ctx);

    /* Determine go PKCS11/PSA or PSA straight */
    bool go_pkcs11_psa = !psa_straight;

    psa_key_id_t code_pubkey_handle = 0;

    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_open_key(xPSAPublicKeyId, &code_pubkey_handle));
    TEST_ASSERT_EQUAL(xPSAPublicKeyId, code_pubkey_handle);

    psa_key_attributes_t code_pubkey_attributes = PSA_KEY_ATTRIBUTES_INIT;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_get_key_attributes(xPSAPublicKeyId,
                                                          &code_pubkey_attributes));

    psa_key_type_t code_pubkey_type = psa_get_key_type(&code_pubkey_attributes);
    size_t code_pubkey_bits = psa_get_key_bits(&code_pubkey_attributes);
    printf("Code verification key: %s, bits=%d\r\n",
           PSA_KEY_TYPE_IS_RSA(code_pubkey_type) ? "RSA" : PSA_KEY_TYPE_IS_ECC(code_pubkey_type) ? "ECC" : "Neither RSA Nor ECC",
           code_pubkey_bits);

    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_close_key(code_pubkey_handle));

    /* For digest, neither PKCS11/PSA nor PSA straight supports SHA1 */
    TEST_ASSERT_TRUE(xHashAlgorithm == cryptoHASH_ALGORITHM_SHA256);

    /* For asymmetric, PKCS11/PSA supports only RSA and ECC */
    if (go_pkcs11_psa &&
        (!PSA_KEY_TYPE_IS_RSA(code_pubkey_type) && !PSA_KEY_TYPE_IS_ECC(code_pubkey_type))) {
        go_pkcs11_psa = false;
    }
    /* For ECC, PKCS11/PSA supports only P-256. */
    if (go_pkcs11_psa &&
        PSA_KEY_TYPE_IS_ECC(code_pubkey_type) &&
        code_pubkey_bits != 256) {
        go_pkcs11_psa = false;
    }

    printf("Code verification with %s\r\n", go_pkcs11_psa ? "PKCS11/PSA" : "PSA straight");

    void *pvContext = NULL;

    TEST_ASSERT_EQUAL(true, CRYPTO_SignatureVerificationStart(&pvContext,
                                                              PSA_KEY_TYPE_IS_RSA(code_pubkey_type) ? cryptoASYMMETRIC_ALGORITHM_RSA : cryptoASYMMETRIC_ALGORITHM_ECDSA,
                                                              xHashAlgorithm));

    CRYPTO_SignatureVerificationUpdate(pvContext,
                                       knownMessage,
                                       sizeof(knownMessage) - 1);

    /* Verify the signature */                                                     
    if (go_pkcs11_psa) {
        TEST_ASSERT_EQUAL(true, CRYPTO_SignatureVerificationFinalByPKCS11Label(pvContext,
                                                                               (uint8_t *) pcPKCS11PublicKeyLabel,
                                                                               xPKCS11PublicKeyLabelLength,
                                                                               sig_mbedtls,
                                                                               sig_size_mbedtls));
    } else {
        TEST_ASSERT_EQUAL(true, CRYPTO_SignatureVerificationFinalByPSAKeyId(pvContext,
                                                                            xPSAPublicKeyId,
                                                                            sig_mbedtls,
                                                                            sig_size_mbedtls));
    }

    /* Clean up */
    if (sig_mbedtls) {
        free(sig_mbedtls);
        sig_mbedtls = NULL;
    }
}
