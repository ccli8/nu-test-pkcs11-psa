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

/* Standard includes */
#include <string.h>

/* Test includes */
#include "common.h"
#include "provision_psa_utils.h"

/* TEST: Install root CA certificate */
void test_provision_install_rootca_crt(void)
{
    printf("TEST: PROV: Install root CA certificate...\r\n");
    provpsa_install_nonconf((const unsigned char *) aws_rootCACrt,
                            strlen(aws_rootCACrt) + 1,
                            PSA_ROOT_CERTIFICATE_UID);
    printf("TEST: PROV: Install root CA certificate...OK\r\n");
}

/* TEST: Install device certificate */
void test_provision_install_device_crt(void)
{
    printf("TEST: PROV: Install device certificate...\r\n");
    provpsa_install_nonconf((const unsigned char *) aws_deviceCrt,
                            strlen(aws_deviceCrt) + 1,
                            PSA_DEVICE_CERTIFICATE_UID);
    printf("TEST: PROV: Install device certificate...OK\r\n");
}

/* TEST: Install device public key */
void test_provision_install_device_pubkey(void)
{
    printf("TEST: PROV: Install device public key...\r\n");
    provpsa_install_pvtpub((const unsigned char *) aws_devicePubKey,
                           strlen(aws_devicePubKey) + 1,
                           PSA_DEVICE_PUBLIC_KEY_ID,
                           false);
    printf("TEST: PROV: Install device public key...OK\r\n");
}

/* TEST: Install device private key */
void test_provision_install_device_pvtkey(void)
{
    printf("TEST: PROV: Install device private key...\r\n");
    provpsa_install_pvtpub((const unsigned char *) aws_devicePvtKey,
                           strlen(aws_devicePvtKey) + 1,
                           PSA_DEVICE_PRIVATE_KEY_ID,
                           true);
    provpsa_install_pvtpub_extra_nonconf((const unsigned char *) aws_devicePvtKey,
                                         strlen(aws_devicePvtKey) + 1,
                                         PSA_DEVICE_PRIVATE_KEY_ID,
                                         PSA_DEVICE_PRIVATE_KEY_UID);
    printf("TEST: PROV: Install device private key...OK\r\n");
}

void test_provision_check_device_keypair(void)
{
    printf("TEST: PROV: Check device key pair...\r\n");
    provpsa_check_pair_pvtpub(PSA_DEVICE_PRIVATE_KEY_ID,
                              PSA_DEVICE_PUBLIC_KEY_ID);
    printf("TEST: PROV: Check device key pair...OK\r\n");
}

void test_provision_check_device_crt(void)
{
    printf("TEST: PROV: Check device certificate...\r\n");
    provpsa_check_pair_pvtcrt(PSA_DEVICE_PRIVATE_KEY_ID,
                              PSA_DEVICE_CERTIFICATE_UID,
                              PSA_DEVICE_PRIVATE_KEY_UID);
    printf("TEST: PROV: Check device certificate...OK\r\n");
}

void test_provision_install_codever_crt(void)
{
    printf("TEST: PROV: Install code verification certificate...\r\n");
    provpsa_install_nonconf((const unsigned char *) aws_codeVerCrt,
                            strlen(aws_codeVerCrt) + 1,
                            PSA_CODE_VERIFICATION_CERTIFICATE_UID);
    printf("TEST: PROV: Install code verification certificate...OK\r\n");
}

/* TEST: Install code verification public key */
void test_provision_install_codever_pubkey(void)
{
    printf("TEST: PROV: Install code verification public key...\r\n");
#if 0
    provpsa_install_pvtpub((const unsigned char *) aws_codeVerPubKey,
                           strlen(aws_codeVerPubKey) + 1,
                           PSA_CODE_VERIFICATION_KEY_ID,
                           false);
#else
    provpsa_install_pubkey_by_crt((const unsigned char *) aws_codeVerCrt,
                                  strlen(aws_codeVerCrt) + 1,
                                  PSA_CODE_VERIFICATION_KEY_ID);
#endif
    printf("TEST: PROV: Install code verification public key...OK\r\n");
}

/* TEST: Install code verification private key */
void test_provision_install_codever_pvtkey(void)
{
    printf("TEST: PROV: Install code verification private key...\r\n");
    provpsa_install_pvtpub((const unsigned char *) aws_codeVerPvtKey,
                           strlen(aws_codeVerPvtKey) + 1,
                           PSA_CODE_VERIFICATION_PRIVATE_KEY_ID,
                           true);
    printf("TEST: PROV: Install code verification private key...OK\r\n");
}

void test_provision_check_codever_keypair(void)
{
    printf("TEST: PROV: Check code verification key pair...\r\n");
    provpsa_check_pair_pvtpub(PSA_CODE_VERIFICATION_PRIVATE_KEY_ID,
                              PSA_CODE_VERIFICATION_KEY_ID);
    printf("TEST: PROV: Check code verification key pair...OK\r\n");
}

void test_provision_check_codever_crt(void)
{
    printf("TEST: PROV: Check code verification certificate...\r\n");
    provpsa_check_pair_pvtcrt(PSA_CODE_VERIFICATION_PRIVATE_KEY_ID,
                              PSA_CODE_VERIFICATION_CERTIFICATE_UID,
                                    0);
    printf("TEST: PROV: Check code verification certificate...OK\r\n");
}
