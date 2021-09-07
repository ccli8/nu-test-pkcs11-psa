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

static CK_CHAR pin[] = { "MyPIN" };
static CK_CHAR label[32];

void test_pkcs11_ut_version(void)
{
    TEST_ASSERT_EQUAL(CKR_OK, C_GetFunctionList(&function_list));
    printf("Version: %d.%d\r\n", function_list->version.major, function_list->version.minor);
}

/* TEST: Initialize PKCS11 */
void test_pkcs11_ut_init(void)
{
    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_Initialize(NULL_PTR));
}

/* TEST: Query PKCS11 */
void test_pkcs11_ut_query(void)
{
    CK_SLOT_ID slot_list[2];
    CK_ULONG slot_list_size = sizeof(slot_list) / sizeof(slot_list[0]);
    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_GetSlotList(CK_TRUE,
                                                           slot_list,
                                                           &slot_list_size));
    active_slot_id = slot_list[0];
    printf("C_GetSlotList(): slot_list_size: %lu\r\n", slot_list_size);
    printf("active_slot_id: %lu\r\n", active_slot_id);

    memset(label, ' ', sizeof(label));
    memcpy(label, "My first token", sizeof("My first token"));
    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_InitToken(active_slot_id,
                                                         pin,
                                                         sizeof(pin),
                                                         label));
                      
    CK_TOKEN_INFO tokenInfo;
    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_GetTokenInfo(active_slot_id,
                                                            &tokenInfo));
}

/* TEST: Open PKCS11 session */
void test_pkcs11_ut_openSession(bool write)
{
    CK_FLAGS flags = CKF_SERIAL_SESSION | (write ? CKF_RW_SESSION : 0);
    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_OpenSession(active_slot_id,
                                                           flags,
                                                           NULL,
                                                           NULL,
                                                           &active_session));

    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_Login(active_session,
                                                     CKU_SO,
                                                     pin,
                                                     sizeof(pin)));
}

/* TEST: Close PKCS11 session */
void test_pkcs11_ut_closeSession(void)
{
    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_CloseSession(active_session));
}

/* TEST: Finalize PKCS11 */
void test_pkcs11_ut_fini(void)
{
    TEST_ASSERT_EQUAL(CKR_OK, function_list->C_Finalize(NULL_PTR));
}
