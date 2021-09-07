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
#include "pkcs11-psa-tests/common.h"

#if (MBED_HEAP_STATS_ENABLED) || (MBED_STACK_STATS_ENABLED)
/* Measure memory footprint */
#include "mbed_stats.h"
/* Fix up the compilation on AMRCC for PRIu32 */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif

#if (MBED_HEAP_STATS_ENABLED)
MBED_USED void print_heap_stats(void);
#endif
#if (MBED_STACK_STATS_ENABLED)
MBED_USED void print_stack_statistics(void);
#endif

int main()
{
    //UnityBegin(__FILE__);
    UNITY_BEGIN();

    /* Initialize PSA Crypto */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_INITIALIZATION_FAILED),
                    "psa_crypto_init() failed: ",
                    status);
    }

    /* Provision */
    test_provision_install_rootca_crt();
    test_provision_install_device_crt();
    test_provision_install_device_pubkey();
    test_provision_install_device_pvtkey();
    test_provision_check_device_keypair();
    test_provision_check_device_crt();
    test_provision_install_codever_crt();
    test_provision_install_codever_pubkey();
    test_provision_install_codever_pvtkey();
    test_provision_check_codever_keypair();
    test_provision_check_codever_crt();

    /* PKCS11 basic */
    test_pkcs11_ut_version();
    test_pkcs11_ut_init();
    test_pkcs11_ut_query();
    test_pkcs11_ut_openSession(true);
    test_pkcs11_ut_closeSession();
    test_pkcs11_ut_fini();

    /* PKCS11 advanced */
    test_pkcs11_init();
    test_pkcs11_findObjects();
    test_pkcs11_fini();
    test_pkcs11_deviceSignVerify(cryptoHASH_ALGORITHM_SHA1, false);
    test_pkcs11_deviceSignVerify(cryptoHASH_ALGORITHM_SHA256, false);
    test_pkcs11_codeSignVerify(cryptoHASH_ALGORITHM_SHA1, false);
    test_pkcs11_codeSignVerify(cryptoHASH_ALGORITHM_SHA256, false);
    test_pkcs11_deviceSignVerify(cryptoHASH_ALGORITHM_SHA1, true);
    test_pkcs11_deviceSignVerify(cryptoHASH_ALGORITHM_SHA256, true);
    test_pkcs11_codeSignVerify(cryptoHASH_ALGORITHM_SHA1, true);
    test_pkcs11_codeSignVerify(cryptoHASH_ALGORITHM_SHA256, true);

    printf("\r\nAll tests PASS\r\n\r\n");

#if (MBED_HEAP_STATS_ENABLED)
    print_heap_stats();
#endif

#if (MBED_STACK_STATS_ENABLED)
    print_stack_statistics();
#endif
}

#if (MBED_HEAP_STATS_ENABLED)
void print_heap_stats(void)
{
    mbed_stats_heap_t stats;
    mbed_stats_heap_get(&stats);
    printf("** MBED HEAP STATS **\n");
    printf("**** current_size: %" PRIu32 "\n", stats.current_size);
    printf("**** max_size    : %" PRIu32 "\n", stats.max_size);
    printf("*****************************\n\n");
}
#endif  // MBED_HEAP_STATS_ENABLED

#if (MBED_STACK_STATS_ENABLED)
void print_stack_statistics()
{
    printf("** MBED THREAD STACK STATS **\n");
    int cnt = osThreadGetCount();
    mbed_stats_stack_t *stats = (mbed_stats_stack_t*) malloc(cnt * sizeof(mbed_stats_stack_t));

    if (stats) {
        cnt = mbed_stats_stack_get_each(stats, cnt);
        for (int i = 0; i < cnt; i++) {
            printf("Thread: 0x%" PRIx32 ", Stack size: %" PRIu32 ", Max stack: %" PRIu32 "\r\n", stats[i].thread_id, stats[i].reserved_size, stats[i].max_size);
        }

        free(stats);
    }
    printf("*****************************\n\n");
}
#endif  // MBED_STACK_STATS_ENABLED
