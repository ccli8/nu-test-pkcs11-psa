/*
 * AWS Certificates
 * Copyright (c) 2020 Arm Limited
 * SPDX-License-Identifier: Apache-2.0
 */


#include "aws_credentials.h"

/*
 * PEM-encoded root CA certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char aws_rootCACrt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n"
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
"b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n"
"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n"
"b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n"
"ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n"
"9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n"
"IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n"
"VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n"
"93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n"
"jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
"AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n"
"A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n"
"U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n"
"N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n"
"o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n"
"5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n"
"rqXRfboQnoZsG4q5WTP468SQvvG5\n"
"-----END CERTIFICATE-----";

/*
 * PEM-encoded device certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char aws_deviceCrt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDWTCCAkGgAwIBAgIUAzDIpEQWV/yKVo8suGhvjmFY0n4wDQYJKoZIhvcNAQEL\n"
"BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\n"
"SW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTE4MDQxNzA5NDMx\n"
"M1oXDTQ5MTIzMTIzNTk1OVowHjEcMBoGA1UEAwwTQVdTIElvVCBDZXJ0aWZpY2F0\n"
"ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKsLlECiw4ud5laejJmL\n"
"bBhafKLdCRx6tkcjBYyEUoAC3Qs2ogqGngQgjU4QJoWpEBO/U1M+e1QtlZ2o/CiL\n"
"MViHA3rYvP86N/TH8pFA3aPKaeEp+WIt5v4OXdfPkVNKTotiRuRCpzRzrY4xKp11\n"
"ouKkVKf3FcNuKIMt/uEhje90KofBbFHQY3HFYe19qIg1m/IBV+npmNlAKElGNSB7\n"
"xHHLzzUuue38s+ceJyzsWuPjFiVYoeyPHF8gDVWf28XJ4KUFs80Deycqe9efroud\n"
"cQY/6aLDWDJXHvhenwoAIbHqUsYRoWoanrg5Cq3id5+pzVkadNV3+x9bGwROhpbQ\n"
"M9ECAwEAAaNgMF4wHwYDVR0jBBgwFoAUVUXg3+Dd1qSnAT9LN413zSdNoE0wHQYD\n"
"VR0OBBYEFIx86SOxw5k/50GtyRjUwlj+9d1gMAwGA1UdEwEB/wQCMAAwDgYDVR0P\n"
"AQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQCI1fqqjvLAFzL2E1nvWMrkaWN2\n"
"EQK44uOcw53ZzgNNH7fJ85BW8T2l1yZx/Blgs10pEp7vmccnRoR7nYbUGO8++9nG\n"
"S7bfZhiaE2syJqqvLwPGdqR6fvDdfEpmhgJ1CqeMCqun9XZvUTsgBn7Sqqz7P99h\n"
"gGmDRKS/CtsPai0Df0ZPNuV/YuUkpHKJSDm+ZTnzevMS3KXkG1cc/sIuc4IwF+aj\n"
"nbyzdC2fN0r+34srQ8/9aXezOTQ0NBWtoJCCkD+LL6PYJJkAgLA2jcbcbuRJUQ7n\n"
"Zsp25kKX40fuyIcgPRsd/7sao3zTVYxwKy8r6/mbgrPiMeHvJZ8y3nwUpsPO\n"
"-----END CERTIFICATE-----";

/*
 * PEM-encoded device public key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN PUBLIC KEY-----\n"
 * "...base64 data...\n"
 * "-----END PUBLIC KEY-----"
 */
const char aws_devicePubKey[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqwuUQKLDi53mVp6MmYts\n"
"GFp8ot0JHHq2RyMFjIRSgALdCzaiCoaeBCCNThAmhakQE79TUz57VC2Vnaj8KIsx\n"
"WIcDeti8/zo39MfykUDdo8pp4Sn5Yi3m/g5d18+RU0pOi2JG5EKnNHOtjjEqnXWi\n"
"4qRUp/cVw24ogy3+4SGN73Qqh8FsUdBjccVh7X2oiDWb8gFX6emY2UAoSUY1IHvE\n"
"ccvPNS657fyz5x4nLOxa4+MWJVih7I8cXyANVZ/bxcngpQWzzQN7Jyp715+ui51x\n"
"Bj/posNYMlce+F6fCgAhsepSxhGhahqeuDkKreJ3n6nNWRp01Xf7H1sbBE6GltAz\n"
"0QIDAQAB\n"
"-----END PUBLIC KEY-----";

/*
 * PEM-encoded device private key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN RSA PRIVATE KEY-----\n"
 * "...base64 data...\n"
 * "-----END RSA PRIVATE KEY-----";
 */
const char aws_devicePvtKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAqwuUQKLDi53mVp6MmYtsGFp8ot0JHHq2RyMFjIRSgALdCzai\n"
"CoaeBCCNThAmhakQE79TUz57VC2Vnaj8KIsxWIcDeti8/zo39MfykUDdo8pp4Sn5\n"
"Yi3m/g5d18+RU0pOi2JG5EKnNHOtjjEqnXWi4qRUp/cVw24ogy3+4SGN73Qqh8Fs\n"
"UdBjccVh7X2oiDWb8gFX6emY2UAoSUY1IHvEccvPNS657fyz5x4nLOxa4+MWJVih\n"
"7I8cXyANVZ/bxcngpQWzzQN7Jyp715+ui51xBj/posNYMlce+F6fCgAhsepSxhGh\n"
"ahqeuDkKreJ3n6nNWRp01Xf7H1sbBE6GltAz0QIDAQABAoIBAAzl7KILJA/NMmdp\n"
"wVR6zQXxHODzJhK9ti0bGPoFqGr6zExiLEn66MOK6NzwHteJbirvDIuEdKxeW5/t\n"
"9EXiaTAxzjNfULE2ZK3Svhnx+ES3qNBP5/xdVcPmtXDmuCC9w7qDCLGBzTYJWxcT\n"
"4hDJpCTPG4sm+L8p+Wga+dNkQl3CFyHHINDZ0pKcP0kDDt6inKfiU7uU4lFYbCZy\n"
"PceUgIOTQiNVoPQYtkHgZAtmD9rcwdq2/0GZEbzTkZuSE9S8+WlGxJP5xMGzeVsv\n"
"zZ/scx0LM7fz5Zq0lsvAwSB1mcs04DaaNpU7Z0tXDIS249RTqdtpPkJzmevpAGhF\n"
"VNe30/kCgYEA4rflfqyw/YHWKRxCGJRO+q0gPvlBIes30noz5Hxl0knb/J5Ng4Nx\n"
"xMaIMZgCbwHbw5i01JOPvVKICROKb8wkli4Y2eVzxMPKk2CSpji16RQZ4eOl3YXL\n"
"1Vnn07Ei+GpsGgDNF0HWf/Ur7es/KdAPCWbKJyoSR90+WN29gP2+Zp8CgYEAwSLv\n"
"Kt/vdd6XKnR9xR3IajsW/X2GR/x/m2JffJPOP6VpDTKAbv86hVHDV0oBEDMDc7qy\n"
"023ognyFCPb9Gzol2lq8egjMsisA2bgoB9HqldrSYlaZ0wPe0QJBf1gZ29jPyVJ0\n"
"ciaBbNbSRhwTrwet7Bae9EbpJsyvBxVh00v0f48CgYEAvKQKviXudmCL01UB4fW0\n"
"6XsXs44tlY1juyuW9exTxG9ULZOCJ4U9Kl+OfsVecQL42ny7KY1GMl7zdanerDsN\n"
"zi+42cTDWNsYORxHqSrSoYbqKjwCjJmBCppt/IQM9umF3PUBsPJFCd7zmFj/C0lk\n"
"2Yu/dGrbHxSFheeqgCOhQz0CgYBfZxdHUYji64o2cYay+QxH1Vp86yWKp6KNKeHL\n"
"EuP9soKa/0hMDA1nT8UzeB3gV6Kr5xxwrkj9M+8vR3otmeKa4tlZWsFqfS2VXo9/\n"
"lWTQk1/7LZYckzvceMXL1sQnQgkaBH366SRjlBYYhcP/YMa76Uypk+GVxePrltdU\n"
"3Z8v5wKBgEXL38yc9LqTIWe1U40ZZKvp2A8c86jtstorEEFqXharE8kxcEpL8ZLL\n"
"wjgPKdfNMIuApHSrhG7a7gU1rgJyDy1sOIwSvgTYrWfITPTVu5owvSZEblx4KYOm\n"
"g8hke3Oego4v9cwctkQss3/HZ6rs3PR942oAetuxLy3KPF83IeFm\n"
"-----END RSA PRIVATE KEY-----";

/*
 * PEM-encoded code verification certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char aws_codeVerCrt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIBMTCB2QIUX8Z/Uyltyj0VL3p7MoDHZgo3bx4wCgYIKoZIzj0EAwIwHDEaMBgG\n"
"A1UEAwwRY2NsaThAbnV2b3Rvbi5jb20wHhcNMjEwMTA3MDYwOTQ0WhcNMzEwMTA1\n"
"MDYwOTQ0WjAcMRowGAYDVQQDDBFjY2xpOEBudXZvdG9uLmNvbTBZMBMGByqGSM49\n"
"AgEGCCqGSM49AwEHA0IABDnZVzF1jjLjANoedmigucMqfR4GYT5YKa0Lk1HP2tJr\n"
"/thBapYq09ckcmb2Lja8SSr3nq3jG5hWMtnWotq4J0swCgYIKoZIzj0EAwIDRwAw\n"
"RAIgcOzyolG/LkEaaCorSShoYBdBfo5EAOf5Cq3/g2wv20ICIC4nhJ3l7EmLwhxg\n"
"SgcM+/daTX9aGMRMDJe3gUohXGtR\n"
"-----END CERTIFICATE-----";

/*
 * PEM-encoded code verification public key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN PUBLIC KEY-----\n"
 * "...base64 data...\n"
 * "-----END PUBLIC KEY-----";
 */
const char aws_codeVerPubKey[] = "-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOdlXMXWOMuMA2h52aKC5wyp9HgZh\n"
"PlgprQuTUc/a0mv+2EFqlirT1yRyZvYuNrxJKveereMbmFYy2dai2rgnSw==\n"
"-----END PUBLIC KEY-----\n";

/*
 * PEM-encoded code verification private key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN PRIVATE KEY-----\n"
 * "...base64 data...\n"
 * "-----END PRIVATE KEY-----";
 */
const char aws_codeVerPvtKey[] = "-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXcyrOBenlnnby+EJ\n"
"wpF09zt7GtIhP1Bz+v4ec29za7ShRANCAAQ52VcxdY4y4wDaHnZooLnDKn0eBmE+\n"
"WCmtC5NRz9rSa/7YQWqWKtPXJHJm9i42vEkq956t4xuYVjLZ1qLauCdL\n"
"-----END PRIVATE KEY-----\n";
