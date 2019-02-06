/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include <aws/cal/hmac.h>
#include <aws/testing/aws_test_harness.h>

/*
 * these are the rfc4231  test vectors, as compiled here:
 * https://tools.ietf.org/html/rfc4231#section-4.1
 */

static int s_verify_test_case(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *input,
    struct aws_byte_cursor *secret,
    struct aws_byte_cursor *expected) {
    uint8_t output[AWS_SHA256_HMAC_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;

    struct aws_hmac *hmac = aws_sha256_hmac_new(allocator, secret);
    ASSERT_NOT_NULL(hmac);
    ASSERT_SUCCESS(aws_hmac_update(hmac, input));
    ASSERT_SUCCESS(aws_hmac_finalize(hmac, &output_buf));

    ASSERT_BIN_ARRAYS_EQUALS(expected->ptr, expected->len, output_buf.buffer, output_buf.len);

    aws_hmac_destroy(hmac);

    return AWS_OP_SUCCESS;
}

static int s_sha256_hmac_rfc4231_test_case_1_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t secret[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    struct aws_byte_cursor secret_buf = aws_byte_cursor_from_array(secret, sizeof(secret));

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("Hi There");
    uint8_t expected[] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input, &secret_buf, &expected_buf);
}

AWS_TEST_CASE(sha256_hmac_rfc4231_test_case_1, s_sha256_hmac_rfc4231_test_case_1_fn)

static int s_sha256_hmac_rfc4231_test_case_2_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t secret[] = {
        0x4a,
        0x65,
        0x66,
        0x65,
    };
    struct aws_byte_cursor secret_buf = aws_byte_cursor_from_array(secret, sizeof(secret));

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("what do ya want for nothing?");
    uint8_t expected[] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input, &secret_buf, &expected_buf);
}

AWS_TEST_CASE(sha256_hmac_rfc4231_test_case_2, s_sha256_hmac_rfc4231_test_case_2_fn)

static int s_sha256_hmac_rfc4231_test_case_3_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t secret[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    struct aws_byte_cursor secret_buf = aws_byte_cursor_from_array(secret, sizeof(secret));

    uint8_t input[] = {
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    };

    struct aws_byte_cursor input_buf = aws_byte_cursor_from_array(input, sizeof(input));

    uint8_t expected[] = {
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
        0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input_buf, &secret_buf, &expected_buf);
}

AWS_TEST_CASE(sha256_hmac_rfc4231_test_case_3, s_sha256_hmac_rfc4231_test_case_3_fn)

static int s_sha256_hmac_rfc4231_test_case_4_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    };
    struct aws_byte_cursor secret_buf = aws_byte_cursor_from_array(secret, sizeof(secret));

    uint8_t input[] = {
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    };

    struct aws_byte_cursor input_buf = aws_byte_cursor_from_array(input, sizeof(input));

    uint8_t expected[] = {
        0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
        0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input_buf, &secret_buf, &expected_buf);
}

AWS_TEST_CASE(sha256_hmac_rfc4231_test_case_4, s_sha256_hmac_rfc4231_test_case_4_fn)

/* test case 5 is deliberately left out. It deals with truncation behavior. */

static int s_sha256_hmac_rfc4231_test_case_6_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t secret[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    struct aws_byte_cursor secret_buf = aws_byte_cursor_from_array(secret, sizeof(secret));

    struct aws_byte_cursor input_buf =
        aws_byte_cursor_from_c_str("Test Using Larger Than Block-Size Key - Hash Key First");

    uint8_t expected[] = {
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
        0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input_buf, &secret_buf, &expected_buf);
}

AWS_TEST_CASE(sha256_hmac_rfc4231_test_case_6, s_sha256_hmac_rfc4231_test_case_6_fn)

static int s_sha256_hmac_rfc4231_test_case_7_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t secret[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    struct aws_byte_cursor secret_buf = aws_byte_cursor_from_array(secret, sizeof(secret));

    struct aws_byte_cursor input_buf =
        aws_byte_cursor_from_c_str("This is a test using a larger than block-size key and a larger than block-size "
                                   "data. The key needs to be hashed before being used by the HMAC algorithm.");

    uint8_t expected[] = {
        0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
        0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input_buf, &secret_buf, &expected_buf);
}

AWS_TEST_CASE(sha256_hmac_rfc4231_test_case_7, s_sha256_hmac_rfc4231_test_case_7_fn)

static int s_sha256_hmac_invalid_buffer_size_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t secret[] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    };
    struct aws_byte_cursor secret_buf = aws_byte_cursor_from_array(secret, sizeof(secret));

    struct aws_hmac *hmac = aws_sha256_hmac_new(allocator, &secret_buf);
    ASSERT_NOT_NULL(hmac);

    uint8_t output[AWS_SHA256_HMAC_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 1;
    ASSERT_ERROR(AWS_ERROR_SHORT_BUFFER, aws_hmac_finalize(hmac, &output_buf));
    aws_hmac_destroy(hmac);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha256_hmac_invalid_buffer_size, s_sha256_hmac_invalid_buffer_size_fn)
