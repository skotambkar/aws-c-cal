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
#include <aws/cal/hash.h>
#include <aws/testing/aws_test_harness.h>

/*
 * these are the NIST test vectors, as compiled here:
 * https://www.di-mgt.com.au/sha_testvectors.html
 */

static int s_verify_test_case(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *input,
    struct aws_byte_cursor *expected) {
    uint8_t output[AWS_SHA256_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;

    struct aws_hash *hash = aws_sha256_new(allocator);
    ASSERT_NOT_NULL(hash);
    ASSERT_SUCCESS(aws_hash_update(hash, input));
    ASSERT_SUCCESS(aws_hash_finalize(hash, &output_buf));

    ASSERT_BIN_ARRAYS_EQUALS(expected->ptr, expected->len, output_buf.buffer, output_buf.len);

    aws_hash_destroy(hash);

    return AWS_OP_SUCCESS;
}

static int s_sha256_nist_test_case_1_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("abc");
    uint8_t expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input, &expected_buf);
}

AWS_TEST_CASE(sha256_nist_test_case_1, s_sha256_nist_test_case_1_fn)

static int s_sha256_nist_test_case_2_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("");
    uint8_t expected[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input, &expected_buf);
}

AWS_TEST_CASE(sha256_nist_test_case_2, s_sha256_nist_test_case_2_fn)

static int s_sha256_nist_test_case_3_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
        aws_byte_cursor_from_c_str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    uint8_t expected[] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input, &expected_buf);
}

AWS_TEST_CASE(sha256_nist_test_case_3, s_sha256_nist_test_case_3_fn)

static int s_sha256_nist_test_case_4_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
        aws_byte_cursor_from_c_str("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklm"
                                   "nopqrlmnopqrsmnopqrstnopqrstu");
    uint8_t expected[] = {
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
        0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_test_case(allocator, &input, &expected_buf);
}

AWS_TEST_CASE(sha256_nist_test_case_4, s_sha256_nist_test_case_4_fn)

static int s_sha256_nist_test_case_5_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_hash *hash = aws_sha256_new(allocator);
    ASSERT_NOT_NULL(hash);
    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("a");

    for (size_t i = 0; i < 1000000; ++i) {
        ASSERT_SUCCESS(aws_hash_update(hash, &input));
    }

    uint8_t output[AWS_SHA256_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;
    ASSERT_SUCCESS(aws_hash_finalize(hash, &output_buf));

    uint8_t expected[] = {
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
        0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));
    ASSERT_BIN_ARRAYS_EQUALS(expected_buf.ptr, expected_buf.len, output_buf.buffer, output_buf.len);

    aws_hash_destroy(hash);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha256_nist_test_case_5, s_sha256_nist_test_case_5_fn)

static int s_sha256_nist_test_case_6_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_hash *hash = aws_sha256_new(allocator);
    ASSERT_NOT_NULL(hash);
    struct aws_byte_cursor input =
        aws_byte_cursor_from_c_str("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");

    for (size_t i = 0; i < 16777216; ++i) {
        ASSERT_SUCCESS(aws_hash_update(hash, &input));
    }

    uint8_t output[AWS_SHA256_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;
    ASSERT_SUCCESS(aws_hash_finalize(hash, &output_buf));

    uint8_t expected[] = {
        0x50, 0xe7, 0x2a, 0x0e, 0x26, 0x44, 0x2f, 0xe2, 0x55, 0x2d, 0xc3, 0x93, 0x8a, 0xc5, 0x86, 0x58,
        0x22, 0x8c, 0x0c, 0xbf, 0xb1, 0xd2, 0xca, 0x87, 0x2a, 0xe4, 0x35, 0x26, 0x6f, 0xcd, 0x05, 0x5e,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));
    ASSERT_BIN_ARRAYS_EQUALS(expected_buf.ptr, expected_buf.len, output_buf.buffer, output_buf.len);

    aws_hash_destroy(hash);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha256_nist_test_case_6, s_sha256_nist_test_case_6_fn)

static int s_sha256_invalid_buffer_size_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_hash *hash = aws_sha256_new(allocator);
    ASSERT_NOT_NULL(hash);

    uint8_t output[AWS_SHA256_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 1;
    ASSERT_ERROR(AWS_ERROR_SHORT_BUFFER, aws_hash_finalize(hash, &output_buf));
    aws_hash_destroy(hash);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha256_invalid_buffer_size, s_sha256_invalid_buffer_size_fn)
