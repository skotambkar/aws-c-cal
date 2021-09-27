/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/cal.h>
#include <aws/cal/hash.h>

#include <aws/checksums/crc.h>

#include <aws/common/clock.h>
#include <aws/common/device_random.h>

#include <inttypes.h>

#define UNUSED(x) (void)(x)

static void s_profile_streaming_hash_at_chunk_size(
    struct aws_allocator *allocator,
    struct aws_byte_cursor to_hash,
    size_t chunk_size,
    size_t alignment,
    bool print) {

    UNUSED(allocator);

    struct aws_byte_cursor to_hash_seeked = to_hash;

    uint64_t start = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");

    uint32_t runningHash = 0;

    if (alignment) {
        size_t alignment_miss = (uintptr_t)to_hash_seeked.ptr % alignment;
        struct aws_byte_cursor unaligned_chunk = aws_byte_cursor_advance(&to_hash_seeked, alignment_miss);
        runningHash = aws_checksums_crc32(unaligned_chunk.ptr, unaligned_chunk.len, runningHash);
    }

    while (to_hash_seeked.len) {
        size_t remaining = chunk_size > to_hash_seeked.len ? to_hash_seeked.len : chunk_size;
        struct aws_byte_cursor chunk_to_process = aws_byte_cursor_advance(&to_hash_seeked, remaining);
        runningHash = aws_checksums_crc32(chunk_to_process.ptr, chunk_to_process.len, runningHash);
    }

    uint64_t end = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed");

    if(print) {
//        fprintf(stdout, "CRC32 streaming hash is %" PRIu32 "\n", runningHash);
        fprintf(stdout, "CRC32 streaming computation took %" PRIu64 "ns\n", end - start);
    }
}

static void s_profile_oneshot_hash(struct aws_allocator *allocator, struct aws_byte_cursor to_hash) {
    UNUSED(allocator);

    uint64_t start = 0;
    uint32_t runningHash = 0;

    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");
    runningHash = aws_checksums_crc32(to_hash.ptr, to_hash.len, runningHash);

    uint64_t end = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed");
//    fprintf(stdout, "CRC32 streaming hash is %" PRIu32 "\n", runningHash);
    fprintf(stdout, "CRC32 oneshot computation took %" PRIu64 "ns\n", end - start);
}

static void s_run_profiles(struct aws_allocator *allocator, size_t to_hash_size, const char *profile_name) {
    fprintf(stdout, "********************* CRC32 Profile %s ************************************\n\n", profile_name);

    struct aws_byte_buf to_hash;
    AWS_FATAL_ASSERT(!aws_byte_buf_init(&to_hash, allocator, to_hash_size) && "failed to allocate buffer for hashing");
    AWS_FATAL_ASSERT(!aws_device_random_buffer(&to_hash) && "reading random data failed");
    struct aws_byte_cursor to_hash_cur = aws_byte_cursor_from_buf(&to_hash);

    fprintf(stdout, "********************* Chunked/Alignment Runs *********************************\n\n");
    fprintf(stdout, "****** 128 byte chunks ******\n\n");
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 8, false);
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 8, true);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 16, true);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 64, true);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 128, true);
    fprintf(stdout, "\n****** 256 byte chunks ******\n\n");
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 8, true);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 16, true);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 64, true);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 128, true);

    fprintf(stdout, "\n******* 512 byte chunks *****\n\n");
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 8, true);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 16, true);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 64, true);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 128, true);

    fprintf(stdout, "\n********************** Oneshot Run *******************************************\n\n");
    s_profile_oneshot_hash(allocator, to_hash_cur);
    fprintf(stdout, "\n\n");
    aws_byte_buf_clean_up(&to_hash);
}

int main(void) {
    struct aws_allocator *allocator = aws_default_allocator();
    aws_cal_library_init(allocator);

    fprintf(stdout, "Starting profile run for Crc32 using implementation \n\n");
    s_run_profiles(allocator, 1024, "1 KB");
    s_run_profiles(allocator, 1024 * 64, "64 KB");
    s_run_profiles(allocator, 1024 * 128, "128 KB");
    s_run_profiles(allocator, 1024 * 512, "512 KB");

    aws_cal_library_clean_up();
    return 0;
}
