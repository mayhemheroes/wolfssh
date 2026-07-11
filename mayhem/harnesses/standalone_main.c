/* standalone_main.c — run-once reproducer driver for the wolfSSH libFuzzer harness.
 *
 * Reads each path argument as a single input file and feeds its bytes to
 * LLVMFuzzerTestOneInput exactly once. No libFuzzer runtime — used to replay a
 * crashing testcase under the sanitizers outside the fuzzing engine.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    int i;
    for (i = 1; i < argc; i++) {
        FILE* f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); continue; }
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        if (n < 0) { fclose(f); continue; }
        fseek(f, 0, SEEK_SET);
        uint8_t* buf = (uint8_t*)malloc((size_t)n ? (size_t)n : 1);
        size_t got = fread(buf, 1, (size_t)n, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, got);
        free(buf);
    }
    return 0;
}
