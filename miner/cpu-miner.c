/*
 * cpu-miner.c (YESPOWERTIDE WASM VERSION)
 * ------------------------------------------------------------
 * Output format (string returned):
 *   "NONCE,HEX_HASH,HEX_TARGET"
 *
 * Nonce = 8 hex chars
 * Hash  = 64 hex chars
 * Target= 64 hex chars
 *
 * Fully compatible with browser miner (WebWorker) using Module.cwrap()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "miner.h"
#include "sysendian.h"
#include "yespower.h"

/* -----------------------------------------------------------
   Pretest: fast comparison before fulltest()
----------------------------------------------------------- */
static inline int pretest(const uint32_t *hash, const uint32_t *target)
{
    return hash[7] < target[7];
}

/* -----------------------------------------------------------
   sha256d_str — optional helper for bench/testing
----------------------------------------------------------- */
char* sha256d_str(const char* input)
{
    static char out[65];
    uint8_t hash[32];

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)input, strlen(input));
    sha256_final(&ctx, hash);

    sha256_init(&ctx);
    sha256_update(&ctx, hash, 32);
    sha256_final(&ctx, hash);

    bin2hex(out, hash, 32);
    return out;
}

/* -----------------------------------------------------------
   MAIN MINER FUNCTION — YESPOWERTIDE VERSION
----------------------------------------------------------- */
const char* miner_thread(const char* blockheader, const char* targetstr,
        uint32_t first_nonce)
{
    static char rv[8 + 1 + 64 + 1 + 64 + 1];

    uint32_t headerbin[20];
    uint32_t data[28] __attribute__((aligned(128)));
    uint32_t hash[8]  __attribute__((aligned(32)));
    uint32_t target[8];
    uint32_t max_nonce = 0xffffffffU;

    uint32_t n = first_nonce - 1;
    uint32_t n2 = 0;
    double diff;

    /* ------------------------------
       YESPOWERTIDE PARAMETERS
       N = 2048, r = 8 (LITE)
    ------------------------------ */
    yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 8,
        .pers = NULL,
        .perslen = 0
    };

    /* Convert header HEX → binary */
    hex2bin(headerbin, blockheader, 80);

    /* Convert difficulty → target */
    diff = atof(targetstr);
    diff_to_target(target, diff / 65536.0);

    /* Prepare parsed 80-byte block header → uint32 */
    data[0] = be32dec(&((uint8_t*)headerbin)[0]);

    /* Prev hash */
    for (int i = 0; i < 8; i++)
        data[i+1] = be32dec(&((uint8_t*)headerbin)[(i+1)*4]);

    /* Merkle root */
    for (int i = 0; i < 8; i++)
        data[9+i] = le32dec(&((uint8_t*)headerbin)[(i+9)*4]);

    /* nTime, nBits, Nonce placeholder */
    for (int i = 17; i < 20; i++)
        data[i] = be32dec(&((uint8_t*)headerbin)[i*4]);

    /* ------------------------------
       Main mining loop
    ------------------------------ */
    do {
        be32enc(&data[19], ++n);

        yespower_tls((const uint8_t*)data, 80, &params,
                     (yespower_binary_t*)hash);

        if (pretest(hash, target) && fulltest(hash, target)) {
            n2 = n;

            bin2hex(rv, &n2, 4);
            rv[8] = ',';

            bin2hex(&rv[9], hash, 32);
            rv[9+64] = ',';

            bin2hex(&rv[10+64], target, 32);
            rv[10+64+64] = 0;

            return rv;
        }

    } while (n < max_nonce);

    rv[0] = 0;
    return rv;
}
