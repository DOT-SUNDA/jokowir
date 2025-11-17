/*
 * cpu-miner.c – YESPOWERTIDE + compatible with miner.h / sha256.c / util.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "miner.h"
#include "sysendian.h"
#include "yespower.h"

/* ------------------------------------------------------------
   Double SHA256 → string hex output
   (Compatible with miner.h where sha256_init takes uint32_t *)
------------------------------------------------------------ */

char* sha256d_str(const char* input)
{
    static char out[65];
    uint8_t hash1[32], hash2[32];
    uint32_t ctx[8];

    /* SHA256 #1 */
    sha256_init(ctx);
    sha256_update(ctx, (const uint8_t*)input, strlen(input));
    sha256_final(ctx, hash1);

    /* SHA256 #2 */
    sha256_init(ctx);
    sha256_update(ctx, hash1, 32);
    sha256_final(ctx, hash2);

    bin2hex(out, hash2, 32);
    return out;
}

/* ------------------------------------------------------------
   Pretest (quick reject)
------------------------------------------------------------ */
static inline int pretest(const uint32_t *h, const uint32_t *t)
{
    return h[7] < t[7];
}

/* ------------------------------------------------------------
   YESPOWERTIDE Miner
------------------------------------------------------------ */
const char* miner_thread(const char* blockheader, const char* targetstr,
        uint32_t first_nonce)
{
    static char rv[8 + 1 + 64 + 1 + 64 + 1];

    uint8_t headerbin[80];
    uint32_t data[20];
    uint32_t hash[8];
    uint32_t target[8];

    uint32_t n = first_nonce - 1;
    uint32_t n2 = 0;
    double diff;
    uint32_t max_nonce = 0xffffffffU;

    /* YESPOWERTIDE PARAMS */
    yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 8,
        .pers = NULL,
        .perslen = 0
    };

    /* Convert blockheader HEX → bytes */
    hex2bin(headerbin, blockheader, 80);

    /* Difficulty → target */
    diff = atof(targetstr);
    diff_to_target(target, diff / 65536.0);

    /* Parse header */
    for (int i=0;i<20;i++)
        data[i] = be32dec(&headerbin[i*4]);

    /* Main loop */
    do {
        data[19] = ++n;

        yespower_tls((const uint8_t*)data, 80, &params,
                     (yespower_binary_t*)hash);

        if (pretest(hash, target) && fulltest(hash, target)) {

            n2 = n;

            /* nonce hex */
            bin2hex(rv, (uint8_t*)&n2, 4);
            rv[8] = ',';

            /* hash hex */
            bin2hex(&rv[9], (uint8_t*)hash, 32);
            rv[9+64] = ',';

            /* target hex */
            bin2hex(&rv[10+64], (uint8_t*)target, 32);
            rv[10+64+64] = 0;

            return rv;
        }

    } while (n < max_nonce);

    rv[0] = 0;
    return rv;
}
