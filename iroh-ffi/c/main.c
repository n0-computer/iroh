#include <stdio.h>
#include <stdlib.h>

#include "iroh.h"

int main (int argc, char const * const argv[]) {
    if (argc < 3) {
        printf("Usage: %s <OUT_PATH> <TICKET>\n", argv[0]);
        return 1;
    }

    const char *out_path = argv[1];
    const char *ticket = argv[2];
    iroh_get_ticket(ticket, out_path);
    return EXIT_SUCCESS;
}