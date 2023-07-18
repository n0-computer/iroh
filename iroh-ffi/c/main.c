#include <stdio.h>
#include <stdlib.h>

#include "iroh.h"

int main (int argc, char const * const argv[]) {
  if (argc < 3) {
    printf("Usage: %s <OUT_PATH> <TICKET>\n", argv[0]);
    return 1;
  }

  printf("starting node...\n");
  fflush(stdout);
  
  iroh_node_t *node = iroh_initialize();
  if (node == NULL) {
    printf("failed to start node\n");
    fflush(stdout);
    return -1;
  }

  printf("node started\n");
  fflush(stdout);
    
  const char *out_path = argv[1];
  const char *ticket = argv[2];
  iroh_error_t * err = iroh_get_ticket(node, ticket, out_path);
  if (err != NULL) {
    char * msg = iroh_error_message_get(err);
    printf("failed: %s\n", msg);
    fflush(stdout);

    iroh_string_free(msg);
    iroh_error_free(err);
    return -1;
  }

  printf("done\n");
  fflush(stdout);
  iroh_free(node);
  
  return EXIT_SUCCESS;
}

