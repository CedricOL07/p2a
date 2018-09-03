#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

/* signatures */
void sha(char ip[20], int port, char* hash_string);
int nbr_digits(int a);

/* MAIN */
int main(int argc, char *argv[]) {
    char hash_string[SHA_DIGEST_LENGTH*2+1];
    char ip[20];
    // check args
    if (argc!=3) {
        printf("Usage:\n./sha IP PORT\n");
        exit(1);
    }
    // save args as local vars
    int port = atoi(argv[2]);
    strncpy(ip, argv[1], sizeof(ip)-1);
    printf("IP:   %s\nPort: %d\n", ip, port);
    // call sha1 and print result
    sha(ip, port, hash_string);
    printf("SHA1: %s\n", hash_string);
    return 0;
}

/* UTILS (can be found in <utils.c> as well) */
void sha(char ip[20], int port, char* hash_string) {
  /*
   * Returns sha1(<ip>, <port>) in <hash_string>
   */
  unsigned char hash[SHA_DIGEST_LENGTH];
  char port_str[nbr_digits(port)];
  sprintf(port_str, "%d", port);
  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, ip, strlen(ip));
  SHA1_Update(&ctx, port_str, strlen(port_str));
  SHA1_Final(hash, &ctx);
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
    sprintf(&hash_string[i*2], "%02x", (unsigned int)hash[i]);
  }
}

int nbr_digits(int a) {
  /*
   * Returns the number of digits in a relatively small positive integer.
   * Yep, pretty ugly but oh well..
   */
  if (a<0) return -1;
  if (a<10) return 1;
  if (a<100) return 2;
  if (a<1000) return 3;
  if (a<10000) return 4;
  if (a<100000) return 5;
  if (a<1000000) return 6;
  if (a<10000000) return 7;
  if (a<100000000) return 8;
  if (a<1000000000) return 9;
  if (a<10000000000) return 10;
  return -1;
}
