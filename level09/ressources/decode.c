#include <stdio.h>
int main(int argc, char **argv) {
  char *arg;
  int i = 0;
  if (argc != 2) {
    fprintf(stderr, "[-] Only one argument is accepted\n");
    return 1;
  }
  arg = argv[1];
  while (*arg) {
    printf("%c", *arg - i);
    i++;
    arg++;
  }
  printf("\n");
  return 0;
}