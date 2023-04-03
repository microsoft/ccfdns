// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cstdio>
#include <cstdlib>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/types.h>

int main(int argc, char** argv)
{
  int r = 0;
  size_t n = 1024;

  if (argc > 1)
    n = atoll(argv[1]);

  union msg
  {
    unsigned char buf[4096];
    HEADER h;
  } res;

  _res.options = (RES_USEVC | RES_DEBUG | RES_USE_DNSSEC) & ~RES_STAYOPEN;

  if ((r = res_init()) != 0)
  {
    printf("res_init() failed: %d\n", r);
    return 1;
  }

  inet_aton("10.1.0.4", &_res.nsaddr_list[0].sin_addr);
  // _res.nsaddr_list[0].sin_port = htons(1054);

  size_t i = 0;
  for (; i < n; i++)
  {
    if (
      (r = res_query(
         "ns1.adns.ccf.dev.", C_IN, T_A, res.buf, sizeof(res.buf))) < 0)
    {
      printf(
        "res_query() failed after %zu queries: %s (%u)\n",
        i + 1,
        hstrerror(_res.res_h_errno),
        _res.res_h_errno);
      return 1;
    }
  }

  printf("last answer:\n");
  printf("flags=%02x%02x\n", res.buf[2], res.buf[3]);
  printf("qdcount=%u\n", ntohs(res.h.qdcount));
  printf("ancount=%u\n", ntohs(res.h.ancount));
  printf("ancount=%u\n", ntohs(res.h.nscount));
  printf("qdcount=%u\n", ntohs(res.h.arcount));

  printf("# queries: %zu\n", i);
  return 0;
}
