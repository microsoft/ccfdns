// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/types.h>

union msg
{
  unsigned char buf[4096];
  HEADER h;
} res;

void show_reply(union msg& reply, int reply_size)
{
  size_t i = 0;
  char pbuf[4096];
  ns_msg msg;
  ns_rr rr;

  printf("Flags: %02x%02x\n", reply.buf[2], reply.buf[3]);
  // printf("qdcount=%u\n", ntohs(reply.h.qdcount));
  // printf("ancount=%u\n", ntohs(reply.h.ancount));
  // printf("nscount=%u\n", ntohs(reply.h.nscount));
  // printf("qdcount=%u\n", ntohs(reply.h.arcount));

  ns_initparse(reply.buf, reply_size, &msg);
  printf("\n");
  printf("Questions:\n");
  for (i = 0; i < ns_msg_count(msg, ns_s_qd); i++)
  {
    ns_parserr(&msg, ns_s_qd, i, &rr);
    sprintf(
      pbuf,
      "%s.  %s %s %s\n",
      ns_rr_name(rr),
      p_time(ns_rr_ttl(rr)),
      p_class(ns_rr_class(rr)),
      p_type(ns_rr_type(rr)));
    printf("  %s \n", pbuf);
  }
  printf("Answers:\n");
  for (i = 0; i < ns_msg_count(msg, ns_s_an); i++)
  {
    ns_parserr(&msg, ns_s_an, i, &rr);
    ns_sprintrr(&msg, &rr, NULL, NULL, pbuf, sizeof(pbuf));
    printf("  %s \n", pbuf);
  }
  printf("Authorities:\n");
  for (i = 0; i < ns_msg_count(msg, ns_s_ns); i++)
  {
    ns_parserr(&msg, ns_s_ns, i, &rr);
    ns_sprintrr(&msg, &rr, NULL, NULL, pbuf, sizeof(pbuf));
    printf("  %s \n", pbuf);
  }
  printf("Additional:\n");
  for (i = 0; i < ns_msg_count(msg, ns_s_ar); i++)
  {
    ns_parserr(&msg, ns_s_ar, i, &rr);
    ns_sprintrr(&msg, &rr, NULL, NULL, pbuf, sizeof(pbuf));
    printf("  %s \n", pbuf);
  }

  printf("\n");
}

int main(int argc, char** argv)
{
  int r = 0;
  size_t n = 1000;
  const char* server = "10.1.0.4";
  const char* qname = "service43.adns.ccf.dev.";
  int type = T_A;

  if (argc > 1)
    n = atoll(argv[1]);

  if (argc > 2)
    qname = argv[2];

  if (argc > 3)
  {
    if (strcmp(argv[3], "A") == 0)
      type = T_A;
    else if (strcmp(argv[3], "AAAA") == 0)
      type = T_AAAA;
    else if (strcmp(argv[3], "NS") == 0)
      type = T_NS;
    else if (strcmp(argv[3], "RRSIG") == 0)
      type = T_RRSIG;
    else if (strcmp(argv[3], "TXT") == 0)
      type = T_TXT;
    else if (strcmp(argv[3], "ATTEST") == 0)
      type = 32771;
  }

  _res.options = (RES_USEVC | RES_DEBUG | RES_USE_DNSSEC) & ~RES_STAYOPEN;

  if ((r = res_init()) != 0)
  {
    printf("res_init() failed: %d\n", r);
    return 1;
  }

  inet_aton(server, &_res.nsaddr_list[0].sin_addr);
  //_res.nsaddr_list[0].sin_port = htons(1054);

  size_t i = 0;
  for (; i < n; i++)
  {
    if ((r = res_query(qname, C_IN, type, res.buf, sizeof(res.buf))) < 0)
    {
      printf(
        "res_query() failed after %zu queries: %s (%u)\n",
        i + 1,
        hstrerror(_res.res_h_errno),
        _res.res_h_errno);
      return 1;
    }
  }

  printf("Last reply:\n");
  show_reply(res, r);

  printf("# queries: %zu\n", i);
  return 0;
}
