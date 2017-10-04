/* Copyright (c) 2017 Yutaro Hayakawa
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "bpf_load.h"
#include "bpf_util.h"
#include "libbpf.h"

#include <net/netmap.h>

#include <net/vale_bpf_native.h>

void die(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
  int err;
	char *filename;
  char *swname;

	filename = strdup(argv[1]);
  swname = strdup(argv[2]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	if (!prog_fd[0]) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

  int nmfd;
  nmfd = open("/dev/netmap", O_RDWR);
  if (nmfd < 0) {
    die("open");
  }

  struct nm_ifreq req;
  memset(&req, 0, sizeof(req));
  strcpy(req.nifr_name, swname);

  struct vale_bpf_native_req *r = (struct vale_bpf_native_req *)req.data;
  r->method = INSTALL_PROG;
  r->len = sizeof(int);
  r->ufd = prog_fd[0];

  err = ioctl(nmfd, NIOCCONFIG, &req);
  if (err < 0) {
    die("ioctl NIOCCONFIG");
  }

  free(filename);
  free(swname);

	return 0;
}
