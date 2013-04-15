#include <zebra.h>

/* Includes from main */
#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "prefix.h"
#include "command.h"
#include "if.h"
#include "md5.h"
#include "privs.h"
#include "getopt.h"
#include "log.h"
#include "memory.h"
#include "filter.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"

/* Includes from auto */
#include "ospf6d/ospf6_top.h"
#include "ospf6d/ospf6_zebra.h"
#include "ospf6d/ospf6_interface.h"
#include "ospf6d/ospf6_message.h"
#include "ospf6d/ospf6_area.h"
#include "ospf6d/ospf6_neighbor.h"

#include "ospf6d/ospf6_intra.h"
#include "ospf6d/ospf6_lsdb.h"
#include "ospf6d/ospf6_lsa.h"
#include "ospf6d/ospf6_proto.h"
#include "ospf6d/ospf6_abr.h"
#include "ospf6d/ospf6d.h"

#include "ospf6d/ospf6_auto.h"

#define VT100_RESET "\x1b[0m"
#define VT100_RED "\x1b[31m"
#define VT100_GREEN "\x1b[32m"
#define VT100_YELLOW "\x1b[33m"
#define OK VT100_GREEN "OK" VT100_RESET
#define FAILED VT100_RED "failed" VT100_RESET

struct thread_master *master = NULL;

int auto_conf = 1;

zebra_capabilities_t _caps_p [] =
{
    ZCAP_NET_RAW,
      ZCAP_BIND
};

struct zebra_privs_t ospf6d_privs =
{
#if defined(QUAGGA_USER)
  .user = QUAGGA_USER,
#endif
#if defined QUAGGA_GROUP
  .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = 2,
  .cap_num_i = 0
};

static void 
setup (void)
{
  struct ospf6_area *backbone_area;

  master = malloc ( sizeof (struct thread));

  ospf6 = ospf6_create ();
	backbone_area = ospf6_area_create (0, ospf6);
	
	ospf6->router_id = 0;


	/* PULL OUT */
	struct ospf6_lsa *lsa;
	struct ospf6_lsa_header *lsa_header;

	lsa_header = malloc (4090);

	lsa_header->age = 0;
	lsa_header->type = htons (OSPF6_LSTYPE_AC);
	lsa_header->id = 0;
	lsa_header->adv_router = ospf6->router_id;
	lsa_header->seqnum =
	  ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
				lsa_header->adv_router, backbone_area->lsdb);

	lsa_header->length = sizeof (struct ospf6_lsa_header);

	ospf6_lsa_checksum (lsa_header);

	ospf6_lsa_init ();
	ospf6_intra_init ();

	lsa = ospf6_lsa_create (lsa_header);

	ospf6_lsdb_add (lsa, backbone_area->lsdb);

}

int 
main (int argc, int **argv)
{
  setup();  

  ospf6_assign_prefixes ();
	
	if (ospf6->aggregated_prefix_list == NULL)
	{
		printf (FAILED "\n");
	}	
	else 
	{
  	printf (OK "\n");
	}

}
