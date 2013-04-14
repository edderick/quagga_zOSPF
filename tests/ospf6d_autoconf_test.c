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

  ospf6 = malloc ( sizeof (struct ospf6));
  
  ospf6->area_list = list_new();
  ospf6->aggregated_prefix_list = list_new ();

  backbone_area = malloc (sizeof (struct ospf6_area));
  backbone_area->area_id = 0;

  backbone_area->lsdb = malloc (sizeof (struct ospf6_lsdb));
  backbone_area->lsdb_self = malloc (sizeof (struct ospf6_lsdb));

  backbone_area->lsdb->table = malloc (sizeof (struct route_table));
  backbone_area->lsdb->table->top = malloc (sizeof (struct route_node));

  listnode_add (ospf6->area_list, backbone_area);
}

int 
main (int argc, int **argv)
{
  setup();  

  ospf6_assign_prefixes ();
  
  printf (OK "\n");
}
