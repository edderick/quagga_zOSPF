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

#define OWN_ID 0
#define CONNECTED_IF_ID 0
#define NOT_NEIGHBOR -1

const int test_count = 9;
int fail_count;

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

struct lsa 
{
  u_int32_t id;

  int if_index;

  int num_of_aggregated_prefixes;
  char aggregated_prefix[10][64];

  int num_of_assigned_prefixes;
  char assigned_prefix[10][64];
  int ifindex[10];
};

struct test_case 
{
  int number;
  int num_of_lsas;
  int num_of_interfaces;
  struct lsa lsa[10]; /* XXX */
};

struct test_case test_cases[] = 
{
  {/* Test Case: */ 0, 
    1, 0,
    {
      {OWN_ID, 0, 0, {}, 0, {}, {}}
    }
  }, 
  {/* Test Case: */ 1,
    1, 0,
    {
      {OWN_ID, 0, 1, {"fc00::/48"}, 0, {}, {}}
    }
  },
  {/* Test Case: */ 2,
    1, 0,
    {
      {OWN_ID, 0, 2, {"fc00::/48", "fc01::/48"}, 0, {}, {}}
    }
  },
  {/* Test Case: */ 3,
    1, 1,
    {
      {OWN_ID, 0, 1, {"fc00::/48"}, 0, {}, {0}}
    }
  },
  {/* Test Case: */ 4,
    2, 2,
    {
      {OWN_ID, 0, 1, {"fc00::/48"}, 2, {"fc00:0:0:1::/64", "fc00:0:0:2::/64"}, {0, 1}},
      {1, 0, 0, {}, 1, {"fc00:0:0:3::/64"}, {CONNECTED_IF_ID}}
    }
  },
  {/* Test Case: */ 5,
    2, 2,
    {
      {OWN_ID, 0, 1, {"fc00::/48"}, 2, {"fc00:0:0:1::/64", "fc00:0:0:2::/64"}, {0, 1}},
      {1, 0, 1, {"fc00:1::/48"}, 1, {"fc00:0:0:3::/64"}, {CONNECTED_IF_ID}}
    }
  },
  {/* Test Case: */ 6,
    3, 2,
    {
      {OWN_ID, 0, 0, {}, 0, {}, {}},
      {1, 0, 1, {"fc00::/48"}, 1, {"fc00:0:0:1::/64"}, {CONNECTED_IF_ID}},
      {2, 1, 0, {}, 1, {"fc00:0:0:2::/64"}, {CONNECTED_IF_ID}}
    }
  },
  {/* Test Case: */ 7,
    3, 2,
    {
      {OWN_ID, 0, 0, {}, 0, {}, {}},
      {1, 0, 1, {"fc00::/48"}, 1, {"fc00:0:0:1::/64"}, {CONNECTED_IF_ID}},
      {2, NOT_NEIGHBOR, 0, {}, 1, {"fc00:0:0:2::/64"}, {CONNECTED_IF_ID}}
    }
  },
  {/* Test Case: */ 8,
    1, 2,
    {
      {OWN_ID, 0, 2, {"fc00::/48", "fc01::/48"}, 0, {}, {}}
    }
  }
};

#define COND_AGG_PREFIX	      0
#define COND_ASS_PREFIX_IS    1
#define COND_ASS_PREFIX_ISNT  2
#define COND_IS_PENDING	      3
#define COND_IS_DEPRECATING   4

struct condition 
{
  int type;
  char prefix[64];
  int ifindex;
};

struct expected_value 
{
  int num_of_interfaces;
  int num_of_aggregated_prefixes;
  int num_of_assigned_prefixes;
  int num_of_assigned_prefixes_on_interface[10];
  
  int num_of_conditions;
  struct condition conditions[10];
};

struct expected_value expected_values[] = 
{
  /* Expected Value for Testcase 0 */
  {0, 0, 0, {}, 0, {}},
  /* Expected Value for Testcase 1 */
  {0, 1, 0, {}, 1, 
    {
      {COND_AGG_PREFIX, "fc00/48", 0}
    }
  }, 
  /* Expected Value for Testcase 2 */
  {0, 2, 0, {}, 2, 
    {
      {COND_AGG_PREFIX, "fc00/48", 0},
      {COND_AGG_PREFIX, "fc01/48", 0}
    }
  },
  /* Expected Value for Testcase 3 */
  {1, 1, 1, {1}, 2,
    {
      {COND_AGG_PREFIX, "fc00/48", 0},
      {COND_IS_PENDING, "", 0}
    }
  },
  /* Expected Value for Testcase 4 */
  {2, 1, 3, {2, 1}, 4,
    {
      {COND_AGG_PREFIX, "fc00/47", 0},
      {COND_IS_DEPRECATING, "fc00:0:0:1::/64", 0},
      {COND_ASS_PREFIX_IS, "fc00:0:0:3::/64", 0},
      {COND_ASS_PREFIX_IS, "fc00:0:0:2::/64", 0},
    }
  }
};
/* A modified version of the AC-LSA origination code.
   Used to generated AC-LSAs. */
  static struct ospf6_lsa *
create_ac_lsa (struct ospf6_area *oa,
    struct lsa *test_lsa,
    u_int32_t id)
{
  char buffer [OSPF6_MAX_LSASIZE];
  struct ospf6_lsa_header *lsa_header;
  struct ospf6_lsa *lsa;

  int i;

  u_int32_t link_state_id = 0;
  void *current_tlv;
  struct ospf6_ac_lsa *ac_lsa;
  struct ospf6_ac_tlv_router_hardware_fingerprint *ac_tlv_rhwfp;
  struct ospf6_ac_tlv_aggregated_prefix *ac_tlv_ag_p;
  struct ospf6_ac_tlv_assigned_prefix *ac_tlv_as_p;

  struct listnode *node, *nextnode;
  struct ospf6_aggregated_prefix *aggregated_prefix;
  struct ospf6_interface *ifp;

  memset (buffer, 0, sizeof (buffer));
  lsa_header = (struct ospf6_lsa_header *) buffer;
  ac_lsa = (struct ospf6_ac_lsa *)
    ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

  current_tlv = ac_lsa;

  /* Fill AC-LSA */
  /* Router-Hardware Fingerprint */
  ac_tlv_rhwfp = (struct ospf6_ac_tlv_router_hardware_fingerprint *) current_tlv; 
  ac_tlv_rhwfp->header.type = htons (OSPF6_AC_TLV_ROUTER_HARDWARE_FINGERPRINT);
  ac_tlv_rhwfp->header.length = htons (OSPF6_AC_TLV_RHWFP_LENGTH);

  /*TODO: FIX THIS */
  memset (&ac_tlv_rhwfp->value, 0, 32); 

  /* Step onto next tlv? */
  current_tlv = ++ac_tlv_rhwfp;

  /* Aggregated (allocated) prefixes */
  for (i = 0; i < test_lsa->num_of_aggregated_prefixes; i++) 
  {
    struct prefix prefix; 
    str2prefix (test_lsa->aggregated_prefix[i], &prefix);

    ac_tlv_ag_p = (struct ospf6_ac_tlv_aggregated_prefix *) current_tlv;
    ac_tlv_ag_p->header.type = htons (OSPF6_AC_TLV_AGGREGATED_PREFIX);
    ac_tlv_ag_p->header.length = htons (OSPF6_AC_TLV_AGGREGATED_PREFIX_LENGTH);

    /* Send prefix */ 
    ac_tlv_ag_p->prefix_length = prefix.prefixlen;
    ac_tlv_ag_p->prefix = prefix.u.prefix6;

    current_tlv = ++ac_tlv_ag_p;
  }

  /* Assigned prefixes */
  for (i = 0; i < test_lsa->num_of_assigned_prefixes; i++) 
  {
    struct prefix prefix; 
    str2prefix (test_lsa->assigned_prefix[i], &prefix);

    ac_tlv_as_p = (struct ospf6_ac_tlv_assigned_prefix *) current_tlv;
    ac_tlv_as_p->header.type = htons (OSPF6_AC_TLV_ASSIGNED_PREFIX);
    ac_tlv_as_p->header.length = htons (OSPF6_AC_TLV_ASSIGNED_PREFIX_LENGTH);

    /* Send prefix */ 
    ac_tlv_as_p->prefix_length = prefix.prefixlen;
    ac_tlv_as_p->prefix = prefix.u.prefix6;

    ac_tlv_as_p->interface_id = test_lsa->ifindex[i];

    if (id == OWN_ID)
    {
      struct ospf6_interface *oi;
      struct ospf6_assigned_prefix *ass_p;
      oi = ospf6_interface_lookup_by_ifindex (i);

      ass_p = malloc (sizeof (struct ospf6_assigned_prefix));
      ass_p->prefix = prefix; 
      ass_p->assigning_router_id = OWN_ID;
      ass_p->assigning_router_if_id = i;
      ass_p->is_valid = 1;

      ass_p->interface = oi;

      ass_p->pending_thread = NULL;
      ass_p->deprecation_thread = NULL;

      if (!oi->assigned_prefix_list)
      {
	oi->assigned_prefix_list = list_new ();
      }

      listnode_add (oi->assigned_prefix_list, ass_p); 
    }

    current_tlv = ++ac_tlv_as_p;
  }

  /* Fill LSA Header */
  lsa_header->age = 0;
  lsa_header->type = htons (OSPF6_LSTYPE_AC);
  lsa_header->id = htonl (link_state_id);
  lsa_header->adv_router = id;
  lsa_header->seqnum =
    ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
	lsa_header->adv_router, oa->lsdb);
  lsa_header->length = htons ((caddr_t) current_tlv - (caddr_t) buffer);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* create LSA */
  lsa = ospf6_lsa_create (lsa_header);

  return lsa;
}

static void create_neighbor (struct lsa *lsa)
{
  struct ospf6_interface *oi;
  struct ospf6_neighbor *on;
  
  oi = ospf6_interface_lookup_by_ifindex (lsa->if_index);
  on = ospf6_neighbor_create (lsa->id, oi);
  
  on->ifindex = CONNECTED_IF_ID;
  on->state = OSPF6_NEIGHBOR_FULL;
}

  static void 
handle_lsa (struct lsa *lsa, struct ospf6_area *backbone_area)
{
  struct ospf6_lsa *new_lsa;
  new_lsa = create_ac_lsa (backbone_area, lsa, lsa->id);
  if ((lsa->id != OWN_ID) && (lsa->if_index != NOT_NEIGHBOR))
  {
    create_neighbor (lsa);
  }
  ospf6_lsdb_add (new_lsa, backbone_area->lsdb);
}

  static void 
setup (void)
{
  struct ospf6_area *backbone_area;

  master = malloc ( sizeof (struct thread));

  ospf6 = ospf6_create ();
  backbone_area = ospf6_area_create (0, ospf6);

  ospf6->router_id = 0;

  ospf6_lsa_init ();
  ospf6_intra_init ();

  if_init ();
}

  static void 
reset (void)
{
  struct ospf6_area *backbone_area;
  backbone_area = ospf6_area_lookup (0, ospf6);

  ospf6_lsdb_delete (backbone_area->lsdb);
  backbone_area->lsdb = ospf6_lsdb_create (backbone_area);

  ospf6_lsdb_delete (backbone_area->lsdb_self);
  backbone_area->lsdb_self = ospf6_lsdb_create (backbone_area);

  list_delete (ospf6->aggregated_prefix_list);
  ospf6->aggregated_prefix_list = list_new ();

  list_delete (iflist);
  iflist = list_new ();

  list_delete (backbone_area->if_list);
  backbone_area->if_list = list_new ();
}

  static void 
do_test_case (struct test_case *test_case)
{
  struct ospf6_area *backbone_area;
  int i; 

  reset ();

  backbone_area = ospf6_area_lookup (0, ospf6);

  /* Now add the interface if needed */
  for (i = 0; i < test_case->num_of_interfaces; i++)
  {
    struct interface *ifp;
    struct ospf6_interface *oi;

    ifp = malloc (sizeof (struct interface));
    ifp->ifindex = i;
 
    //TODO: More compact way?
    ifp->name[0] = 'e'; 
    ifp->name[1] = 't';
    ifp->name[2] = 'h';
    ifp->name[3] = 'x';
    ifp->name[4] = '\0';

    oi = ospf6_interface_create (ifp);
  
    oi->area = backbone_area;

    listnode_add(iflist, ifp);
    listnode_add(backbone_area->if_list, oi);
  }

  for (i = 0; i < test_case->num_of_lsas; i++)
  {
    handle_lsa (&test_case->lsa[i], backbone_area);
  }

  /* LSDB has been filled - Run the algorithm */
  ospf6_assign_prefixes ();

  if (ospf6->aggregated_prefix_list == NULL)
  {
    printf ("Testcase %d: \n", test_case->number);

    printf (FAILED "\n");

    fail_count ++;
  }	
  else 
  {
    int assigned_prefix_count;
    struct listnode *node, *nnode; 
    struct ospf6_aggregated_prefix  *agp;

    assigned_prefix_count = 0;	

    printf ("Testcase %d ", test_case->number);
    printf (OK "\n");


    printf("Toal interface count: %d \n", iflist->count);

    for (ALL_LIST_ELEMENTS(ospf6->aggregated_prefix_list, node, nnode, agp))
    {
	char buf[64];
	prefix2str (&agp->prefix, buf, 64);
	printf (" Aggregated Prefix: %s\n", buf);
    }
    
    printf("Total Aggregated Prefix count: %d \n", ospf6->aggregated_prefix_list->count);

    for (i = 0; i < iflist->count; i++)
    {
      struct ospf6_interface *oi;	
      struct ospf6_assigned_prefix  *ap;
      
      oi = ospf6_interface_lookup_by_ifindex (i);

      printf(" eth%d's Assigned Prefix count: %d\n", i, oi->assigned_prefix_list->count); 

      for (ALL_LIST_ELEMENTS (oi->assigned_prefix_list, node, nnode, ap))
      {
	char buf[64];
	prefix2str (&ap->prefix, buf, 64);
	printf ("  Assigned Prefix: %s\n", buf);
	if (ap->pending_thread) printf ("   Pending Thread\n");
	if (!ap->is_valid) printf ("   Not Valid\n");
	if (ap->deprecation_thread) printf ("   Deprecation Thread\n");
      }
      
      assigned_prefix_count += oi->assigned_prefix_list->count;
    }

    printf("Total Assigned Prefix count: %d \n", assigned_prefix_count);

    if (ospf6->ula_generation_thread) printf ("Generating a ULA\n");

    printf("\n");

  }
}


  int 
main (int argc, int **argv)
{
  int i;
  setup();  

  fail_count = 0;

  for (i = 0; i < test_count; i++)
  {
    do_test_case (&test_cases[i]);
  }

  printf ("Total failed: %d \n", fail_count);
  fflush (stdout);

}
