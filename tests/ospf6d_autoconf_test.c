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

struct lsa 
{
	u_int32_t id;

	int num_of_aggregated_prefixes;
	char aggregated_prefix[10][64];

	int num_of_assigned_prefixes;
	char assigned_prefix[10][64];
	int ifindex[10];
};

struct test_case 
{
	int num_of_lsas;
	struct lsa lsa[10]; /* XXX */
};

struct test_case test_cases[] = 
{
	{/* Test Case 0 */
		1, 
		{
			{0, 0, {}, 0, {}, {}}
		}
	}, 
	{/* Test Case 1 */
		1,
		{
			{1, 1, {"fc00::/48"}, 0, {}, {}}
		}
	},
	{/* Test Case 2*/
		1,
		{
			{1, 2, {"fc00::/48", "fc01::/48"}, 0, {}, {}}
		}
	},
	{/* Test Case 3 */
		1,
		{
			{1, 2, {"fc00::/48"}, 1, {"fc00::1/64"}, {0}}
		}
	},
	 
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
	ac_tlv_rhwfp->header.type = OSPF6_AC_TLV_ROUTER_HARDWARE_FINGERPRINT;
	ac_tlv_rhwfp->header.length = OSPF6_AC_TLV_RHWFP_LENGTH;
	ac_tlv_rhwfp->value = id; /*XXX*/

	/* Step onto next tlv? */
	current_tlv = ++ac_tlv_rhwfp;

	/* Aggregated (allocated) prefixes */
	for (i = 0; i < test_lsa->num_of_aggregated_prefixes; i++) 
	{
		struct prefix prefix; 
		str2prefix (test_lsa->aggregated_prefix[i], &prefix);

		ac_tlv_ag_p = (struct ospf6_ac_tlv_aggregated_prefix *) current_tlv;
		ac_tlv_ag_p->header.type = OSPF6_AC_TLV_AGGREGATED_PREFIX;
		ac_tlv_ag_p->header.length = OSPF6_AC_TLV_AGGREGATED_PREFIX_LENGTH;

		/* Send prefix */ 
		ac_tlv_ag_p->prefix_length = prefix.prefixlen;
		ac_tlv_ag_p->prefix = prefix.u.prefix6;

		current_tlv = ++ac_tlv_ag_p;
	}

	/* Assigned prefixes */

	for (i = 0; i < test_lsa->num_of_assigned_prefixes; i++) 
	{
		struct prefix prefix; 
		str2prefix (test_lsa->aggregated_prefix[i], &prefix);

		ac_tlv_as_p = (struct ospf6_ac_tlv_assigned_prefix *) current_tlv;
		ac_tlv_as_p->header.type = OSPF6_AC_TLV_ASSIGNED_PREFIX;
		ac_tlv_as_p->header.length = OSPF6_AC_TLV_ASSIGNED_PREFIX_LENGTH;

		/* Send prefix */ 
		ac_tlv_as_p->prefix_length = prefix.prefixlen;
		ac_tlv_as_p->prefix = prefix.u.prefix6;
	
		ac_tlv_as_p->interface_id = test_lsa->ifindex[i];
		/*TODO: Now add the interface if needed */
		if (!ospf6_interface_lookup_by_ifindex (test_lsa->ifindex[i]))
		{
		  struct interface *ifp;
		  struct ospf6_interface *oi;

		  ifp = malloc (sizeof (struct interface));
		  ifp->ifindex = test_lsa->ifindex[i];

		  oi = ospf6_interface_create (ifp);

		  listnode_add(oa->if_list, oi);
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

static void 
handle_lsa (struct lsa *lsa, struct ospf6_area *backbone_area)
{
	lsa = create_ac_lsa (backbone_area, lsa, 0);
	ospf6_lsdb_add (lsa, backbone_area->lsdb);
}

static void 
do_test_case (struct test_case *test_case)
{
	struct ospf6_area *backbone_area;
	int i; 

	backbone_area = ospf6_area_lookup (0, ospf6);

	for (i = 0; i < test_case->num_of_lsas; i++)
	{
		handle_lsa (&test_case->lsa[i], backbone_area);
	}

	/* LSDB has been filled - Run the algorithm */
	ospf6_assign_prefixes ();

	if (ospf6->aggregated_prefix_list == NULL)
	{
		printf (FAILED "\n");
	}	
	else 
	{
		printf("%d", backbone_area->if_list->count);
		printf (OK "\n");
	}

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
}

int 
main (int argc, int **argv)
{
	setup();  

	do_test_case (&test_cases[3]);
}
