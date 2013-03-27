/*TODO: Remove (or change to debug) zlog_warns */
#include <zebra.h>

#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "prefix.h"
#include "command.h"
#include "if.h"

#include "ospf6_top.h"
#include "ospf6_interface.h"
#include "ospf6_message.h"
#include "ospf6_area.h"
#include "ospf6_neighbor.h"

#include "ospf6_intra.h"
#include "ospf6_lsdb.h"
#include "ospf6_lsa.h"
#include "ospf6d.h"

#include "ospf6_auto.h"

/* Proto */
static void create_if (char * name);

/* Convert a transmission order MAC address to storage order */
static u_int64_t
hw_addr_to_long (u_char *hw_addr, int hw_addr_len)
{
  u_int64_t total = 0;
  int i;

  for (i = hw_addr_len - 1; i >= 0; i--)
  {
    total *= 256;
    total += hw_addr[i];
  }

  return total;
}

/* Can be replaced with a more sophisticated hash if needed */
static u_int32_t
hash_hw_addr (u_int64_t hw_addr)
{
  return hw_addr % UINT32_MAX;
}

/* Generate a Router Hardware Fingerprint for zOSPF */
u_int32_t
ospf6_router_hardware_fingerprint ()
{
  struct listnode *node;
  int i;
  u_int32_t fingerprint = 0;

  node = iflist->head;

  for (i = 0; i < iflist->count; i++) 
  {
    struct interface *current_interface = listgetdata(node);
#ifdef HAVE_STRUCT_SOCKADDR_DL
    /* TODO Add support for STRUCT_SOCKADDR_DL */
    /*fingerprint = fingerprint + LLADDR(current_interface->sdl);*/
    fingerprint = 1;
#else
    if (if_is_up (current_interface) && !if_is_loopback(current_interface))
    {
      fingerprint += hash_hw_addr (hw_addr_to_long (current_interface->hw_addr,
	    current_interface->hw_addr_len));
    }
#endif /* HAVE_STRUCT_SOCKADDR_DL */
    node = listnextnode(node);
  }

  zlog_warn("Fingerprint: %lu", fingerprint);

  return fingerprint;
}

/* Initialises the rid seed to the router-hardware fingerprint */
void 
ospf6_init_seed ()
{
  ospf6->rid_seed = ospf6_router_hardware_fingerprint ();
}

/* Generates a _new_ router id */
u_int32_t
ospf6_generate_router_id ()
{
  /* rand_r returns and positive int, we would prefer an unsigned int */
  return rand_r(&ospf6->rid_seed);
}

/* Shuts down router and restarts it with new router-id */
void 
ospf6_set_router_id (u_int32_t rid)
{
  u_int32_t old_seed = 0;

  /* Remove all timers */
  struct thread *t = master->timer.head;
  for(int i = 0; i < master->timer.count; i++)
  {
    struct thread *next; 
    next = t->next;
    thread_cancel(t);
    t = next;
  }

  if (ospf6 != NULL) 
  {
    old_seed = ospf6->rid_seed;
    ospf6_delete (ospf6);
  }

  /* Reconfigure */
  if (!auto_conf) 
  {	
    vty_read_config (NULL, "/usr/local/quagga/ospf6d.conf");
  }
  else 
  {
    ospf6 = ospf6_create ();
    ospf6_enable (ospf6);

    struct listnode *node;
    int i;

    node = iflist->head;

    /* TODO: I think this currently depends on the config file to put the interfaces up..? */
    for (i = 0; i < iflist->count; i++) 
    {
      struct interface *current_interface = listgetdata(node);
      if (if_is_up (current_interface) && !if_is_loopback(current_interface))
      {
	create_if (current_interface->name);
      }
      node = listnextnode(node);
    }
  }

  ospf6->router_id = rid; 
  ospf6->router_id_static = rid;
  ospf6->rid_seed = old_seed;
}

/* A copy of ospf_interface_area_cmd */
static void 
create_if (char * name)
{
  struct ospf6 *o;
  struct ospf6_area *oa;
  struct ospf6_interface *oi;
  struct interface *ifp;
  u_int32_t area_id;

  o = ospf6;

  /* find/create ospf6 interface */
  ifp = if_get_by_name (name);
  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);

  area_id = 0; 

  /* find/create ospf6 area */
  oa = ospf6_area_lookup (area_id, o);
  if (oa == NULL)
    oa = ospf6_area_create (area_id, o);

  /* attach interface to area */
  listnode_add (oa->if_list, oi); /* sort ?? */
  oi->area = oa;

  SET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

  /* start up */
  thread_add_event (master, interface_up, oi, 0);

  /* If the router is ABR, originate summary routes */
  if (ospf6_is_router_abr (o))
    ospf6_abr_enable_area (oa);

  /* Read in previous assignments from non volatile storage */
  ospf6_read_associated_prefixes_from_file (oi);
}

/* Ensure router id is not a duplicate */
void 
ospf6_check_router_id (struct ospf6_header *oh, struct in6_addr src, struct in6_addr dst)
{
  if (oh->router_id == ospf6->router_id) 
  {
    struct listnode *node, *nnode;
    struct ospf6_area *area; 

    /* Self originated */
    if (IPV6_ADDR_SAME (&src, &dst))
      return;

    /* Check all IP Addresses associated with this router*/
    for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, area))
    {
      struct listnode *ifnode, *ifnnode;
      struct ospf6_interface *inf;
      for (ALL_LIST_ELEMENTS (area->if_list, ifnode, ifnnode, inf))
      {
	/* Multiple interfaces on same link? */
	/* Draft doesn't specify _HOW_ this should be done */
	if(IPV6_ADDR_SAME (&src, inf->linklocal_addr)){
	  return;
	}
      }
    }
    
    /* If link local address was smaller */
    if (IPV6_ADDR_CMP (&dst, &src) < 0)
    {
      zlog_warn ("Changing router-id");
      ospf6_set_router_id (ospf6_generate_router_id ());
    }
  }
}

/* Ensure a self originated lsa is from self */
int 
ospf6_check_hw_fingerprint (struct ospf6_lsa_header *lsa_header) 
{
  char *start, *end, *current;

  /* Check it is an AC LSA */
  if (lsa_header->type != ntohs(OSPF6_LSTYPE_AC)) return 0;
  

  /* Check it has an LS-ID of 0 */
  if (lsa_header->id != 0) return 0;

  /* First TLV */
  start = (char *) lsa_header 
    + sizeof (struct ospf6_lsa_header) 
    + sizeof (struct ospf6_ac_lsa);

  /* End of LSA */
  end = (char *) lsa_header + ntohs (lsa_header->length);

  current = start;

  while (current < end)
  {
    struct ospf6_ac_tlv_header *ac_tlv_header = (struct ospf6_ac_tlv_header *) current;
    if (ac_tlv_header->type == OSPF6_AC_TLV_ROUTER_HARDWARE_FINGERPRINT) 
    {
      u_int32_t fingerprint = ospf6_router_hardware_fingerprint ();
      struct ospf6_ac_tlv_router_hardware_fingerprint *ac_tlv_rhfp =
	(struct ospf6_ac_tlv_router_hardware_fingerprint *) ac_tlv_header;

      /* Check fingerprints, check length first since its variable */
      if (ac_tlv_header->length == 4 
	  && ac_tlv_rhfp->value == fingerprint)
      {
	/* Matching fingerprints implies true self origination*/
	return 0;
      }
      else 
      {
	if (ac_tlv_header->length != 4) 
	{
	  zlog_warn ("Different sized fingerprint - must be a conflict");
	}	

	/* There is a conflict */
	zlog_warn ("Conflict");

	/* If their fingerprint is smaller */
	if (R_HW_FP_CMP (&ac_tlv_rhfp->value, &fingerprint) < 0)
	{
	  zlog_warn ("Not our problem (fingerprint)");
	  return 0;
	}

	zlog_warn("Changing router-id");
	ospf6_set_router_id (ospf6_generate_router_id ());

	return 1;
      }
    }
    /* Step */
    current = (char *) ac_tlv_header 
      + sizeof (ac_tlv_header) 
      + ntohs (ac_tlv_header->length);
  }

  /* There must have been a problem */
  zlog_warn ("No rhwfp tlv found");
  return 1;
}

/* Begin originating an updated ac_lsa */
static void originate_new_ac_lsa (void) 
{
  struct listnode *node, *nextnode;
  struct ospf6_area *area;
  
  /* Originate new AC_LSA */
  for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nextnode, area))
  {
    OSPF6_AC_LSA_SCHEDULE(area);  
  }
}

/* Allocate a prefix */
DEFUN (ipv6_allocate_prefix,
       ipv6_allocate_prefix_cmd,
       "ipv6 allocate-prefix X:X::X:X/M",
       OSPF6_STR)
{
  struct prefix_ipv6 prefix;
  struct ospf6_aggregated_prefix *ap; 

  str2prefix_ipv6 (argv[0], &prefix);

  ap = malloc (sizeof (struct ospf6_aggregated_prefix));

  ap->prefix = prefix;
  ap->source = OSPF6_PREFIX_SOURCE_CONFIGURED; 
  ap->advertising_router_id = ospf6->router_id;

  listnode_add (ospf6->aggregated_prefix_list, ap); 

  zlog_warn (argv[0]);

  originate_new_ac_lsa ();

  return CMD_SUCCESS;
}

/* Remove an allocated prefix */
DEFUN (no_ipv6_allocate_prefix,
       no_ipv6_allocate_prefix_cmd,
       "no ipv6 allocate-prefix X:X::X:X/M",
       OSPF6_STR)
{
  struct listnode *node, *nextnode;
  struct ospf6_aggregated_prefix *aggregated_prefix;
  struct prefix_ipv6 prefix;

  str2prefix_ipv6 (argv[0], &prefix);

  for (ALL_LIST_ELEMENTS (ospf6->aggregated_prefix_list, node, nextnode, aggregated_prefix)) 
  {
    if (IPV6_ADDR_SAME (&aggregated_prefix->prefix.prefix, &prefix.prefix))
    {
      listnode_delete (ospf6->aggregated_prefix_list, aggregated_prefix);
    }
  }

  zlog_warn (argv[0]);

  originate_new_ac_lsa ();

  return CMD_SUCCESS;
}

static const char * 
source_string (int source)
{
  switch (source) 
  {
    case OSPF6_PREFIX_SOURCE_DHCP6_PD: 
      return OSPF6_PREFIX_SOURCE_DHCP6_PD_STRING;
    case OSPF6_PREFIX_SOURCE_CONFIGURED:
      return OSPF6_PREFIX_SOURCE_CONFIGURED_STRING;
    case OSPF6_PREFIX_SOURCE_GENERATED:
      return OSPF6_PREFIX_SOURCE_GENERATED_STRING;
    case OSPF6_PREFIX_SOURCE_OSPF:
      return OSPF6_PREFIX_SOURCE_OSPF_STRING;
  }
}

/* List all prefixes allocated to this router */
DEFUN (show_ipv6_allocated_prefix, 
       show_ipv6_allocated_prefix_cmd, 
       "show ipv6 ospf6 prefixes allocated",
       OSPF6_STR)
{
  struct listnode *node, *nextnode;
  struct ospf6_aggregated_prefix *aggregated_prefix;

  vty_out (vty, "%s      Prefixes Allocated To This Router %s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS (ospf6->aggregated_prefix_list, node, nextnode, aggregated_prefix)) 
  {
    if (aggregated_prefix->source != OSPF6_PREFIX_SOURCE_OSPF)
    {
      char prefix_str[64];
      
      prefix2str (&aggregated_prefix->prefix, &prefix_str, 64);

      vty_out (vty, "Prefix: %s%s", prefix_str, VTY_NEWLINE); 
      vty_out (vty, "Source : %s%s%s", source_string (aggregated_prefix->source), VTY_NEWLINE, VTY_NEWLINE); 
    }
  }
}

/* List all known aggregated prefixes across all AS routers */
DEFUN (show_ipv6_aggregated_prefix, 
       show_ipv6_aggregated_prefix_cmd, 
       "show ipv6 ospf6 prefixes aggregated",
       OSPF6_STR)
{
  struct listnode *node, *nextnode;
  struct ospf6_aggregated_prefix *aggregated_prefix;

  vty_out (vty, "%s      All Known Aggregated Prefixes %s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (ospf6->aggregated_prefix_list, node, nextnode, aggregated_prefix)) 
  {
    char prefix_str[64], router_id_str[16];

    inet_ntop (AF_INET, &aggregated_prefix->advertising_router_id, router_id_str, sizeof (router_id_str));
    prefix2str (&aggregated_prefix->prefix, &prefix_str, 64);
   
    vty_out (vty, "Prefix: %s%s", prefix_str, VTY_NEWLINE); 
    vty_out (vty, "Source : %s%s", source_string (aggregated_prefix->source), VTY_NEWLINE); 
    vty_out (vty, "Advertising Router-ID: %s%s%s", router_id_str, VTY_NEWLINE, VTY_NEWLINE);
  }
}

/* Show all prefixes assigned to a given interface */
DEFUN (show_ipv6_assigned_prefix, 
       show_ipv6_assigned_prefix_cmd, 
       "show ipv6 ospf6 prefixes assigned IFNAME",
       OSPF6_STR)
{
  struct listnode *node, *nextnode;
  struct ospf6_assigned_prefix *assigned_prefix;

  char *ifname;
  struct interface *ifp;
  struct ospf6_interface *interface;  

  ifname = argv[0];
  ifp = if_lookup_by_name (ifname);
  
  if (ifp== NULL){
    vty_out (vty, "No interface %s%s", ifname, VTY_NEWLINE);
    return; 
  }

  interface = ospf6_interface_lookup_by_ifindex(ifp->ifindex);

  vty_out (vty, "%s      Assigned Prefixes For %s %s%s", VTY_NEWLINE, ifname, VTY_NEWLINE, VTY_NEWLINE);
  
  for (ALL_LIST_ELEMENTS (interface->assigned_prefix_list, node, nextnode, assigned_prefix)) 
  {
    char prefix_str[64], router_id_str[16];

    inet_ntop (AF_INET, &assigned_prefix->assigning_router_id, router_id_str, sizeof (router_id_str));
    prefix2str (&assigned_prefix->prefix, &prefix_str, 64);
   
    vty_out (vty, "Prefix: %s%s", prefix_str, VTY_NEWLINE); 
    vty_out (vty, "Assigning Router-ID: %s%s%s", router_id_str, VTY_NEWLINE, VTY_NEWLINE);
  }
}

/* XXX: Move to prefix? */
static u_int8_t 
prefix_contains (struct prefix *container, struct prefix *containee)
{
  int i;
  if (container->prefixlen > containee->prefixlen)
    return 0;
  
  if(container->family != containee->family)
    return 0;

  for (i = 0; i < container->prefixlen; i++) 
  {
    if (prefix_bit (&container->u, i) 
     != prefix_bit (&containee->u, i))
    {
      return 0;
    }
  }

  return 1;
}

static void
mark_prefix_invalid (struct ospf6_assigned_prefix *ap)
{
  ap->is_valid = 0;
}

static void 
mark_prefix_valid (struct ospf6_assigned_prefix *ap)
{
  ap->is_valid = 1;
}

static void 
mark_interface_prefixes_invalid (struct ospf6_interface *oi)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *ap;

  for (ALL_LIST_ELEMENTS (oi->assigned_prefix_list, node, nnode, ap))
  {
       mark_prefix_invalid (ap);
  }
}

static void 
mark_area_prefixes_invalid (struct ospf6_area *oa)
{
  struct listnode *node, *nnode;
  struct ospf6_interface *ifp;

  for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, ifp)) 
  {
    mark_interface_prefixes_invalid (ifp);
  }
}

static int
lookup_aggregated_prefix_source (struct ospf6_aggregated_prefix *ag_prefix)
{
  struct listnode *node, *nnode;
  struct ospf6_aggregated_prefix *current_ag_prefix;

  for (ALL_LIST_ELEMENTS (ospf6->aggregated_prefix_list, 
			  node, nnode, current_ag_prefix))
  {
    if (prefix_same (&current_ag_prefix->prefix, &ag_prefix->prefix))
    {
      return current_ag_prefix->source;
    }
  }

  return OSPF6_PREFIX_SOURCE_OSPF;
}

static struct ospf6_aggregated_prefix * 
handle_aggregated_prefix_tlv (char *current, struct ospf6_lsa *current_lsa)
{
  struct ospf6_ac_tlv_aggregated_prefix *ac_tlv_ag_p 
    = (struct ospf6_ac_tlv_aggregated_prefix *) current;
  struct ospf6_aggregated_prefix *ag_prefix;

  ag_prefix = malloc (sizeof (struct ospf6_aggregated_prefix));

  ag_prefix->prefix.family = AF_INET6;
  ag_prefix->prefix.prefixlen = ac_tlv_ag_p->prefix_length;
  ag_prefix->prefix.prefix = ac_tlv_ag_p->prefix;

  if (current_lsa->header->adv_router != ospf6->router_id) 
  {
    ag_prefix->source = OSPF6_PREFIX_SOURCE_OSPF;
  }
  else
  {
    ag_prefix->source = lookup_aggregated_prefix_source (ag_prefix);
  }

  ag_prefix->advertising_router_id = current_lsa->header->adv_router;

  return ag_prefix;
}

static struct ospf6_assigned_prefix * 
handle_assigned_prefix_tlv (char *current, struct ospf6_lsa *current_lsa)
{
  struct ospf6_ac_tlv_assigned_prefix *ac_tlv_as_p 
    = (struct ospf6_ac_tlv_assigned_prefix *) current;
  struct ospf6_assigned_prefix *as_prefix;

  as_prefix = malloc (sizeof (struct ospf6_assigned_prefix));

  as_prefix->prefix.family = AF_INET6;
  as_prefix->prefix.prefixlen = ac_tlv_as_p->prefix_length;
  as_prefix->prefix.prefix = ac_tlv_as_p->prefix;

  as_prefix->assigning_router_id = current_lsa->header->adv_router;
  as_prefix->assigning_router_if_id = ac_tlv_as_p->interface_id;

  as_prefix->deprecation_thread = NULL;

  return as_prefix;
}

static void
create_ac_lsdb_snapshot (struct ospf6_lsdb *lsdb, struct list **assigned_prefix_list, struct list **aggregated_prefix_list)
{
  struct ospf6_lsa *current_lsa;
 
  *assigned_prefix_list = list_new ();
  *aggregated_prefix_list = list_new ();

  current_lsa = ospf6_lsdb_type_head (htons (OSPF6_LSTYPE_AC), lsdb);

  while (current_lsa != NULL) 
  {
    struct ospf6_ac_lsa * ac_lsa;
    char *start, *end, *current;
    
    if (!current_lsa->reachable) 
    {
      current_lsa = ospf6_lsdb_type_next (htons (OSPF6_LSTYPE_AC), current_lsa);
      continue;
    }

    /* Process LSA */
    ac_lsa = (struct ospf6_ac_lsa *)
        ((char *) current_lsa->header + sizeof (struct ospf6_lsa_header));

    /* Start and end of all TLVs */
    start = (char *) ac_lsa + sizeof (struct ospf6_ac_lsa);
    end = (char *) current_lsa->header + ntohs (current_lsa->header->length);
    current = start;

    while (current < end)
    {
        struct ospf6_ac_tlv_header *ac_tlv_header = (struct ospf6_ac_tlv_header *) current;

	if (ac_tlv_header->type == OSPF6_AC_TLV_AGGREGATED_PREFIX)
	{
	    struct ospf6_aggregated_prefix *ag_prefix;
	    ag_prefix = handle_aggregated_prefix_tlv (current, current_lsa);
	    listnode_add (*aggregated_prefix_list, ag_prefix);
	} 
	else if (ac_tlv_header->type == OSPF6_AC_TLV_ASSIGNED_PREFIX)
	{
	    struct ospf6_assigned_prefix *as_prefix;
	    as_prefix = handle_assigned_prefix_tlv(current, current_lsa);
	    listnode_add (*assigned_prefix_list, as_prefix);
	} 
	current += sizeof (struct ospf6_ac_tlv_header) + ac_tlv_header->length;
    }    
    
    current_lsa = ospf6_lsdb_type_next (htons (OSPF6_LSTYPE_AC), current_lsa);
  }
}

static struct list *
generate_active_neighbor_list (struct list * neighbor_list)
{
  struct list *active_neigbor_list;
  struct listnode *node, *nnode; 
  struct ospf6_neighbor *neighbor;

  active_neigbor_list = list_new ();
    
  for (ALL_LIST_ELEMENTS (neighbor_list, node, nnode, neighbor))
  {
    if (neighbor->state > OSPF6_NEIGHBOR_INIT)
    {
      listnode_add (active_neigbor_list, neighbor);
    }
  }
  return active_neigbor_list;
}

static u_int8_t 
is_highest_rid (u_int32_t router_id, struct list *neighbor_list) 
{
  struct listnode *node, *nextnode;
  struct ospf6_neighbor *neighbor;

  for (ALL_LIST_ELEMENTS (neighbor_list, node, nextnode, neighbor))
  {
    if (neighbor->router_id > router_id) return 0;
  }
  return 1;
}

static struct ospf6_assigned_prefix *
find_neighbors_prefix_assignment (struct ospf6_aggregated_prefix *agp, 
			   struct ospf6_neighbor *neighbor, 
			   struct list *assigned_prefix_list)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *ap;

  for (ALL_LIST_ELEMENTS (assigned_prefix_list, node, nnode, ap))
  {
    if((ap->assigning_router_id == neighbor->router_id) 
	&& (ap->assigning_router_if_id == neighbor->ifindex))
    {
      if (prefix_contains (&agp->prefix, &ap->prefix)) return ap;
    }
  }
  return NULL;
}

static struct ospf6_assigned_prefix *
find_own_prefix_assignment (struct ospf6_aggregated_prefix *agp, 
		     struct ospf6_interface *ifp, struct list *aspl)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *ap;

  for (ALL_LIST_ELEMENTS (aspl, node, nnode, ap))
  {
    if((ap->assigning_router_id == ospf6->router_id) 
	&& (ap->assigning_router_if_id == ifp->interface->ifindex))
    {
	if (prefix_contains (&agp->prefix, &ap->prefix)) return ap;
    }
  }
  return NULL;
}


static struct ospf6_assigned_prefix *
find_highest_prefix_assignment (struct ospf6_aggregated_prefix *ag_prefix, 
			 struct list *neighbor_list, 
			 struct list *assigned_prefix_list)
{
  struct listnode *node, *nnode;
  struct ospf6_neighbor *neighbor;
  struct ospf6_assigned_prefix *highest_ap;
  
  highest_ap = NULL;

  for (ALL_LIST_ELEMENTS (neighbor_list, node, nnode, neighbor))
  {
    struct ospf6_assigned_prefix *current_ap;
    current_ap = find_neighbors_prefix_assignment (ag_prefix, neighbor, 
						   assigned_prefix_list);
    if (current_ap != NULL)
    {
      if (prefix_contains (&ag_prefix->prefix, &current_ap->prefix)) 
      {
	if ( (highest_ap == NULL)
	|| (current_ap->assigning_router_id > highest_ap->assigning_router_id))
	{ 
	  highest_ap = current_ap;
	}
      }
    }
  }

  return highest_ap;
}

static u_int8_t
is_prefix_valid_network_wide (struct ospf6_assigned_prefix *current_assigned_prefix, 
			      struct list *aspl)
{
  struct listnode *node, *nextnode;
  struct ospf6_assigned_prefix *prefix;

  for (ALL_LIST_ELEMENTS (aspl, node, nextnode, prefix))
  {
    if (prefix_same (&prefix->prefix, &current_assigned_prefix->prefix))
    {
      if (prefix->assigning_router_id > 
	  current_assigned_prefix->assigning_router_id)
      {
	return 0;
      }
    }
  }

  return 1;
}

static u_int8_t 
is_prefix_valid_locally (struct ospf6_assigned_prefix *current_assigned_prefix, 
			 struct ospf6_area *oa)
{
  struct listnode *node, *nnode;
  struct ospf6_interface *ifp;

  for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, ifp))
  {
    struct listnode *inner_node, *inner_nnode;
    struct ospf6_assigned_prefix *ap;
    
    for (ALL_LIST_ELEMENTS (ifp->assigned_prefix_list, 
			    inner_node, inner_nnode, ap))
    {
      if (prefix_same (&ap->prefix, &current_assigned_prefix->prefix))
      {
	if (ap->assigning_router_id > 
	    current_assigned_prefix->assigning_router_id)
	{
	  return 0;
	}
      }
    }
  }
  return 1;
}

static struct list *
create_in_use_list (struct ospf6_aggregated_prefix *agp, struct list *aspl)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *ap;
  struct list *in_use_list;
  
  in_use_list = list_new ();

  for (ALL_LIST_ELEMENTS (aspl, node, nnode, ap))
  {
    if (prefix_contains (&agp->prefix, &ap->prefix)) listnode_add (in_use_list, ap);
  }
  return in_use_list;
}

static void 
increment_prefix (struct prefix *prefix)
{
  /* Convert to a little endian number and increment */
  u_int64_t numeric_prefix;

  memcpy (&numeric_prefix, &prefix->u.prefix6, 8);

  numeric_prefix = be64toh (numeric_prefix);
  numeric_prefix++;
  numeric_prefix = htobe64 (numeric_prefix);

  memcpy (&prefix->u.prefix6, &numeric_prefix, 8);
}

static struct prefix* 
choose_first_unassigned_prefix (struct ospf6_aggregated_prefix *agp, 
				struct list *in_use_prefixes)
{
  struct prefix *new_prefix; 
  struct listnode *node, *nnode; 
  struct prefix *prefix;
  u_int8_t collides; 
  
  new_prefix = prefix_new ();
  prefix_copy (new_prefix, &agp->prefix);
  apply_mask (new_prefix);
  new_prefix->prefixlen = 64;

  while (prefix_contains (&agp->prefix, new_prefix)) 
  {
    collides = 0;

    for (ALL_LIST_ELEMENTS (in_use_prefixes, node, nnode, prefix))
    {
      if (prefix_same (new_prefix, prefix))
      {
	  collides = 1; 
	  break;
      }
    }
    
    if (collides == 0) return new_prefix; 
    
    increment_prefix (new_prefix);
  }

  /* Address space exhaustion!! */
  prefix_free (new_prefix);
  return NULL;
}

void 
ospf6_write_associated_prefixes_to_file (struct ospf6_interface *ifp)
{
  struct listnode *node, *nnode;
  struct prefix *prefix;
  FILE *file_pointer;
  char filepath[100];
  
  snprintf (filepath, sizeof (filepath), "%s%s%s", SYSCONFDIR, ifp->interface->name, "_prefixes");

  file_pointer = fopen (filepath, "w");

  if (file_pointer != NULL) 
  {
    for (ALL_LIST_ELEMENTS (ifp->associated_prefixes, node, nnode, prefix))
    {
      char buf[64];
      prefix2str (prefix, buf, 64);
      fprintf (file_pointer, "%s\n", buf);
    }
    fclose (file_pointer);
  }
}

void 
ospf6_read_associated_prefixes_from_file (struct ospf6_interface *ifp)
{
  FILE *file_pointer;
  char filepath[100], linebuf[100];

  list_delete (ifp->associated_prefixes);
  ifp->associated_prefixes = list_new ();

  snprintf (filepath, sizeof (filepath), "%s%s%s", SYSCONFDIR, ifp->interface->name, "_prefixes");

  file_pointer = fopen (filepath, "r");

  if (file_pointer != NULL)
  {
    while (fgets (&linebuf, 50, file_pointer) != NULL)
    {
      struct prefix *prefix;
      size_t ln = strlen(linebuf) - 1;
      if (linebuf[ln] == '\n') linebuf[ln] = '\0';

      prefix = prefix_new ();
      str2prefix (linebuf, prefix);

      listnode_add (ifp->associated_prefixes, prefix);
    }
    fclose (file_pointer);
  }
}

static void 
schedule_writing (struct ospf6_assigned_prefix *assigned_prefix,
		  struct ospf6_interface *ifp)
{
  if (assigned_prefix->assigning_router_id == ospf6->router_id)
    {
      /* Write AQ to file */
      /* Cancel any timers to write */
      THREAD_OFF(ifp->associated_prefixes_writer);
      ifp->associated_prefixes_writer = 
	thread_add_timer (master, ospf6_associated_prefix_writer, 
			  ifp, 5);
    }
    else 
    {
    /* Schedule writing to file in 10 mins
     * (Don't touch existing timer) */
      if (ifp->associated_prefixes_writer == NULL)
      {
	ifp->associated_prefixes_writer = 
	  thread_add_timer (master, ospf6_associated_prefix_writer, 
			    ifp, 60 * 10);
      }
    }
}

static void 
remove_from_associated_prefixes (struct ospf6_assigned_prefix *assigned_prefix, 
				   struct ospf6_interface *ifp)
{
  /* Remove from queue */
  struct listnode *node, *nnode;
  struct prefix *prefix;

  for (ALL_LIST_ELEMENTS (ifp->associated_prefixes, node, nnode, prefix))
  {
    if (prefix_same (prefix, &assigned_prefix->prefix))
    {
      listnode_delete (ifp->associated_prefixes, prefix);
    }
  }

  schedule_writing (assigned_prefix, ifp);
}

static void 
add_to_associated_prefixes (struct ospf6_assigned_prefix *assigned_prefix, 
			      struct ospf6_interface *ifp)
{
  /* First Remove it! */
  remove_from_associated_prefixes (assigned_prefix, ifp);
  
  /* Add to queue */
  /* XXX: Might need to make a copy */
  if(list_isempty (ifp->associated_prefixes))
  {
    listnode_add (ifp->associated_prefixes, &assigned_prefix->prefix);
  }
  else 
  {
    list_add_node_prev (ifp->associated_prefixes, 
		      listhead(ifp->associated_prefixes), 
		      &assigned_prefix->prefix);
  }

  if (ifp->associated_prefixes->count > ASSOCIATED_PREFIXES_MAX_LEN){
    listnode_delete (ifp->associated_prefixes, listtail (ifp->associated_prefixes));
  }

  schedule_writing (assigned_prefix, ifp);
}

static struct ospf6_interface *
find_ifp_for_pending_prefix_on_interface (struct ospf6_interface *oi,
              struct ospf6_assigned_prefix *assigned_prefix)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *ap;

  for (ALL_LIST_ELEMENTS (oi->pending_prefix_list, node, nnode, ap))
  {
    if (prefix_same (&ap->prefix, &assigned_prefix->prefix))
    {
      return oi;
    }
  }
  return NULL;
}

static struct ospf6_interface *
find_ifp_for_pending_prefix_in_area (struct ospf6_area *oa,
    struct ospf6_assigned_prefix *assigned_prefix)
{
  struct listnode *node, *nnode;
  struct ospf6_interface *ifp;

  for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, ifp))
  {
    struct ospf6_interface *found_ifp;
    found_ifp = find_ifp_for_pending_prefix_on_interface (ifp, assigned_prefix);
    if (found_ifp) return found_ifp;
  }
  return NULL;
}

static struct ospf6_interface * 
find_ifp_for_pending_prefix (struct ospf6_assigned_prefix *assigned_prefix)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;

  for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
  {
    struct ospf6_interface *found_ifp;
    found_ifp = find_ifp_for_pending_prefix_in_area (oa, assigned_prefix);
    if (found_ifp) return found_ifp;
  }
  return NULL;
}

static void
use_pending_assignment_thread (struct thread *thread)
{
  struct ospf6_assigned_prefix *assigned_prefix;
  struct ospf6_interface *ifp;

  assigned_prefix = (struct ospf6_assigned_prefix *) THREAD_ARG (thread);

  ifp = find_ifp_for_pending_prefix (assigned_prefix);

  listnode_add (ifp->assigned_prefix_list, assigned_prefix);
  listnode_delete (ifp->pending_prefix_list, assigned_prefix);

  originate_new_ac_lsa ();
}

static struct ospf6_assigned_prefix * 
check_pending_assignments (struct ospf6_aggregated_prefix *agp,
			   struct ospf6_interface *ifp)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *assigned_prefix;

  for (ALL_LIST_ELEMENTS (ifp->pending_prefix_list, node, nnode, assigned_prefix))
  { 
    if (prefix_contains (&agp->prefix, &assigned_prefix->prefix)) return assigned_prefix;
  }
  return NULL;
}

static struct ospf6_assigned_prefix *
find_pending_assignment (struct ospf6_assigned_prefix *asp,
			 struct ospf6_interface *ifp)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *assigned_prefix;

  for (ALL_LIST_ELEMENTS (ifp->pending_prefix_list, node, nnode, assigned_prefix))
  { 
    if (prefix_same (&asp->prefix, &assigned_prefix->prefix)) return assigned_prefix;
  }
  return NULL;
}

static void
schedule_using_assigned_prefix (struct ospf6_assigned_prefix *assigned_prefix,
				struct ospf6_interface *ifp)
{
  add_to_associated_prefixes (assigned_prefix, ifp);
  listnode_add (ifp->pending_prefix_list, assigned_prefix);  

  assigned_prefix->pending_thread =
    thread_add_timer (master,
                      use_pending_assignment_thread,
                      assigned_prefix,
                      OSPF6_NEW_PREFIX_ASSIGNMENT_SECONDS);

}

static void 
start_using_prefix (struct ospf6_assigned_prefix *assigned_prefix, 
		    struct ospf6_interface *ifp, struct list *aspl)
{
  struct ospf6_assigned_prefix *pending_prefix;
  mark_prefix_valid (assigned_prefix);

  listnode_add (aspl, assigned_prefix);

  if (assigned_prefix->assigning_router_id == ospf6->router_id)
  {
    schedule_using_assigned_prefix (assigned_prefix, ifp);  
  }
  else 
  {
    listnode_add (ifp->assigned_prefix_list, assigned_prefix);	
    pending_prefix = find_pending_assignment (assigned_prefix, ifp);
  }
}

static u_int8_t
continue_using_prefix (struct ospf6_assigned_prefix *assigned_prefix, 
		       struct ospf6_interface *ifp, struct list *aspl)
{
  /* Keep using prefix (Mark it as valid) */
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *prefix; 
  u_int8_t success; 
    
  success = 0;

  for (ALL_LIST_ELEMENTS (ifp->assigned_prefix_list, node, nnode, prefix))
  {
    if (prefix_same (&prefix->prefix, &assigned_prefix->prefix)) {
      mark_prefix_valid (prefix);
      success = 1;
    }
  }

  return success;
}

static void 
stop_using_prefix (struct ospf6_assigned_prefix *assigned_prefix,
		   struct ospf6_interface *ifp, struct list *aspl)
{
  /* AKA Deprecate prefix */
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *prefix; 
  for (ALL_LIST_ELEMENTS (ifp->assigned_prefix_list, node, nnode, prefix))
  {
    if (prefix_same (&prefix->prefix, &assigned_prefix->prefix)) {
      mark_prefix_invalid (prefix);
    }
  } 
  remove_from_associated_prefixes (assigned_prefix, ifp);
}

static struct prefix *
check_non_volatile_storage (struct ospf6_aggregated_prefix *agp, 
			    struct ospf6_interface *ifp, struct list *in_use_prefixes)
{
  struct listnode *node, *nnode;
  struct prefix *prefix;

  for (ALL_LIST_ELEMENTS (ifp->associated_prefixes, node, nnode, prefix))
  {
    if (prefix_contains (&agp->prefix, prefix)){
      /* Ensure validity */
      struct listnode *inner_node, *inner_nnode;
      struct prefix *current_prefix;
      u_int8_t collides;

      collides = 0;

      for (ALL_LIST_ELEMENTS (in_use_prefixes, node, nnode, current_prefix))
      {
	if (prefix_same (current_prefix, prefix))
	{
	  collides = 1;
	  break;
	}
      }

      if (!collides) return prefix;
    }
  }
  return NULL;
}

static void 
make_prefix_assignment (struct ospf6_aggregated_prefix *agp, 
			struct ospf6_interface *ifp, struct list *aspl)
{
  struct list *in_use_prefixes; 
  struct prefix *prefix;  
  struct ospf6_assigned_prefix *assigned_prefix;
  
  if (check_pending_assignments (agp, ifp)) return;

  //Determine which prefixes are already in use
  in_use_prefixes = create_in_use_list (agp, aspl);

  prefix = check_non_volatile_storage (agp, ifp, in_use_prefixes); 

  /*TODO check pending */

  if (prefix == NULL)
  {
    prefix = choose_first_unassigned_prefix (agp, in_use_prefixes);
  }
  
  //If can't make an assignment - Raise a warning?

  //Mark as valid and originate
  if (prefix != NULL)
  {
    assigned_prefix = malloc (sizeof (struct ospf6_assigned_prefix));

    assigned_prefix->prefix.family = prefix->family;
    assigned_prefix->prefix.prefixlen = prefix->prefixlen;
    assigned_prefix->prefix.prefix = prefix->u.prefix6;

    assigned_prefix->assigning_router_id = ospf6->router_id;
    assigned_prefix->assigning_router_if_id = ifp->interface->ifindex;
   
    assigned_prefix->deprecation_thread = NULL;

    start_using_prefix (assigned_prefix, ifp, aspl);
  }
}

static void 
handle_self_assigned (struct ospf6_assigned_prefix *existing_assigned_prefix, 
		      struct ospf6_interface *ifp, struct list *aspl)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *prefix;

  if (is_prefix_valid_network_wide (existing_assigned_prefix, aspl))
  {
    continue_using_prefix (existing_assigned_prefix, ifp, aspl);
  }
  else 
  {
    stop_using_prefix (existing_assigned_prefix, ifp, aspl);
  }
}

static void 
handle_other_assigned (struct ospf6_assigned_prefix *existing_assigned_prefix, 
			  struct ospf6_interface *ifp, struct list *aspl)
{
    if (continue_using_prefix (existing_assigned_prefix, ifp, aspl)) return;

    if (is_prefix_valid_locally (existing_assigned_prefix, ifp->area))
    {
      start_using_prefix (existing_assigned_prefix, ifp, aspl);
      /* TODO: Cancel pending */
    }
   
    /* Silently ignore invalid assignments */
}

static void 
handle_self_not_assigned (struct ospf6_aggregated_prefix *current_aggregate_prefix, 
		       struct ospf6_interface *ifp, struct list *aspl)
{
    /* Make assignment from this aggregated prefix */
    make_prefix_assignment (current_aggregate_prefix, ifp, aspl);
}

static void 
handle_other_not_assigned (struct ospf6_aggregated_prefix *current_aggregate_prefix, 
			   struct ospf6_interface *ifp, struct list *aspl)
{
  /* Draft specifies to do nothing */
}

static void 
process_prefix_interface_pair (struct ospf6_aggregated_prefix *agp, 
			       struct ospf6_interface *ifp, struct list *aspl)
{
  struct list *active_neigbor_list;
  u_int8_t has_highest_rid, has_highest_assignment;
  struct ospf6_assigned_prefix *highest_assigned_prefix;
 
  active_neigbor_list = generate_active_neighbor_list (ifp->neighbor_list);

  has_highest_rid = is_highest_rid (ospf6->router_id, active_neigbor_list);
  highest_assigned_prefix = find_highest_prefix_assignment (agp, 
						 active_neigbor_list, aspl);

  list_free (active_neigbor_list);
  /* Is Router ID higher than current assigner? */
  has_highest_assignment = 0;
  
  if ((highest_assigned_prefix 
	&& ospf6->router_id > highest_assigned_prefix->assigning_router_id) 
      || highest_assigned_prefix == NULL)
  {
    highest_assigned_prefix = find_own_prefix_assignment (agp, ifp, aspl);
    
    if (highest_assigned_prefix != NULL)
    {
      has_highest_assignment = 1;
    }
  }

  if (has_highest_assignment)
  {
    handle_self_assigned (highest_assigned_prefix, ifp, aspl);
  }
  else if (highest_assigned_prefix != NULL)
  {
    handle_other_assigned (highest_assigned_prefix, ifp, aspl);
  }
  else if (has_highest_rid) 
  {
    handle_self_not_assigned (agp, ifp, aspl); 
  }
  else 
  {
    handle_other_not_assigned (agp, ifp, aspl);
  }
}

static u_int8_t
exists_containing_prefix (struct ospf6_aggregated_prefix *aggregated_prefix, 
			  struct list *aggregated_prefix_list)
{
  struct listnode *node, *nnode;
  struct ospf6_aggregated_prefix *current_prefix; 
  
  for (ALL_LIST_ELEMENTS (aggregated_prefix_list, node, nnode, current_prefix))
  {
    if (prefix_contains (current_prefix, aggregated_prefix) 
	&& (current_prefix != aggregated_prefix)) 
    {
      return 1;
    }
  }

  return 0;
}

static void 
process_prefix_interface_pairs (struct ospf6_area *oa, 
				struct list *aggregated_prefix_list, 
				struct list *assigned_prefix_list)
{
  struct listnode *node, *nnode;
  struct ospf6_aggregated_prefix *ag_prefix;

  for (ALL_LIST_ELEMENTS (aggregated_prefix_list, node, nnode, ag_prefix)) 
  {
    struct listnode *inner_node, *inner_nnode;
    struct ospf6_interface *ifp;

    if (!exists_containing_prefix (ag_prefix, aggregated_prefix_list))
    {	
      for (ALL_LIST_ELEMENTS (oa->if_list, inner_node, inner_nnode, ifp)) 
      {
	process_prefix_interface_pair (ag_prefix, ifp, assigned_prefix_list);
      }
    }
  }
}

static void
purge_assigned_prefix_from_interface (struct ospf6_interface *oi,
              struct ospf6_assigned_prefix *assigned_prefix)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *ap;

  for (ALL_LIST_ELEMENTS (oi->assigned_prefix_list, node, nnode, ap))
  {
    if (prefix_same(&ap->prefix, &assigned_prefix->prefix))
    {
      listnode_delete (oi->assigned_prefix_list, ap);
    }
  }
}

static void
purge_assigned_prefix_from_area (struct ospf6_area *oa,
    struct ospf6_assigned_prefix *assigned_prefix)
{
  struct listnode *node, *nnode;
  struct ospf6_interface *ifp;

  for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, ifp))
  {
    purge_assigned_prefix_from_interface (ifp, assigned_prefix);
  }
}

static void
purge_assigned_prefix (struct ospf6_assigned_prefix *assigned_prefix)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;

  for (ALL_LIST_ELEMENTS (ospf6->area_list, node, nnode, oa))
  {
    purge_assigned_prefix_from_area (oa, assigned_prefix);
  }
}

static void
assigned_prefix_deprication_thread (struct thread *thread)
{
  struct ospf6_assigned_prefix *assigned_prefix;

  assigned_prefix = (struct ospf6_assigned_prefix *) THREAD_ARG (thread);

  purge_assigned_prefix (assigned_prefix);

  if (assigned_prefix->assigning_router_id == ospf6->router_id)
  {
    //TODO: Send out RA - With time set to 0
    originate_new_ac_lsa ();
  }
  assigned_prefix->deprecation_thread = NULL;
}

static void
schedule_assigned_prefix_deprecation (struct ospf6_assigned_prefix *assigned_prefix)
{
  if (!assigned_prefix->deprecation_thread)
  {
    assigned_prefix->deprecation_thread =
      thread_add_timer (master,
                        assigned_prefix_deprication_thread,
                        assigned_prefix,
                        OSPF6_TERMINATE_PREFIX_ASSIGNMENT_SECONDS);
  }
}

static void 
delete_invalid_assigned_prefixes_on_interface (struct ospf6_interface *oi)
{
  struct listnode *node, *nnode;
  struct ospf6_assigned_prefix *ap;

  for (ALL_LIST_ELEMENTS (oi->assigned_prefix_list, node, nnode, ap))
  {
    if (!ap->is_valid) 
    {
      schedule_assigned_prefix_deprecation (ap);
    }
    else 
    {
      THREAD_OFF (ap->deprecation_thread);
      ap->deprecation_thread = NULL;
    }
  }
}

static void 
delete_invalid_assigned_prefixes_in_area (struct ospf6_area *oa)
{
  struct listnode *node, *nnode;
  struct ospf6_interface *ifp;

  for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, ifp)) 
  {
    delete_invalid_assigned_prefixes_on_interface (ifp);
  }
}

void 
ospf6_assign_prefixes (void)
{
  struct ospf6_area *backbone_area;
  struct list *assigned_prefix_list, *aggregated_prefix_list;
  
  zlog_warn ("Running assignment algorithm");

  /* OSPFv3 Autoconf only runs on the backbone */
  backbone_area = ospf6_area_lookup (0, ospf6);

  mark_area_prefixes_invalid (backbone_area);

  create_ac_lsdb_snapshot (backbone_area->lsdb, 
      &assigned_prefix_list, &aggregated_prefix_list);

  process_prefix_interface_pairs (backbone_area, 
      aggregated_prefix_list, assigned_prefix_list);
    
  delete_invalid_assigned_prefixes_in_area (backbone_area);

  /* Tidy up */
  /* Keep hold of aggregated prefix list */
  list_delete (ospf6->aggregated_prefix_list);
  ospf6->aggregated_prefix_list = aggregated_prefix_list;

  list_free (assigned_prefix_list);
}

static void 
ospf6_assign_prefixes_thread (struct thread *t)
{
  ospf6->assign_prefix_thread = NULL;
  ospf6_assign_prefixes ();
}

void 
ospf6_schedule_assign_prefixes (void) 
{
  if (ospf6->assign_prefix_thread) 
    return;
  ospf6->assign_prefix_thread =
    thread_add_event (master, ospf6_assign_prefixes_thread, NULL, 0);
}

/* Install autoconf related commands. */
void 
ospf6_auto_init (void) 
{
  install_element (CONFIG_NODE, &ipv6_allocate_prefix_cmd);
  install_element (CONFIG_NODE, &no_ipv6_allocate_prefix_cmd);

  install_element (VIEW_NODE, &show_ipv6_allocated_prefix_cmd); 
  install_element (VIEW_NODE, &show_ipv6_aggregated_prefix_cmd); 
  install_element (VIEW_NODE, &show_ipv6_assigned_prefix_cmd); 

  install_element (ENABLE_NODE, &show_ipv6_allocated_prefix_cmd); 
  install_element (ENABLE_NODE, &show_ipv6_aggregated_prefix_cmd); 
  install_element (ENABLE_NODE, &show_ipv6_assigned_prefix_cmd); 
}
