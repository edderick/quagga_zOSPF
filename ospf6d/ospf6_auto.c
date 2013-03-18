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

#include "ospf6_intra.h"
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
}

/* Ensure router id is not a duplicate */
void 
ospf6_check_router_id (struct ospf6_header *oh, struct in6_addr src, struct in6_addr dst)
{
  zlog_warn ("Checking packet");
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
  else 
  {
    zlog_warn ("No match");
  }
}

/* Ensure a self originated lsa is from self */
int 
ospf6_check_hw_fingerprint (struct ospf6_lsa_header *lsa_header) 
{
  char *start, *end, *current;

  /* Check it is an AC LSA */
  if (lsa_header->type != ntohs(OSPF6_LSTYPE_AC))
  {
    zlog_warn ("Is not an AC LSA");
    return 0;
  }

  /* Check it has an LS-ID of 0 */
  if (lsa_header->id != 0)
  {
    zlog_warn ("Is not ID = 0");
    return 0;
  }

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
	zlog_warn("True self");
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

/* List all prefixes allocated to this router */
DEFUN (show_ipv6_allocated_prefix, 
       show_ipv6_allocated_prefix_cmd, 
       "show ipv6 ospf6 prefixes allocated",
       OSPF6_STR)
{
  struct listnode *node, *nextnode;
  struct ospf6_aggregated_prefix *aggregated_prefix;

  vty_out (vty, "aggregated Prefixes: %s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS (ospf6->aggregated_prefix_list, node, nextnode, aggregated_prefix)) 
  {
    if (aggregated_prefix->source != OSPF6_PREFIX_SOURCE_OSPF)
    {
      vty_out (vty, "Source : %d%s", aggregated_prefix->source, VTY_NEWLINE); 
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

  vty_out (vty, "Aggregated Prefixes: %s", VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (ospf6->aggregated_prefix_list, node, nextnode, aggregated_prefix)) 
  {
    vty_out (vty, "Advertising router id: %d", aggregated_prefix->advertising_router_id);
    /* TODO: list out all aggregate prefixes known about */
    /* Include where they are originated from */
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
  interface = ospf6_interface_lookup_by_ifindex(ifp->ifindex);

  vty_out (vty, "Assigned Prefixes for %s: %s", ifname, VTY_NEWLINE);
  
  for (ALL_LIST_ELEMENTS (interface->assigned_prefix_list, node, nextnode, assigned_prefix)) 
  {
    vty_out (vty, "Originating router id: %d", assigned_prefix->assigning_router_id);
    /* TODO: list out all assigned prefixes for interface */
    /* Include who assigned them */
  }
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
}
