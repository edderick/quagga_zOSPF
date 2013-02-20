#include <zebra.h>

#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "prefix.h"

#include "ospf6_top.h"
#include "ospf6_interface.h"
#include "ospf6_message.h"
#include "ospf6_area.h"
#include "ospf6_auto.h"
#include "ospf6d.h"

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

        for (i = 0; i < iflist->count; i++) {
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

/* TODO Add a parameter for fingerprint? */
 u_int32_t
generate_router_id ()
{
        srand(ospf6_router_hardware_fingerprint ());
        return rand();
}

/* Shuts down router and restarts it with new router-id */
void 
ospf6_set_router_id (u_int32_t rid)
{
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
		ospf6_delete (ospf6);

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
        	for (i = 0; i < iflist->count; i++) {
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
  
  zlog_warn("Checking packet");
  if (oh->router_id == ospf6->router_id) 
  {
    struct listnode *node, *nnode;
    struct ospf6_area *area; 

    /* Self originated */
    if (IPV6_ADDR_SAME(&src, &dst))
      return;
    
    /* Check all IP Addresses associated with this router*/
    for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area))
    {
      struct listnode *ifnode, *ifnnode;
      struct ospf6_interface *inf;
      for (ALL_LIST_ELEMENTS(area->if_list, ifnode, ifnnode, inf))
      {
	/* Multiple interfaces on same link? */
	if(IPV6_ADDR_SAME(&src, inf->linklocal_addr)){
	  return;
	}
      }
    }
  
    zlog_warn("BETTER CHANGE BRO");

  }
  else 
  {
    zlog_warn("No match");
  }
  
}
