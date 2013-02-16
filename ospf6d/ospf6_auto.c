#include <zebra.h>

#include "linklist.h"
#include "thread.h"

#include "ospf6_auto.h"
#include "ospf6_top.h"
#include "ospf6_interface.h"
#include "ospf6d.h"

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
void ospf6_set_router_id (u_int32_t rid){
	ospf6_delete(ospf6);

	/* Remove all timers */
	struct thread *t = master->timer.head;
	for(int i = 0; i < master->timer.count; i++){
		struct thread *next; 
		next = t->next;
		thread_cancel(t);
		t = next;
	}

	/* Reconfigure */
	/* TODO: AUTO CONFIGURE :) */
	vty_read_config (NULL, "/usr/local/quagga/ospf6d.conf");

	ospf6->router_id = rid; 
	ospf6->router_id_static = rid;
}
