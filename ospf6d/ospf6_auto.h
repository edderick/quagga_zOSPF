#ifndef OSPF6_AUTO_H
#define OSPF6_AUTO_H

/* Prefix that has been given to OSPF6d to distribute */
struct ospf6_aggregated_prefix 
{
  struct prefix prefix;
  int source;
  u_int32_t advertising_router_id; 
};

#define OSPF6_PREFIX_SOURCE_DHCP6_PD 0
#define OSPF6_PREFIX_SOURCE_CONFIGURED 1
#define OSPF6_PREFIX_SOURCE_GENERATED 2
#define OSPF6_PREFIX_SOURCE_OSPF 3

#define OSPF6_PREFIX_SOURCE_DHCP6_PD_STRING "DHCPv6 Prefix Delegation"
#define OSPF6_PREFIX_SOURCE_CONFIGURED_STRING "Manually Configured"
#define OSPF6_PREFIX_SOURCE_GENERATED_STRING "Automatically Generated"
#define OSPF6_PREFIX_SOURCE_OSPF_STRING "Received From Neighbouring Router"

#define OSPF6_NEW_ULA_PREFIX_SECONDS		    20
#define OSPF6_TERMINATE_ULA_PREFIX_SECONDS	    120 
#define OSPF6_NEW_PREFIX_ASSIGNMENT_SECONDS	    20 
#define OSPF6_TERMINATE_PREFIX_ASSIGNMENT_SECONDS   60 

/* Prefix that has been assigned to a link by some router */
struct ospf6_assigned_prefix 
{
  struct prefix prefix;
  u_int32_t assigning_router_id;
  u_int32_t assigning_router_if_id;
  u_int8_t is_valid;

  struct ospf6_interface *interface;

  struct thread *pending_thread;
  struct thread *deprecation_thread;
};

void ospf6_auto_init (void); 

u_int32_t ospf6_generate_router_id (void);
u_int32_t ospf6_router_hardware_fingerprint (void); 
void ospf6_init_seed (void);

void ospf6_set_router_id (u_int32_t rid);

void ospf6_check_router_id (struct ospf6_header *oh, struct in6_addr src, struct in6_addr dst);
int ospf6_check_hw_fingerprint (struct ospf6_lsa_header *lsa_header); 

void ospf6_schedule_assign_prefixes (void);

void ospf6_write_associated_prefixes_to_file (struct ospf6_interface *ifp);
void ospf6_read_associated_prefixes_from_file (struct ospf6_interface *ifp);

#define R_HW_FP_BYTELEN 4
#define R_HW_FP_CMP(D,S)   memcmp ((D), (S), R_HW_FP_BYTELEN)

#define ASSOCIATED_PREFIXES_MAX_LEN 5

#endif /* OSPF6_AUTO_H */
