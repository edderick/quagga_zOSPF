#ifndef OSPF6_AUTO_H
#define OSPF6_AUTO_H

u_int32_t ospf6_generate_router_id ();
u_int32_t ospf6_router_hardware_fingerprint (); 
void ospf6_init_seed ();

void ospf6_set_router_id (u_int32_t rid);

void ospf6_check_router_id(struct ospf6_header *oh, struct in6_addr src, struct in6_addr dst);
int ospf6_check_hw_fingerprint (struct ospf6_lsa_header *lsa_header); 

#define R_HW_FP_BYTELEN 4
#define R_HW_FP_CMP(D,S)   memcmp ((D), (S), R_HW_FP_BYTELEN)

#endif /* OSPF6_AUTO_H */
