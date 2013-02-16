#ifndef OSPF6_AUTO_H
#define OSPF6_AUTO_H

u_int32_t generate_router_id ();
u_int32_t ospf6_router_hardware_fingerprint (); 

void ospf6_set_router_id (u_int32_t rid);

#endif /* OSPF6_AUTO_H */
