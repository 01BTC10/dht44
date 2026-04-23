#ifndef DHT44_UPNP_H
#define DHT44_UPNP_H

#include <stdint.h>

/*
 * Best-effort UPnP IGD (Internet Gateway Device) port mapping for the daemon's
 * UDP port. All errors are non-fatal — log and carry on; the daemon still works
 * on a public IP or with manual port forwarding. Mappings show up at the IGD
 * with description "dht44".
 *
 * Usage:
 *   upnp_init(port, lifetime_sec)        // discover + AddPortMapping (UDP)
 *   upnp_refresh()                       // re-add (idempotent), every ~30 min
 *   upnp_shutdown()                      // DeletePortMapping + free
 */

/* Returns 0 on success; -1 if no IGD found, mapping refused, or any error. */
int  upnp_init(uint16_t udp_port, uint32_t lifetime_sec);

/* Returns 0 on success, -1 if init failed or refresh refused. */
int  upnp_refresh(void);

/* Safe to call even if init failed. */
void upnp_shutdown(void);

#endif
