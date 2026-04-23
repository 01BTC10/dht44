/*
 * miniupnpc IGD glue. The daemon calls upnp_init at startup; on success the
 * router has a UDP mapping for our port. Refresh on a 30-minute timer to
 * outlast the lease duration we requested. Errors are logged but never fatal.
 */

#include "upnp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

struct upnp_state {
    int             ready;
    char            port_str[8];        /* "65535\0" worst case */
    char            lease_str[16];      /* int32 seconds */
    char            internal_ip[64];
    char            external_ip[64];
    struct UPNPUrls urls;
    struct IGDdatas data;
};

static struct upnp_state s = { 0 };

static int
do_add_mapping(void)
{
    if (!s.ready) return -1;
    int rc = UPNP_AddPortMapping(
        s.urls.controlURL,
        s.data.first.servicetype,
        s.port_str,                 /* extPort */
        s.port_str,                 /* inPort  */
        s.internal_ip,              /* inClient */
        "dht44",                    /* description */
        "UDP",                      /* protocol */
        NULL,                       /* remoteHost */
        s.lease_str                 /* leaseDuration ("0" = permanent) */
    );
    if (rc != UPNPCOMMAND_SUCCESS) {
        fprintf(stderr, "[dht44:upnp] AddPortMapping(%s/UDP) failed: %s\n",
                s.port_str, strupnperror(rc));
        return -1;
    }
    return 0;
}

int
upnp_init(uint16_t udp_port, uint32_t lifetime_sec)
{
    if (s.ready) {
        fprintf(stderr, "[dht44:upnp] already initialised\n");
        return -1;
    }

    int discover_err = 0;
    /*
     * 2-second discovery timeout. localport 0 = UPNP_LOCAL_PORT_ANY (let
     * the kernel pick the source port for the SSDP M-SEARCH). ipv6=0,
     * ttl=2 (default).
     */
    struct UPNPDev *devlist = upnpDiscover(2000, NULL, NULL, 0, 0, 2, &discover_err);
    if (!devlist) {
        fprintf(stderr, "[dht44:upnp] no IGD discovered (err=%d)\n", discover_err);
        return -1;
    }

    int rc = UPNP_GetValidIGD(devlist, &s.urls, &s.data,
                              s.internal_ip, sizeof(s.internal_ip),
                              s.external_ip, sizeof(s.external_ip));
    freeUPNPDevlist(devlist);
    if (rc != UPNP_CONNECTED_IGD) {
        fprintf(stderr, "[dht44:upnp] no usable IGD (rc=%d)\n", rc);
        FreeUPNPUrls(&s.urls);
        return -1;
    }

    snprintf(s.port_str,  sizeof(s.port_str),  "%u", (unsigned)udp_port);
    snprintf(s.lease_str, sizeof(s.lease_str), "%u", (unsigned)lifetime_sec);
    s.ready = 1;

    if (do_add_mapping() < 0) {
        FreeUPNPUrls(&s.urls);
        s.ready = 0;
        return -1;
    }
    fprintf(stderr, "[dht44:upnp] mapped %s/UDP on IGD (lease=%us, %s -> %s)\n",
            s.port_str, (unsigned)lifetime_sec, s.internal_ip,
            s.external_ip[0] ? s.external_ip : "(unknown)");
    return 0;
}

int
upnp_refresh(void)
{
    if (!s.ready) return -1;
    return do_add_mapping();
}

void
upnp_shutdown(void)
{
    if (!s.ready) return;
    int rc = UPNP_DeletePortMapping(s.urls.controlURL,
                                    s.data.first.servicetype,
                                    s.port_str, "UDP", NULL);
    if (rc != UPNPCOMMAND_SUCCESS) {
        fprintf(stderr, "[dht44:upnp] DeletePortMapping(%s/UDP): %s\n",
                s.port_str, strupnperror(rc));
    } else {
        fprintf(stderr, "[dht44:upnp] removed %s/UDP mapping\n", s.port_str);
    }
    FreeUPNPUrls(&s.urls);
    s.ready = 0;
    memset(&s.urls, 0, sizeof(s.urls));
    memset(&s.data, 0, sizeof(s.data));
}
