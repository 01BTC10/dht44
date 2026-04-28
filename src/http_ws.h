#ifndef DHT44_HTTP_WS_H
#define DHT44_HTTP_WS_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

/*
 * Combined HTTP + WebSocket server (libwebsockets) integrated with the
 * daemon's single-threaded select loop.
 *
 * Routes:
 *   GET  /                         → serves the React bundle (disk or embedded)
 *   GET  /api/peers?limit=&order=  → JSON
 *   GET  /api/queries?since=&limit=→ JSON
 *   GET  /api/infohashes?limit=    → JSON
 *   GET  /api/bep44?limit=         → JSON
 *   GET  /api/stats                → JSON
 *   WS   /stream                   → push events ("peers","queries","infohashes","bep44","stats")
 *
 * GeoIP lookups against MaxMind GeoLite2 .mmdb files are attached to each
 * serialized peer row when http_ws_set_geoip is called with their paths.
 */

/* Initialize. port=0 disables web. static_dir may be NULL to use built-in
 * minimal index.html (just loads /main.js from same origin). Returns 0 on
 * success, -1 on failure. */
int http_ws_init(uint16_t port, const char *static_dir);

/* Tear down. */
void http_ws_uninit(void);

/* Configure local MaxMind .mmdb files. NULL disables. */
int http_ws_set_geoip(const char *city_path, const char *asn_path);

/* Drive one iteration of libwebsockets. Call from the daemon loop. */
void http_ws_service(int timeout_ms);

/* Broadcast a JSON payload to all WebSocket clients subscribed to `topic`.
 * Called by the observer. `json_str` is copied internally. */
void http_ws_publish(const char *topic, const char *json_str);

/* Periodic tick: emits a stats snapshot to the "stats" topic. */
void http_ws_heartbeat(void);

/* Parse an IP string (possibly redacted CIDR form like "1.2.3.0/24")
 * into a sockaddr_storage. Returns 1 on success. Used by both the
 * classifier path here and the deny refresh tick in cmd_daemon.c. */
int parse_ip_lenient(const char *ip, struct sockaddr_storage *ss, socklen_t *ss_len);

#endif
