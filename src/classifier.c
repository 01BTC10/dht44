#define _POSIX_C_SOURCE 200809L
#include "classifier.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "reputation.h"

/* Anti-piracy operator ASN keywords. Matched as case-insensitive
 * substrings in `asn_org`. Mirrored against iBlockList labels by
 * reputation_label_is_strong (reputation.c) so both code paths agree
 * on what counts as a "monitor" hit. */
static const char *MONITOR_ASN_KEYWORDS[] = {
    "markmonitor", "ip-echelon", "ip echelon", "irdeto", "nagra",
    "friend mts", "opsec", "ceg tek", "rightscorp", "excipio", NULL
};

/* Hosting / cloud ASNs that combined with port-farm density score
 * mildly. NOT an accusation by themselves — many legitimate seedboxes
 * live here. */
static const char *DC_ASN_KEYWORDS[] = {
    "hetzner", "ovh", "digitalocean", "amazon", "google llc", "google cloud",
    "microsoft", "azure", "linode", "vultr", "contabo", "leaseweb",
    "datacamp", "choopa", NULL
};

static int
contains_ci(const char *hay, const char *needle)
{
    if (!hay || !needle) return 0;
    size_t nl = strlen(needle);
    if (!nl) return 0;
    for (const char *p = hay; *p; p++) {
        if (strncasecmp(p, needle, nl) == 0) return 1;
    }
    return 0;
}

static const char *
match_keyword(const char *org, const char *const *kws)
{
    if (!org) return NULL;
    for (int i = 0; kws[i]; i++) {
        if (contains_ci(org, kws[i])) return kws[i];
    }
    return NULL;
}

/* Append "<sep><text>" to dst[0..*used] if it fits. *used is bumped on success. */
static void
append_reason(char *dst, size_t cap, size_t *used, const char *text)
{
    if (!text || !*text || *used + 1 >= cap) return;
    int n;
    if (*used == 0) n = snprintf(dst + *used, cap - *used, "%s", text);
    else            n = snprintf(dst + *used, cap - *used, " \xc2\xb7 %s", text);
    if (n > 0) *used += (size_t)n;
}

static void
push_signal(struct classify_result *r, const char *tag)
{
    if (r->n_signals >= CLASSIFY_MAX_SIGNALS) return;
    snprintf(r->signals[r->n_signals], CLASSIFY_SIG_CAP, "%s", tag);
    r->n_signals++;
}

void
classify_compute(const struct peer_signals *s, struct classify_result *r)
{
    memset(r, 0, sizeof(*r));
    r->cls = "ok";
    if (!s) return;

    int score = 0;
    size_t rused = 0;
    char tmp[CLASSIFY_SIG_CAP];

    /* Track which signals fired so the class assignment below can decide
     * "this peer's signals are explained by being a seedbox / VPS user
     * rather than a crawler". */
    int sig_silent_taker   = 0;
    int sig_read_only      = 0;
    int sig_asym_in        = 0;
    int sig_no_v_string    = 0;
    int sig_known_monitor  = 0;
    int sig_known_benign   = 0;

    if (s->as_dst == 0 && s->as_src >= 50) {
        score += 2;
        sig_silent_taker = 1;
        push_signal(r, "silent_taker");
        snprintf(tmp, sizeof(tmp),
                 "returned %lld distinct peers in find_node replies but"
                 " never appears in anyone else's routing table",
                 (long long)s->as_src);
        append_reason(r->reason, sizeof(r->reason), &rused, tmp);
    }

    if (s->same_ip >= 50) {
        score += 3;
        push_signal(r, "port_farm_mass");
        snprintf(tmp, sizeof(tmp),
                 "%lld ports on this IP (datacenter farm)",
                 (long long)s->same_ip);
        append_reason(r->reason, sizeof(r->reason), &rused, tmp);
    } else if (s->same_ip >= 10) {
        score += 2;
        push_signal(r, "port_farm_strong");
        snprintf(tmp, sizeof(tmp),
                 "%lld ports on this IP (likely seedbox / VPN exit)",
                 (long long)s->same_ip);
        append_reason(r->reason, sizeof(r->reason), &rused, tmp);
    } else if (s->same_ip >= 3) {
        push_signal(r, "port_farm_mild");
        snprintf(tmp, sizeof(tmp),
                 "%lld distinct ports on this IP (multi-client / NAT)",
                 (long long)s->same_ip);
        append_reason(r->reason, sizeof(r->reason), &rused, tmp);
    }

    if (s->ro == 1) {
        score += 2;
        sig_read_only = 1;
        push_signal(r, "read_only");
        append_reason(r->reason, sizeof(r->reason), &rused,
                      "advertises BEP 5 read-only (won't respond)");
    }

    if (s->bep42_ok == 0 && (s->queries_in + s->queries_out) >= 50) {
        score += 1;
        push_signal(r, "bep42_bad");
        append_reason(r->reason, sizeof(r->reason), &rused,
                      "ignores BEP 42 with high query volume");
    }

    if (s->queries_in >= 100
        && s->queries_in >= 5 * (s->queries_out > 0 ? s->queries_out : 1)) {
        score += 2;
        sig_asym_in = 1;
        push_signal(r, "asymmetric_in");
        snprintf(tmp, sizeof(tmp),
                 "queries us heavily while we rarely query them back"
                 " (%lld inbound / %lld outbound)",
                 (long long)s->queries_in, (long long)s->queries_out);
        append_reason(r->reason, sizeof(r->reason), &rused, tmp);
    }

    if (!s->has_v_string && (s->queries_in + s->queries_out) >= 20) {
        score += 1;
        sig_no_v_string = 1;
        push_signal(r, "no_v_string");
        append_reason(r->reason, sizeof(r->reason), &rused,
                      "no client identifier, frequent traffic");
    }

    const char *mon  = match_keyword(s->asn_org, MONITOR_ASN_KEYWORDS);
    int         is_dc = match_keyword(s->asn_org, DC_ASN_KEYWORDS) != NULL;
    if (mon) {
        score += 4;
        sig_known_monitor = 1;
        snprintf(tmp, sizeof(tmp), "monitor_asn:%s", s->asn_org ? s->asn_org : mon);
        push_signal(r, tmp);
        snprintf(tmp, sizeof(tmp),
                 "ASN matches known anti-piracy operator: %s",
                 s->asn_org ? s->asn_org : mon);
        append_reason(r->reason, sizeof(r->reason), &rused, tmp);
    } else if (is_dc && s->same_ip >= 5) {
        score += 1;
        snprintf(tmp, sizeof(tmp), "dc_asn:%s", s->asn_org);
        push_signal(r, tmp);
        snprintf(tmp, sizeof(tmp),
                 "datacenter ASN (%s) with %lld peers on this IP",
                 s->asn_org, (long long)s->same_ip);
        append_reason(r->reason, sizeof(r->reason), &rused, tmp);
    }

    /* External reputation. Same scoring as the JSON path in http_ws.c. */
    if (s->rep_source && s->rep_label) {
        if (strcmp(s->rep_source, "iblocklist") == 0) {
            int strong = reputation_label_is_strong(s->rep_source, s->rep_label);
            int mild   = 0;
            if (!strong) {
                if (strncasecmp(s->rep_label, "Botnet", 6) == 0
                    || strncasecmp(s->rep_label, "Proxy", 5) == 0) mild = 1;
            }
            if (strong) {
                score += 3;
                sig_known_monitor = 1;
                snprintf(tmp, sizeof(tmp), "iblocklist:%s", s->rep_label);
                push_signal(r, tmp);
                snprintf(tmp, sizeof(tmp),
                         "on community blocklist (%s)", s->rep_label);
                append_reason(r->reason, sizeof(r->reason), &rused, tmp);
            } else if (mild) {
                score += 1;
                snprintf(tmp, sizeof(tmp), "iblocklist:%s", s->rep_label);
                push_signal(r, tmp);
            } else {
                /* Tagged informational only, no score impact. */
                snprintf(tmp, sizeof(tmp), "iblocklist:%s", s->rep_label);
                push_signal(r, tmp);
            }
        } else if (strcmp(s->rep_source, "tor") == 0) {
            score += 1;
            push_signal(r, "tor_exit");
            append_reason(r->reason, sizeof(r->reason), &rused,
                          "Tor exit node");
        }
    }
    if (s->gn_malicious) {
        score += 3;
        sig_known_monitor = 1;
        push_signal(r, "greynoise:malicious");
        append_reason(r->reason, sizeof(r->reason), &rused,
                      "GreyNoise: classified malicious");
    } else if (s->gn_benign) {
        sig_known_benign = 1;
        push_signal(r, "greynoise:benign");
        append_reason(r->reason, sizeof(r->reason), &rused,
                      "GreyNoise: known benign scanner");
    }

    /* "seedbox-like" peer: clean datacenter / hosting ASN, has a real
     * client identifier, no crawler-shaped signals, no
     * known-monitor/benign tag. Label "seedbox" instead of crawler/
     * monitor when the score would otherwise put them there. */
    int is_seedbox_like = is_dc && !mon
                        && !sig_known_monitor
                        && !sig_known_benign
                        && s->has_v_string
                        && !sig_silent_taker
                        && !sig_asym_in
                        && !sig_read_only
                        && !sig_no_v_string;

    if      (score >= 5)                         r->cls = "honeypot";
    else if (is_seedbox_like && score >= 2)      r->cls = "seedbox";
    else if (score >= 3)                         r->cls = "monitor";
    else if (score >= 2)                         r->cls = "crawler";
    else                                         r->cls = "ok";

    r->score = score;
}
