/*
 * Powerdns logger daemon
 * ----------------------
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (C) 2017, Spamhaus Technology Ltd, London
 *
 * The Initial developer of the Original code is:
 * Massimo Cetra
 *
 */

#include "inih/ini.h"
#include <time.h>
#include "pdns-logger.h"
#include "dnsmessage.pb-c.h"

static FILE *fp = NULL;
static char *file = NULL;
static int force_flush = 0;
static char rewrites_only = 1;
static char disabled = 0;

static int opt_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
    (void) user;

    if (zstr(section) || zstr(name) || zstr(value)) {
        return 1;
    }

    if (!strncmp(section, "jsonfile", sizeof("jsonfile"))) {
        if (!strncmp(name, "logfile", sizeof("logfile"))) {
            file = strdup(value);
        } else if (!strncmp(name, "force-flush", sizeof("force-flush"))) {
            force_flush = atoi(value) ? 1 : 0;
        } else if (!strncmp(name, "only-rewrites", sizeof("only-rewrites"))) {
            rewrites_only = atoi(value) ? 1 : 0;
        } else if (!strncmp(name, "disabled", sizeof("disabled"))) {
            disabled = atoi(value) ? 1 : 0;
        } else {
            fprintf(stderr, "Unmanaged INI option '%s' at line %d\n", name, lineno);
        }
        return 1;
    }

    return 1;
}

static pdns_status_t jsonfile_init(const char *inifile) {
    if (zstr(inifile)) {
        return PDNS_NO;
    }

    if (ini_parse(inifile, opt_handler, NULL) != 0) {
        fprintf(stderr, "jsonfile: Can't read .ini file: '%s'\n", inifile);
        return PDNS_NO;
    }

    if (disabled) {
        fprintf(stderr, "jsonfile: Disabled according to configuration\n");
        return PDNS_OK;
    }

    if (zstr(file)) {
        fprintf(stderr, "jsonfile: no log file set. Disabling.\n");
        return PDNS_NO;
    }

    fp = fopen(file, "a");
    if (fp == NULL) {
        fprintf(stderr, "jsonfile: cannot open '%s' for writing\n", file);
        return PDNS_NO;
    }

    return PDNS_OK;
}

static pdns_status_t jsonfile_rotate(void) {
    if (fp != NULL) {
        fp = freopen(file, "a", fp);
        if (fp == NULL) {
            fprintf(stderr, "jsonfile: cannot open '%s' for writing\n", file);
            return PDNS_NO;
        }
    }

    return PDNS_OK;
}

static pdns_status_t jsonfile_stop(void) {
    safe_free(file);

    if (fp != NULL) {
        fclose(fp);
    }

    return PDNS_OK;
}

#define write_log() \
    if (fp != NULL) { \
        fprintf(fp, "%s\n", str); \
        if (force_flush) { \
            fflush(fp); \
        } \
    }

    //fprintf(stderr, "%s\n", str);

static pdns_status_t jsonfile_log(void *rawpb) {
    PBDNSMessage *msg = rawpb;
    PBDNSMessage__DNSQuestion *q;
    PBDNSMessage__DNSResponse *r;
    char str[4096] = "";
    char ip[INET6_ADDRSTRLEN];
    time_t rawtime;
    struct tm ts;
    char time_string[80];

    if (disabled) {
        return PDNS_OK;
    }

    if (msg == NULL || msg->response == NULL) {
        return PDNS_OK;
    }

    if (rewrites_only != 0) {
        if (msg->response != NULL && zstr(msg->response->appliedpolicy)) {
            return PDNS_OK;
        }
    }

    if (msg->has_from) {
        if (msg->from.len == 4) {
            inet_ntop(AF_INET, (const void *) msg->from.data, ip, sizeof(ip));
        } else if (msg->from.len == 16) {
            inet_ntop(AF_INET6, (const void *) msg->from.data, ip, sizeof(ip));
        }
    }

    if (msg->has_originalrequestorsubnet) {
        assert(0);
    }

    q = msg->question;
    r = msg->response;

    if (msg->timesec && ip != NULL && q != NULL && r != NULL) {
        rawtime = msg->timesec;
        ts = *localtime(&rawtime);
        strftime(time_string, sizeof(time_string), "%Y-%m-%dT%H:%M:%S%z", &ts);
        snprintf(str, sizeof(str), "{\"@timestamp\":\"%s\",\"client\":{\"ip\":\"%s\"},\"dns\":{\"question\":{\"name\":\"%s\"}},\"rpz\":{\"policy_name\":\"%s\"}}", time_string, ip, q->qname, r->appliedpolicy);
        write_log();
    }

    return PDNS_OK;
}

pdns_logger_t jsonfile_engine = {
    jsonfile_init,
    jsonfile_rotate,
    jsonfile_stop,
    jsonfile_log
};
