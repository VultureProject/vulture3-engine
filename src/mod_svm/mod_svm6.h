/*                       _                            __
 *   _ __ ___   ___   __| |    _____   ___ __ ___    / /_
 *  | '_ ` _ \ / _ \ / _` |   / __\ \ / / '_ ` _ \  | '_ \
 *  | | | | | | (_) | (_| |   \__ \\ V /| | | | | | | (_) |
 *  |_| |_| |_|\___/ \__,_|___|___/ \_/ |_| |_| |_|  \___/
 *                       |_____|
 *  Copyright (c) 2017 Baptiste de Magnienville & Kevin Guillemot
 *  Released under the GPLv3
 */


#ifndef VULTURE_ENGINE_MOD_SVM6_H
#define VULTURE_ENGINE_MOD_SVM6_H

#include "svm_util.h"
#include "ap_mpm.h"
#include <hiredis/hiredis.h>


/*************/
/* Constants */
/*************/

#define INPUT_FILTER "SVM5_IN"
#define OUTPUT_FILTER "SVM5_OUT"


/**************/
/* Structures */
/**************/

typedef enum redis_role {
    ROLE_UNKNOWN,
    ROLE_SLAVE,
    ROLE_MASTER
} redis_role;

/*
 * per-server configuration and data
 */
typedef struct mod_redis_conf {
    apr_thread_mutex_t *lock;
    server_rec *server;

    redis_role role;

    // local
    redisContext *context;
    char *unix_socket_path;

    // master
    redisContext *masterContext;
    char *ip;
    int port;

    int timeout;

    char *scriptsha;

    apr_pool_t *pool;
} mod_redis_conf;


/************************/
/* Functions signatures */
/************************/

static const char* svm5_activated(cmd_parms *cmd, void *cfg, int arg);
static const char* svm5_nrclass(cmd_parms* cmd, void* cfg, const char* arg);
static const char* svm5_SVdims(cmd_parms* cmd, void* cfg, const char* arg1, const char *arg2);
static const char* svm5_SV(cmd_parms* cmd, void* cfg, const char* arg);
static const char* svm5_supportdims(cmd_parms* cmd, void* cfg, const char *arg1, const char *arg2);
static const char* svm5_support(cmd_parms* cmd, void* cfg, const char* arg);
static const char* svm5_SVcoef(cmd_parms* cmd, void* cfg, const char* arg);
static const char* svm5_rho(cmd_parms* cmd, void* cfg, const char* arg);
static const char* svm5_nSV(cmd_parms* cmd, void* cfg, const char* arg);
static const char* svm5_SVcoefstrides(cmd_parms* cmd, void* cfg, const char *arg1, const char *arg2);
static const char* svm5_gamma(cmd_parms* cmd, void* cfg, const char *arg);
static const char* svm5_maxsize(cmd_parms* cmd, void* cfg, const char* arg);
static void *create_conf(apr_pool_t *pool, char* context);
static void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD);
static const command_rec svm_directives[] = {
        AP_INIT_FLAG("svm5", svm5_activated, NULL, ACCESS_CONF, "Is the SVM5 On or Off"),
        AP_INIT_TAKE1("svm5_nrclass", svm5_nrclass, NULL, ACCESS_CONF, "Attribute 'nr_class' for svm55"),
        AP_INIT_TAKE2("svm5_SVdims", svm5_SVdims, NULL, ACCESS_CONF, "Attributes 'SV_dims' for svm5"),
        AP_INIT_TAKE1("svm5_SV", svm5_SV, NULL, ACCESS_CONF, "Attribute 'SV' for svm5"),
        AP_INIT_TAKE2("svm5_supportdims", svm5_supportdims, NULL, ACCESS_CONF, "Attributes 'support_dims' for svm5"),
        AP_INIT_TAKE1("svm5_support", svm5_support, NULL, ACCESS_CONF, "Attribute 'support' for svm5"),
        AP_INIT_TAKE1("svm5_SVcoef", svm5_SVcoef, NULL, ACCESS_CONF, "Attribute 'sv_coef' for svm5"),
        AP_INIT_TAKE1("svm5_rho", svm5_rho, NULL, ACCESS_CONF, "Attribute 'rho' for svm5"),
        AP_INIT_TAKE1("svm5_nSV", svm5_nSV, NULL, ACCESS_CONF, "Attribute 'nSV' for svm5"),
        AP_INIT_TAKE2("svm5_SVcoefstrides", svm5_SVcoefstrides, NULL, ACCESS_CONF, "Attributes 'sv_coef_strides' for svm5"),
        AP_INIT_TAKE1("svm5_gamma", svm5_gamma, NULL, ACCESS_CONF, "Attributes 'gamma' for svm5"),
        AP_INIT_TAKE1("svm5_maxsize", svm5_maxsize, NULL,  ACCESS_CONF, "Max size of bytes received"),
        { NULL }
};


/*------------------*/
/* Module functions */
/*------------------*/


#endif //VULTURE_ENGINE_MOD_SVM6_H
