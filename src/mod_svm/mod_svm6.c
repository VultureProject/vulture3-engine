/*                       _                            __
 *   _ __ ___   ___   __| |    _____   ___ __ ___    / /_
 *  | '_ ` _ \ / _ \ / _` |   / __\ \ / / '_ ` _ \  | '_ \
 *  | | | | | | (_) | (_| |   \__ \\ V /| | | | | | | (_) |
 *  |_| |_| |_|\___/ \__,_|___|___/ \_/ |_| |_| |_|  \___/
 *                       |_____|
 *  Copyright (c) 2017 Baptiste de Magnienville & Kevin Guillemot
 *  Released under the GPLv3
 */

#include "mod_svm6.h"

module AP_MODULE_DECLARE_DATA svm6_module;


static redisReply *masterRedisCommand(request_rec *r, char *redisFormatCmd, ...) {
    redisReply *reply = NULL;
    struct timeval timeout;

    mod_redis_conf *conf = ap_get_module_config(r->server->module_config, &svm6_module);

    if (conf->lock)
        apr_thread_mutex_lock(conf->lock);

    /*
     * Connect to the local server if not connected
     */
    if (!conf->context) {
        timeout.tv_sec = conf->timeout / 1000;
        timeout.tv_usec = (conf->timeout - (timeout.tv_sec * 1000)) * 1000;

        ap_log_rerror_(APLOG_MARK, APLOG_DEBUG, 0, r, "Connecting to local redis on %s (%d)", conf->unix_socket_path,
                       conf->timeout);
        conf->context = redisConnectUnixWithTimeout(conf->unix_socket_path, timeout);

        if ((!conf->context) || (conf->context->err != REDIS_OK))
            ap_log_rerror_(APLOG_MARK, APLOG_ERR, 0, r, "Connection to local redis failed to %s", conf->unix_socket_path);
    }

    /*
     * Get redis master ip and role
     */
    if (conf->role == ROLE_UNKNOWN && conf->context && conf->context->err == REDIS_OK) {
        redisReply *role_reply = redisCommand(conf->context, "ROLE");
        if (role_reply) {
            if (!strcmp("slave", role_reply->element[0]->str)) { // slave
                if (!strcmp("connected", role_reply->element[3]->str)) { // slave connected to master
                    conf->ip = apr_pstrdup(conf->pool, role_reply->element[1]->str);
                    conf->port = (int) role_reply->element[2]->integer;
                    ap_log_perror_(APLOG_MARK, APLOG_DEBUG, 0, r->pool, "Retrieved Redis Master address: %s:%d",
                                   conf->ip, conf->port);
                } else { // slave not connected to master
                    ap_log_perror_(APLOG_MARK, APLOG_DEBUG, 0, r->pool, "Redis slave not connected to redis master");
                }
                conf->role = ROLE_SLAVE;
            } else { // master
                conf->ip = NULL;
                conf->port = 0;
                conf->role = ROLE_MASTER;
            }
        } else { // Connection problem with local redis
            conf->context = NULL;
            conf->role = ROLE_UNKNOWN;
            ap_log_perror_(APLOG_MARK, APLOG_DEBUG, 0, r->pool, "Could not get ROLE from redis slave");
        }
    }

    /*
     * Connect to the master server if not connected and slave
     */
    if (conf->role == ROLE_SLAVE && conf->context && conf->context->err == REDIS_OK && !conf->masterContext &&
            conf->ip && conf->port) {
        timeout.tv_sec = conf->timeout / 1000;
        timeout.tv_usec = (conf->timeout - (timeout.tv_sec * 1000)) * 1000;

        ap_log_rerror_(APLOG_MARK, APLOG_DEBUG, 0, r, "Connecting to master redis on %s:%d (%d)", conf->ip, conf->port,
                       conf->timeout);
        conf->masterContext = redisConnectWithTimeout(conf->ip, conf->port, timeout);

        if ((!conf->masterContext) || (conf->masterContext->err != REDIS_OK))
            ap_log_rerror_(APLOG_MARK, APLOG_ERR, 0, r, "Connection to master redis failed to %s:%d", conf->ip, conf->port);
    }

    /*
     * Request redis
     */
    redisContext *ctx = NULL;
    if (conf->role == ROLE_MASTER && conf->context && conf->context->err == REDIS_OK)
        ctx = conf->context;
    else if (conf->role == ROLE_SLAVE && conf->masterContext && conf->masterContext->err == REDIS_OK)
        ctx = conf->masterContext;

    if (ctx) {
        va_list argptr;
        va_start(argptr, redisFormatCmd);
        reply = redisvCommand(ctx, redisFormatCmd, argptr);
        va_end(argptr);
    }

    /*
     * In the event of an error, close the connection to the server and
     * wait for a reconnection later
     */
    if (conf->context && (conf->context->err != REDIS_OK)) {
        ap_log_rerror_(APLOG_MARK, APLOG_ERR, 0, r, "Redis local error: %d %s", conf->context->err,
                       conf->context->errstr);
        redisFree(conf->context);
        conf->context = NULL;
    }

    if (conf->masterContext && (conf->masterContext->err != REDIS_OK)) {
        ap_log_rerror_(APLOG_MARK, APLOG_ERR, 0, r, "Redis master error: %d %s", conf->context->err,
                       conf->context->errstr);
        redisFree(conf->masterContext);
        conf->masterContext = NULL;
    }

    if (conf->lock)
        apr_thread_mutex_unlock(conf->lock);

    return reply;
}

const char *script = "local key = \"svm_\" .. KEYS[1] .. \"_\" .. KEYS[2] .. \"_\" .. ARGV[2]\n"
        "local time = ARGV[1]\n"
        "local last_insertion_time = redis.call(\"HGET\", key, \"ts\")\n"
        "if (last_insertion_time == false) then last_insertion_time = 0 end\n"
        "local elapsed_time = time - last_insertion_time\n"
        "if (elapsed_time >= 60) then -- Init / Time's over\n"
        "redis.call(\"HMSET\", key, \"idx\", 0, \"sum\", 1, \"ts\", 0,\n"
        "\"t0\", 1, \"t1\", 0, \"t2\", 0, \"t3\", 0, \"t4\", 0, \"t5\", 0, \"t6\", 0, \"t7\", 0, \"t8\", 0, \"t9\", 0,\n"
        "\"t10\", 0, \"t11\", 0, \"t12\", 0, \"t13\", 0, \"t14\", 0, \"t15\", 0, \"t16\", 0, \"t17\", 0, \"t18\", 0, \"t19\", 0,\n"
        "\"t20\", 0, \"t21\", 0, \"t22\", 0, \"t23\", 0, \"t24\", 0, \"t25\", 0, \"t26\", 0, \"t27\", 0, \"t28\", 0, \"t29\", 0,\n"
        "\"t30\", 0, \"t31\", 0, \"t32\", 0, \"t33\", 0, \"t34\", 0, \"t35\", 0, \"t36\", 0, \"t37\", 0, \"t38\", 0, \"t39\", 0,\n"
        "\"t40\", 0, \"t41\", 0, \"t42\", 0, \"t43\", 0, \"t44\", 0, \"t45\", 0, \"t46\", 0, \"t47\", 0, \"t48\", 0, \"t49\", 0,\n"
        "\"t50\", 0, \"t51\", 0, \"t52\", 0, \"t53\", 0, \"t54\", 0, \"t55\", 0, \"t56\", 0, \"t57\", 0, \"t58\", 0, \"t59\", 0)\n"
        "elseif (elapsed_time > 0) then -- Inside the period\n"
        "for i = 0, elapsed_time do\n"
        "local index = redis.call(\"HINCRBY\", key, \"idx\", 1)\n"
        "if (index >= 60) then index = 0 redis.call(\"HSET\", key, \"idx\", 0) end\n"
        "local curr_index = \"t\" .. index\n"
        "local req_count_at_tx = tonumber(redis.call(\"HGET\", key, curr_index))\n"
        "if (req_count_at_tx > 0) then redis.call(\"HINCRBY\", key, \"sum\", -req_count_at_tx) end\n"
        "redis.call(\"HSET\", key, curr_index, 0)\n"
        "end\n"
        "local curr_index = \"t\" .. redis.call(\"HGET\", key, \"idx\")\n"
        "redis.call(\"HSET\", key, curr_index, 1)\n"
        "redis.call(\"HINCRBY\", key, \"sum\", 1)\n"
        "elseif (elapsed_time == 0) then -- Latest tx\n"
        "local curr_index = \"t\" .. redis.call(\"HGET\", key, \"idx\")\n"
        "redis.call(\"HINCRBY\", key, curr_index, 1)\n"
        "redis.call(\"HINCRBY\", key, \"sum\", 1)\n"
        "end\n"
        "redis.call(\"HSET\", key, \"ts\", time)\n"
        "redis.call(\"EXPIRE\", key, 60)\n"
        "local sum = tonumber(redis.call(\"HGET\", key, \"sum\"))\n"
        "local limit = tonumber(redis.call(\"GET\", \"svm_\" .. KEYS[1] .. \"_\" .. KEYS[2] .. \"_limit\"))\n"
        "if (limit ~= nil and sum >= limit) then return 1 else return 0 end";

static void load_timering_script(request_rec *r) {
    mod_redis_conf *conf = ap_get_module_config(r->server->module_config, &svm6_module);
    conf->scriptsha = NULL;
    redisReply *reply = masterRedisCommand(r, "SCRIPT LOAD %s", script);
    ap_log_rerror_(APLOG_MARK,  APLOG_ERR, 0, r, "SCRIPT LOAD");
    if (reply) {
        if (reply->type == REDIS_REPLY_STRING) {
            conf->scriptsha = apr_pstrdup(conf->pool, reply->str);
        } else if (reply->type == REDIS_REPLY_ERROR) {
            ap_log_rerror_(APLOG_MARK, APLOG_ERR, 0, r, "SCRIPT LOAD error: %s", reply->str);
        }
    }
    freeReplyObject(reply);
}

static void check_amount(request_rec *r, char* type, char* val, char* svm) {
    if (!val) {
        ap_log_rerror_(APLOG_MARK, APLOG_NOTICE, 0, r, "Not checked: %s is %s", type, val);
        return;
    }
    mod_redis_conf *conf = ap_get_module_config(r->server->module_config, &svm6_module);
    redisReply *reply = masterRedisCommand(r, "EVALSHA %s 2 time %s %ld %s",
                                           conf->scriptsha, type, time(NULL), val);
    ap_log_rerror_(APLOG_MARK, APLOG_NOTICE, 0, r, "EVALSHA %s 2 time %s %ld %s",
                   conf->scriptsha, type, time(NULL), val);
    if (reply) {
        if (reply->type == REDIS_REPLY_INTEGER) {
            long block = reply->integer;
            if (block) {
                ap_log_rerror_(APLOG_MARK, APLOG_NOTICE, 0, r, "%s: too much requests in the last 60s, blocked", val);
                apr_table_set(r->subprocess_env, svm, "1");
            }
        } else if (reply->type == REDIS_REPLY_ERROR) {
            ap_log_rerror_(APLOG_MARK, APLOG_ERR, 0, r, "EVALSHA error: %s", reply->str);
            if (strstr("NOSCRIPT", reply->str))
                load_timering_script(r);
        }
    }
    freeReplyObject(reply);
}

static int svm6_handler(request_rec *r) {
    mod_redis_conf *conf = ap_get_module_config(r->server->module_config, &svm6_module);
    ap_log_rerror_(APLOG_MARK, APLOG_NOTICE, 0, r, "handler");
    apr_table_set(r->subprocess_env, "svm6", "0");

    //sprintf(r->useragent_ip, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);
    //sprintf(r->useragent_ip, "192.168.0.%d", rand() % 256);

    if (!conf->scriptsha)
        load_timering_script(r);

    if (conf->scriptsha) {
        check_amount(r, "ip", r->useragent_ip, "svm6");
        check_amount(r, "user", r->user, "svm7");
    }

    return DECLINED;
}

static const char *set_unix_socket_path(cmd_parms *parms, void *in_struct_ptr, const char *arg) {
    if (strlen(arg) == 0)
        return "RedisUnixSocketPath argument must be a string representing an unix socket";

    mod_redis_conf *conf = ap_get_module_config(parms->server->module_config, &svm6_module);
    conf->unix_socket_path = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char *set_timeout(cmd_parms *parms, void *in_struct_ptr, const char *arg) {
    int timeout;
    if (sscanf(arg, "%d", &timeout) != 1)
        return "RedisTimeout argument must be an integer representing the timeout setting for a connection";

    mod_redis_conf *conf = ap_get_module_config(parms->server->module_config, &svm6_module);
    conf->timeout = timeout;

    return NULL;
}

static apr_status_t redis_pool_cleanup(void *parm) {
    mod_redis_conf *conf = (mod_redis_conf *) parm;

    if (!conf)
        return APR_SUCCESS;

    /*
     * Free the REDIS connection
     */
    if (conf->lock)
        apr_thread_mutex_lock(conf->lock);

    if (conf->context) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conf->server, "Closing local REDIS connection");
        redisFree(conf->context);
        conf->context = NULL;
    }

    if (conf->masterContext) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conf->server, "Closing master REDIS connection");
        redisFree(conf->masterContext);
        conf->masterContext = NULL;
    }

    if (conf->lock)
        apr_thread_mutex_unlock(conf->lock);

    return APR_SUCCESS;
}

static void *svm6_create_config(apr_pool_t *p, server_rec *s) {
    mod_redis_conf *conf = apr_pcalloc(p, sizeof(mod_redis_conf));

    if (!conf) return NULL;

    int threaded_mpm = 0;
    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    if (threaded_mpm)
        apr_thread_mutex_create(&conf->lock, APR_THREAD_MUTEX_DEFAULT, p);

    conf->role = ROLE_UNKNOWN;
    conf->unix_socket_path = apr_pstrdup(p, "/tmp/redis.sock");
    conf->ip = NULL;
    conf->port = 0;
    conf->timeout = 1500;
    conf->server = s;
    conf->context = NULL;
    conf->scriptsha = NULL;
    conf->pool = p;

    return conf;
}


static void redis_child_init(apr_pool_t *p, server_rec *s) {
    mod_redis_conf *conf = ap_get_module_config(s->module_config, &svm6_module);
    apr_pool_cleanup_register(p, conf, redis_pool_cleanup, apr_pool_cleanup_null);
}


static void svm6_register_hooks(apr_pool_t *p) {
    // Initialize redis connections in pool_init
    ap_hook_child_init(redis_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    // This module runs AFTER mod_vulture (APR_HOOK_FIRST)
    ap_hook_header_parser(svm6_handler, NULL, NULL, APR_HOOK_FIRST+1);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmany-braces-around-scalar-init"
static const command_rec svm6_cmds[] = {
        AP_INIT_TAKE1("RedisUnixSocketPath", set_unix_socket_path, NULL, RSRC_CONF,
                      "The unix socket path of the local Redis server"),
        AP_INIT_TAKE1("RedisTimeout", set_timeout, NULL, RSRC_CONF, "The timeout for connections to Redis servers"),
        AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};
#pragma clang diagnostic pop

/* Dispatch list for API hooks */
AP_DECLARE_MODULE(svm6) = {
        STANDARD20_MODULE_STUFF,
        NULL,                  /* create per-dir    config structures */
        NULL,                  /* merge  per-dir    config structures */
        svm6_create_config,   /* create per-server config structures */
        NULL,                  /* merge  per-server config structures */
        svm6_cmds,            /* table of config file commands       */
        svm6_register_hooks    /* register hooks                      */
};
