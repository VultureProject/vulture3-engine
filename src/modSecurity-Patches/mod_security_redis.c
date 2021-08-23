/**
 * \file     mod_vulture_redis.c
 * \authors  Kevin Guillemot, Jeremie Jourdin
 * \version  1.0
 * \date     28/02/17
 * \license  GPLv3
 * \brief    Redis wrapper fonctions
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include "modsecurity.h"


/*****************************************/
/* Prototypes of internal file fonctions */
/*****************************************/

/**
 * \brief    Connect and authenticate to the Redis server
 * \details  Connect and authenticate to the Redis server with 3 Apache directives
 *           included in the server_config pointer:
 *             - redis_ip
 *             - redis_port
 *             - redis_password
 * \param    A pointer to the Apache server directives
 * \return   A redisContext if the connection and authentication succeed otherwise NULL
 */
redisContext* msc_connect_and_authenticate_to_redis(char* redis_ip, int redis_port, char* redis_password);


/***************************/
/* Definition of fonctions */
/***************************/

/**
 *  Verify the connection to redis, and perform the query
 *  Reconnect to redis if needed
 */
int msc_perform_redis_query(modsec_rec *msr, redisContext *redis_connection,
			    apr_thread_mutex_t* redis_lock, request_rec *r,
			    redisReply **reply_ptr, const char *query_format, ...) {
    int nb_retries = 0, result = 0;
    *reply_ptr = NULL;
    //
    va_list argptr;
    do {
        if (redis_lock) {
            apr_thread_mutex_lock(redis_lock);
        }
        va_start(argptr, query_format);
        if( (*reply_ptr=redisvCommand(redis_connection, query_format, argptr)) != NULL ) {
            if (redis_lock) {
                apr_thread_mutex_unlock(redis_lock);
            }
            if( (*reply_ptr)->type != REDIS_REPLY_ERROR ) {
                result = 1;
            } else {
		        msr_log(msr, 1, "msc_perform_redis_query: Error while executing command: %s", (*reply_ptr)->str);
                freeReplyObject(*reply_ptr);
                *reply_ptr = NULL;
            }
        } else {
	        msr_log(msr, 4, "msc_perform_redis_query: Connection to REDIS LOST : Retry of reconnect = %d", nb_retries);
            if( redisReconnect(redis_connection) != REDIS_OK )
		        msr_log(msr, 2, "msc_perform_redis_query: Redis connection LOST : '%s'", redis_connection->errstr);
            if (redis_lock)
                apr_thread_mutex_unlock(redis_lock);
            result = REDIS_LOST;
        }
        va_end(argptr);
        nb_retries++;
    } while( *reply_ptr == NULL && nb_retries < REDIS_MAX_RETRY );
    msr_log(msr, 9, "msc_perform_redis_query: Redis command '%s' result : %d", query_format, result);
    return result;
}

/**
 *  Connexion to the local redis server though Unix socket
 */
redisContext* msc_connect_to_redis_unix_socket(void) {
    redisContext *redis_connection = redisConnectUnix(REDIS_SOCKET);
    if( redis_connection == NULL || redis_connection->err ) {

        if( redis_connection ) {
            redisFree(redis_connection);
        }
        return NULL;
    }
    return redis_connection;
}

/**
 *  Switch the local connection to the master Redis Server for writing data
 */
redisContext* msc_connect_to_redis_master(request_rec* r, redisContext* redis_local_connection, char* redis_password) {
    // Initalize a connection to the local Redis server
    redisContext* redis_master_connection = redis_local_connection;
    redisReply* redis_reply = redisCommand(redis_local_connection, "ROLE");

    // If the local Redis server is a slave and if the local Redis server is connected to a Master:
    //   - Retrieve the master Redis IP and port from the ROLE command
    //   - Initialize a new connection to the master Redis server
    //   - Release the old connection
    if (strcmp("slave", redis_reply->element[0]->str) == 0 && strcmp("connected", redis_reply->element[3]->str) == 0) {
        // Retrieve correctly the master Redis IP and port
        
        // Create a new connection to the master Redis server and release to old connection
        redis_master_connection = msc_connect_and_authenticate_to_redis(redis_reply->element[1]->str,
                                                                    redis_reply->element[2]->integer, redis_password);
        if (redis_master_connection == NULL) {
            //redisFree(redis_local_connection);
            freeReplyObject(redis_reply);
            return NULL;
        }
        if( r != NULL ) {
	  ap_log_error_(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Mod_security::Connected to slave -> release actual connection and connect to Master: %s:%lld",
			redis_reply->element[1]->str, redis_reply->element[2]->integer);
        }
    }

    freeReplyObject(redis_reply);
    return redis_master_connection;
}

/**
 *  Connection and authentication to the Redis server
 */
redisContext* msc_connect_and_authenticate_to_redis(char* redis_ip, int redis_port, char* redis_password) {
    // Connection to Redis
    // return NULL if the connection failed
    redisContext* redis_connection = redisConnect(redis_ip, redis_port);
    if (redis_connection == NULL || redis_connection->err) {
        if (redis_connection) {
            redisFree(redis_connection);
        }
        return NULL;
    }

    /*
    !!! Not used for the authentication is in plain text (not SSL for the moment)!!!
    // Authentication to Redis
    // return NULL if the authentication failed
    redisReply* redis_reply = redisCommand(redis_connection, "AUTH %s", redis_password);
    if (redis_reply->type == REDIS_REPLY_ERROR) {
        freeReplyObject(redis_reply);
        redisFree(redis_connection);

        return NULL;
    }*/

    return redis_connection;
}

/**
 *  Retrieve the Redis IP value from the directive
 */
const char* msc_get_redis_ip(cmd_parms* cmd, void* cfg, const char* arg) {
    msc_server_config *conf = (msc_server_config *) ap_get_module_config(cmd->server->module_config, &security2_module);
    if (conf)
	strncpy(conf->redis_ip, arg, REDIS_IP_SIZE);
    return NULL;
}

/**
 *  Retrieve the Redis port value from the directive
 */
const char* msc_get_redis_port(cmd_parms* cmd, void* cfg, const char* arg) {
    msc_server_config *conf = (msc_server_config *) ap_get_module_config(cmd->server->module_config, &security2_module);
    if (conf)
	conf->redis_port = atoi(arg);
    return NULL;
}

/**
 *  Retrieve the Redis password from the directive (not used for the moment because useless)
 */
const char* msc_get_redis_password(cmd_parms* cmd, void* cfg, const char* arg) {
    msc_server_config *conf = (msc_server_config *) ap_get_module_config(cmd->server->module_config, &security2_module);
    if (conf)
	strncpy(conf->redis_password, arg, REDIS_PASSWORD_SIZE);
    return NULL;
}