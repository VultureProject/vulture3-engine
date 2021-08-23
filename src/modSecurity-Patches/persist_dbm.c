/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2013 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#include "persist_dbm.h"
#include "apr_sdbm.h"
#include "modsecurity.h"

#include <hiredis.h>

/**
 *
 */
static apr_table_t *collection_retrieve_ex(modsec_rec *msr, const char *col_name,
					   const char *col_key)
{

    /**
     * Collection name is col_name
     * The KEY is col_key
     *
     * Here we need to fetch all (var=name) tuples from Redis.
     * These values are stored under KEYS col_name:col_key:variable_name
     * Once fetched, add them into an APR_table collection
     *
     */

    unsigned long long cur = 0;
    unsigned int i;
    
    char *key = NULL;
    char *var = NULL;

    msc_server_config *conf = ap_get_module_config(msr->r->server->module_config, &security2_module);
    msr_log(msr, 9, "collection_retrieve_ex: Try to retrieve data for collection '%s' and key '%s'", col_name, col_key);

    apr_table_t *col = NULL;
    col = apr_table_make(msr->mp, 32);
    if (col == NULL) return NULL;

    /* Persistence code will need to know the name of the key, because it is part of the redis index. */
    msc_string *var_struct__name = apr_pcalloc(msr->mp, sizeof(msc_string));
    var_struct__name->name = "__name";
    var_struct__name->name_len = (unsigned int)strlen(var_struct__name->name);
    var_struct__name->value_len = (unsigned int)strlen(col_name);
    var_struct__name->value = apr_pstrdup(msr->mp, col_name);
    apr_table_setn(col, "__name", (void *)var_struct__name);

    /* Persistence code will need to know the name of the collection, because it is part of the redis index */
    msc_string *var_struct__key = apr_pcalloc(msr->mp, sizeof(msc_string));
    var_struct__key->name = "__key";
    var_struct__key->name_len = (unsigned int)strlen(var_struct__key->name);
    var_struct__key->value_len = (unsigned int)strlen(col_key);
    var_struct__key->value = apr_pstrdup(msr->mp, col_key);
    apr_table_setn(col, "__key", (void *)var_struct__key);

    int nb_key = 0;
    char all_keys[MAX_VAR_PER_COL][MAX_REDIS_KEY_SIZE];

    /* Retrieve all possible variables from modSecurity and vulture's collections */
    if ((strncmp(col_name, "global\0", 7) == 0) && (strncmp(col_key, "global\0", 7) == 0)) {
        nb_key=1;
        strncpy(all_keys[0], "global:global:alerted_970018_iisDefLoc\0", 39);
    }
    else if (strncmp(col_name, "ip\0", 3) == 0) {
        nb_key=8;
        *stpncpy( stpncpy( stpncpy( all_keys[0], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("dos_block_counter")-1),
                  ":dos_block_counter", strlen(":dos_block_counter")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[1], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("dos_block_flag")-1),
                  ":dos_block_flag", strlen(":dos_block_flag")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[2], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("dos_counter")-1),
                  ":dos_counter", strlen(":dos_counter")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[3], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("dos_burst_counter")-1),
                  ":dos_burst_counter", strlen(":dos_burst_counter")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[4], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("dos_block")-1),
                  ":dos_block", strlen(":dos_block")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[5], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("reput_block_reason")-1),
                  ":reput_block_reason", strlen(":reput_block_reason")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[6], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("reput_block_flag")-1),
                  ":reput_block_flag", strlen(":reput_block_flag")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[7], "ip:", strlen("ip:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("ip:")-strlen("previous_rbl_check")-1),
                  ":previous_rbl_check", strlen(":previous_rbl_check")) = 0x00;
    }
    else if (strncmp(col_name, "col_ua\0", 7) == 0) {
        nb_key=1;
        *stpncpy( stpncpy( stpncpy( all_keys[0], "col_ua:", strlen("col_ua:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("col_ua:")-strlen(":ua")-1),
                  ":ua", strlen(":ua")) = 0x00;
    }
    else if (strncmp(col_name, "col_csrf\0", 9) == 0) {
        nb_key=1;
        *stpncpy( stpncpy( stpncpy( all_keys[0], "col_csrf:", strlen("col_csrf:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("col_csrf:")-strlen(":token")-1),
                  ":token", strlen(":token")) = 0x00;
    }
    else if (strncmp(col_name, "col_session\0", 12) == 0) {
        nb_key=1;
        *stpncpy( stpncpy( stpncpy( all_keys[0], "col_session:", strlen("col_session:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("col_session:")-strlen(":sid")-1),
                  ":sid", strlen(":sid")) = 0x00;
    }
    else if (strncmp(col_name, "custom\0", 7) == 0) {
        nb_key=8;
        *stpncpy( stpncpy( stpncpy( all_keys[0], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_1")-1),
                  ":custom_var_1", strlen(":custom_var_1")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[1], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_2")-1),
                  ":custom_var_2", strlen(":custom_var_2")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[2], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_3")-1),
                  ":custom_var_3", strlen(":custom_var_3")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[3], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_4")-1),
                  ":custom_var_4", strlen(":custom_var_4")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[4], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_5")-1),
                  ":custom_var_5", strlen(":custom_var_5")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[5], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_6")-1),
                  ":custom_var_6", strlen(":custom_var_6")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[6], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_7")-1),
                  ":custom_var_7", strlen(":custom_var_7")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[7], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_8")-1),
                  ":custom_var_8", strlen(":custom_var_8")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[8], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_9")-1),
                  ":custom_var_9", strlen(":custom_var_9")) = 0x00;
        *stpncpy( stpncpy( stpncpy( all_keys[9], "custom:", strlen("custom:")),
                           col_key, MAX_REDIS_KEY_SIZE-strlen("custom:")-strlen("custom_var_10")-1),
                  ":custom_var_10", strlen(":custom_var_10")) = 0x00;
    }

    msr_log(msr, 9, "collection_retrieve_ex: Number of keys to retrieve from Redis : %d", nb_key);

    if (nb_key>0) {

        /* NOW REDIS CALL MGET key1 key2 key3 ... */
        char mget_command[MAX_VAR_PER_COL*MAX_REDIS_KEY_SIZE+MAX_VAR_PER_COL*1+strlen("MGET")+1] = {0};
        char *tmp_ptr = stpncpy(mget_command, "MGET", strlen("MGET"));
        for (i=0; i<nb_key; i++) {
            tmp_ptr = stpncpy(tmp_ptr, " ", 1);
            tmp_ptr = stpncpy(tmp_ptr, all_keys[i], MAX_REDIS_KEY_SIZE);
        }
        tmp_ptr = 0x00;

        redisReply* reply = NULL;
        if (msc_perform_redis_query(msr, conf->redis_slave_conn, conf->redis_local_lock,
                        msr->r, &reply, mget_command) == REDIS_LOST) {
            msr_log(msr, 1, "collection_retrieve_ex: Connection to REDIS lost");
            freeReplyObject(reply);
            return NULL;
        }

        for ( i=0; i<reply->elements; ++i ) {
            if (reply->element[i]->str != NULL) {
                msc_string *var_struct = apr_pcalloc(msr->mp, sizeof(msc_string));

                /* Set the variable name */
                var_struct->name = strndup(strrchr(all_keys[i], ':')+1, MAX_REDIS_KEY_SIZE);
                var_struct->name_len = (unsigned int) strlen(var_struct->name);

                /* Retrieve the value */
                var_struct->value = strndup(reply->element[i]->str, MAX_REDIS_KEY_SIZE);
                var_struct->value_len = (unsigned int) strlen(var_struct->value);

                msr_log(msr, 9, "collection_retrieve_ex: Adding element to table : '%s': '%s'", var_struct->name,
                        var_struct->value);
                /* Load raw redis data in apr_table structure */
                apr_table_addn(col, var_struct->name, (void *) var_struct);
            }
        }
        if (reply != NULL)
            freeReplyObject(reply);
    }

    msr_log(msr, 9, "collection_retrieve_ex: Iterated on %d elements", apr_table_elts(col)->nelts - 2);


    return col;
}

/**
 *
 */
apr_table_t *collection_retrieve(modsec_rec *msr, const char *col_name,
    const char *col_key) {
    apr_time_t time_before = apr_time_now();
    apr_table_t *rtable = NULL;
    
    rtable = collection_retrieve_ex(msr, col_name, col_key);
    
    msr->time_storage_read += apr_time_now() - time_before;
    
    return rtable;
}

/**
 *
 */
int collection_store(modsec_rec *msr, apr_table_t *col) {
    msc_server_config *conf = ap_get_module_config(msr->r->server->module_config, &security2_module);

    /* COLLECTION'S NAME: This has been set from initcol */
    msc_string *var_name = (msc_string *)apr_table_get(col, "__name");
    if (var_name == NULL) {
        msr_log(msr, 9, "collection_store: Declining because collection name is NULL");
        return -1;
    }

    /* COLLECTION'S KEY: This has been set from initcol */
    msc_string *var_key = (msc_string *)apr_table_get(col, "__key");
    if (var_key == NULL) {
        msr_log(msr, 9, "collection_store: Declining because key is NULL");
        return -1;
    }

    msr_log(msr, 9, "collection_store called for col '%s' and key '%s'", var_name->value, var_key->value);

    const apr_array_header_t *arr = apr_table_elts(col);
    apr_table_entry_t *te = (apr_table_entry_t *)arr->elts;
    int i;
    for (i = 0; i < arr->nelts; i++) {
        msc_string *var = (msc_string *)te[i].val;

    	//The variable to store is var->name
    	//It's value is var->value

    	//No need to store that in redis, this is use internaly only
        if (strcmp(var->name, "__name") == 0)
            continue;
        if (strcmp(var->name, "__key") == 0)
            continue;

        // __expire_<VAR_NAME>
        if (strncmp(var->name, "__expire_", 9) == 0) {
            char* var_name_to_expire = var->name + 9;
            msr_log(msr, 9, "collection_store: EXPIRE %s:%s:%s %s", var_name->value, var_key->value, var_name_to_expire, var->value);

            redisReply* redis_reply_expire_at = NULL;
            if (msc_perform_redis_query(msr, conf->redis_master_conn, conf->redis_master_lock,
                        msr->r, &redis_reply_expire_at, "EXPIRE %s:%s:%s %s",
                        var_name->value, var_key->value,
                        var_name_to_expire, var->value) == REDIS_LOST) {
                msr_log(msr, 1, "collection_store: Connection to REDIS lost");
                return -1;
            }
            freeReplyObject(redis_reply_expire_at);
            continue;
        }

        msr_log(msr, 9, "collection_store: SET %s:%s:%s %s EX 3600", var_name->value, var_key->value, var->name, var->value);

        redisReply* redis_reply = NULL;
        if (msc_perform_redis_query(msr, conf->redis_master_conn, conf->redis_master_lock,
                        msr->r, &redis_reply, "SET %s:%s:%s %s EX 3600",
                        var_name->value, var_key->value, var->name,
                        var->value) == REDIS_LOST) {
            msr_log(msr, 1, "collection_store: Connection to REDIS lost");
            return -1;
        }
        if( redis_reply != NULL )
            freeReplyObject(redis_reply);
    }

    return 0;

}

