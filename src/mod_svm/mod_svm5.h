/*                       _                           ____
 *   _ __ ___   ___   __| |    _____   ___ __ ___   | ___|
 *  | '_ ` _ \ / _ \ / _` |   / __\ \ / / '_ ` _ \  |___ \
 *  | | | | | | (_) | (_| |   \__ \\ V /| | | | | |  ___) |
 *  |_| |_| |_|\___/ \__,_|___|___/ \_/ |_| |_| |_| |____/
 *                       |_____|
 *  Copyright (c) 2016 Kevin Guillemot & Baptiste de Magnienville
 *  Released under the GPLv3
 */

#ifndef __MOD_SVM5__
#define __MOD_SVM5__

#include "svm_util.h"

/*************/
/* Constants */
/*************/

#define INPUT_FILTER "SVM5_IN"
#define OUTPUT_FILTER "SVM5_OUT"


/**************/
/* Structures */
/**************/

typedef struct svm_config {
    int activated;
    int nr_class;
    long int SV_dims[2];
    double *SV;
    long int support_dims[2];
    int *support;
    double *sv_coef;
    double rho[1];
    int *nSV;
    long int sv_coef_strides[2];
    double gamma;
    struct svm_parameter *param;
    struct svm_model *model;

    int nr_class_OK;
    int SV_dims_OK;
    int SV_OK;
    int support_dims_OK;
    int support_OK;
    int sv_coef_OK;
    int rho_OK;
    int nSV_OK;
    int sv_coef_strides_OK;
    int gamma_OK;
    int svm_created;

    apr_size_t max_size;
} svm_config;


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

static void register_hooks(apr_pool_t *poll);
static void insert_filters( request_rec *r );
static apr_status_t svm5_handler(request_rec *r);
static apr_status_t svm5_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                               ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
static apr_status_t svm5_output_filter(ap_filter_t *f, apr_bucket_brigade *in);
static int get_headers_out_len(request_rec *r);
static apr_size_t get_keep_alive_header_len(request_rec *r);

#endif
