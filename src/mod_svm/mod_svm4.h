/*                       _                           _  _
 *   _ __ ___   ___   __| |    _____   ___ __ ___   | || |
 *  | '_ ` _ \ / _ \ / _` |   / __\ \ / / '_ ` _ \  | || |_
 *  | | | | | | (_) | (_| |   \__ \\ V /| | | | | | |__   _|
 *  |_| |_| |_|\___/ \__,_|___|___/ \_/ |_| |_| |_|    |_|
 *                       |_____|
 *  Copyright (c) 2016 Kevin Guillemot & Baptiste de Magnienville
 *  Released under the GPLv3
 */

#ifndef __MOD_SVM4__
#define __MOD_SVM4__

#include "svm_util.h"

/*************/
/* Constants */
/*************/

#define INPUT_FILTER "SVM4_IN"
#define OUTPUT_FILTER "SVM4_OUT"


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

static const char* svm4_activated(cmd_parms *cmd, void *cfg, int arg);
static const char* svm4_nrclass(cmd_parms *cmd, void *cfg, const char *arg);
static const char* svm4_SVdims(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
static const char* svm4_SV(cmd_parms *cmd, void *cfg, const char *arg);
static const char* svm4_supportdims(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
static const char* svm4_support(cmd_parms *cmd, void *cfg, const char *arg);
static const char* svm4_SVcoef(cmd_parms *cmd, void *cfg, const char *arg);
static const char* svm4_rho(cmd_parms *cmd, void *cfg, const char *arg);
static const char* svm4_nSV(cmd_parms *cmd, void *cfg, const char *arg);
static const char* svm4_SVcoefstrides(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
static const char* svm4_gamma(cmd_parms *cmd, void *cfg, const char *arg);
static const char* svm4_maxsize(cmd_parms *cmd, void *cfg, const char *arg);
static void *create_conf(apr_pool_t *pool, char* context);
static void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD);
static const command_rec svm_directives[] = {
        AP_INIT_FLAG("svm4", svm4_activated, NULL, ACCESS_CONF, "Is the SVM4 On or Off"),
        AP_INIT_TAKE1("svm4_nrclass", svm4_nrclass, NULL, ACCESS_CONF, "Attribute 'nr_class' for svm4"),
        AP_INIT_TAKE2("svm4_SVdims", svm4_SVdims, NULL, ACCESS_CONF, "Attributes 'SV_dims' for svm4"),
        AP_INIT_TAKE1("svm4_SV", svm4_SV, NULL, ACCESS_CONF, "Attribute 'SV' for svm4"),
        AP_INIT_TAKE2("svm4_supportdims", svm4_supportdims, NULL, ACCESS_CONF, "Attributes 'support_dims' for svm4"),
        AP_INIT_TAKE1("svm4_support", svm4_support, NULL, ACCESS_CONF, "Attribute 'support' for svm4"),
        AP_INIT_TAKE1("svm4_SVcoef", svm4_SVcoef, NULL, ACCESS_CONF, "Attribute 'sv_coef' for svm4"),
        AP_INIT_TAKE1("svm4_rho", svm4_rho, NULL, ACCESS_CONF, "Attribute 'rho' for svm4"),
        AP_INIT_TAKE1("svm4_nSV", svm4_nSV, NULL, ACCESS_CONF, "Attribute 'nSV' for svm4"),
        AP_INIT_TAKE2("svm4_SVcoefstrides", svm4_SVcoefstrides, NULL, ACCESS_CONF, "Attributes 'sv_coef_strides' for svm4"),
        AP_INIT_TAKE1("svm4_gamma", svm4_gamma, NULL, ACCESS_CONF, "Attributes 'gamma' for svm4"),
        AP_INIT_TAKE1("svm4_maxsize", svm4_maxsize, NULL,  ACCESS_CONF, "Max size of bytes received"),
        { NULL }
};


/*------------------*/
/* Module functions */
/*------------------*/

static void register_hooks(apr_pool_t *poll);
static void insert_filters( request_rec *r );
static apr_status_t svm4_handler(request_rec *r);
static apr_status_t svm4_input_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode,
                                      apr_read_type_e block, apr_off_t readbytes);
static apr_status_t svm4_output_filter(ap_filter_t *f, apr_bucket_brigade *in);

#endif
