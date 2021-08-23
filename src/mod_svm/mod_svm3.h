/**
 * \file     mod_svm3.h
 * \author   Kevin Guillemot
 * \version  0.1
 * \date     12/07/16
 * \license  GPLv3
 * \brief    Header of the mod_svm3.c program
 */

#include "svm_util.h"

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

    char uris[MAX_URIS];
} svm_config;


/************************/
/* Functions signatures */
/************************/

const char* svm3_activated(cmd_parms *cmd, void *cfg, int arg);
const char* svm3_nrclass(cmd_parms *cmd, void *cfg, const char *arg);
const char* svm3_SVdims(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
const char* svm3_SV(cmd_parms *cmd, void *cfg, const char *arg);
const char* svm3_supportdims(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
const char* svm3_support(cmd_parms *cmd, void *cfg, const char *arg);
const char* svm3_SVcoef(cmd_parms *cmd, void *cfg, const char *arg);
const char* svm3_rho(cmd_parms *cmd, void *cfg, const char *arg);
const char* svm3_nSV(cmd_parms *cmd, void *cfg, const char *arg);
const char* svm3_SVcoefstrides(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
const char* svm3_gamma(cmd_parms *cmd, void *cfg, const char *arg);
const char* svm3_uris(cmd_parms *cmd, void *cfg, const char *arg);
void *create_conf(apr_pool_t *pool, char* context);
void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD);

static const command_rec svm_directives[] = {
    AP_INIT_FLAG("svm3", svm3_activated, NULL, ACCESS_CONF, "Is the SVM On or Off"),
    AP_INIT_TAKE1("svm3_nrclass", svm3_nrclass, NULL, ACCESS_CONF, "Attribute 'nr_class' for svm3"),
    AP_INIT_TAKE2("svm3_SVdims", svm3_SVdims, NULL, ACCESS_CONF, "Attributes 'SV_dims' for svm3"),
    AP_INIT_TAKE1("svm3_SV", svm3_SV, NULL, ACCESS_CONF, "Attribute 'SV' for svm3"),
    AP_INIT_TAKE2("svm3_supportdims", svm3_supportdims, NULL, ACCESS_CONF, "Attributes 'support_dims' for svm3"),
    AP_INIT_TAKE1("svm3_support", svm3_support, NULL, ACCESS_CONF, "Attribute 'support' for svm3"),
    AP_INIT_TAKE1("svm3_SVcoef", svm3_SVcoef, NULL, ACCESS_CONF, "Attribute 'sv_coef' for svm3"),
    AP_INIT_TAKE1("svm3_rho", svm3_rho, NULL, ACCESS_CONF, "Attribute 'rho' for svm3"),
    AP_INIT_TAKE1("svm3_nSV", svm3_nSV, NULL, ACCESS_CONF, "Attribute 'nSV' for svm3"),
    AP_INIT_TAKE2("svm3_SVcoefstrides", svm3_SVcoefstrides, NULL, ACCESS_CONF, "Attributes 'sv_coef_strides' for svm3"),
    AP_INIT_TAKE1("svm3_gamma", svm3_gamma, NULL, ACCESS_CONF, "Attributes 'gamma' for svm3"),
    AP_INIT_TAKE1("svm3_uris", svm3_uris, NULL, ACCESS_CONF, "Attribute 'uris' for svm3"),
    {NULL}
};


/*------------------*/
/* Module functions */
/*------------------*/

static void register_hooks(apr_pool_t *poll);
static int fixups_svm3(request_rec *r);
static int nb_words_split_comma(char *uri);
