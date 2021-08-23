/**
 * \file     mod_svm2.h
 * \author   Kevin Guillemot
 * \version  0.1
 * \date     11/07/16
 * \license  GPLv3
 * \brief    Header of the mod_svm2.c program
 */

#ifndef VULTURE_ENGINE_MOD_SVM2_H
#define VULTURE_ENGINE_MOD_SVM2_H


/*************************/
/* Inclusion of .H files */
/*************************/

#include "svm_util.h"


/**************/
/* Structures */
/**************/

/**
 * \struct  svm_config
 *          Regroup all directory directives
 *              and needed attributes in a structure
 */
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

    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
    /* <Directory> & <Location> specific directives functions  */
    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

        /*-----------------------------------*/
        /* Creation and merging of structure */
        /*-----------------------------------*/

/**
 * \brief    Init a proxy configuration
 * \details  Init a proxy configuration with default values
 * \param    pool A pointer to the memory allocated for the configuration
 * \param    srv  A pointer to the server configuration
 * \return   A pointer to the new configuration
 */
void *create_conf(apr_pool_t *pool, char* context);

/**
 * \brief    Merge 2 proxy configurations
 * \details  Merge 2 proxy configuration directives, like general configuration and vhost specific configuration
 *              with conflict management
 * \param    pool   A pointer to the memory allocated for the configuration
 * \param    BASE   A pointer to the server configuration
 * \param    ADD    A pointer to the vhost configuration
 * \return   A pointer to the merged configuration
 */
void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD);


        /*--------------------------------*/
        /* Fill structure with directives */
        /*--------------------------------*/

/**
 * \brief    Retrieve "svm2" directive
 * \details  Retrieve the value of the "svm2" directive in httpd.conf (On or Off)
 * \param    cmd    A pointer to the list of directives
 * \param    cfg    A pointer to the configuration
 * \param    arg    The argument retrieve from the directive
 * \return   NULL if success, the error message otherwise
 */
const char* svm2_activated(cmd_parms *cmd, void *cfg, int arg);

/**
 * \brief    Retrieve "svm2_nrclass"
 * \details  Retrieve the nr_class attribute of the SVM in httpd.conf
 */
const char* svm2_nrclass(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "svm2_SVdims"
 * \details  Retrieve the SVdims attribute of the SVM in httpd.conf
 */
const char* svm2_SVdims(cmd_parms* cmd, void* cfg, const char* arg1, const char *arg2);

/**
 * \brief    Retrieve "svm2_SV"
 * \details  Retrieve the SV attribute of the SVM in httpd.conf
 */
const char* svm2_SV(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "svm2_supportdims"
 * \details  Retrieve the supportdims attribute of the SVM in httpd.conf
 */
const char* svm2_supportdims(cmd_parms* cmd, void* cfg, const char *arg1, const char *arg2);

/**
 * \brief    Retrieve "svm2_support"
 * \details  Retrieve the support attribute of the SVM in httpd.conf
 */
const char* svm2_support(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "svm2_SVcoef"
 * \details  Retrieve the SVcoef attribute of the SVM in httpd.conf
 */
const char* svm2_SVcoef(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "svm2_rho"
 * \details  Retrieve the rho attribute of the SVM in httpd.conf
 */
const char* svm2_rho(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "svm2_nSV"
 * \details  Retrieve the nSV attribute of the SVM in httpd.conf
 */
const char* svm2_nSV(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "svm2_SVcoefstrides"
 * \details  Retrieve the SVcoefstrides attribute of the SVM in httpd.conf
 */
const char* svm2_SVcoefstrides(cmd_parms* cmd, void* cfg, const char *arg1, const char *arg2);

/**
 * \brief    Retrieve "svm2_gamma"
 * \details  Retrieve the gamma attribute of the SVM in httpd.conf
 */
const char* svm2_gamma(cmd_parms* cmd, void* cfg, const char *arg);

/**
 * \brief    Retrieve "svm2_uris"
 * \details  Retrieve the uris attribute of the SVM in httpd.conf
 */
const char* svm2_uris(cmd_parms* cmd, void* cfg, const char *arg);


/**
 * List all directives and associate their name with their handler
 */
static const command_rec svm_directives[] = {
    AP_INIT_FLAG("svm2", svm2_activated, NULL, ACCESS_CONF, "Is the SVM On or Off"),
    AP_INIT_TAKE1("svm2_nrclass", svm2_nrclass, NULL, ACCESS_CONF, "Attribute 'nr_class' for svm2"),
    AP_INIT_TAKE2("svm2_SVdims", svm2_SVdims, NULL, ACCESS_CONF, "Attributes 'SV_dims' for svm2"),
    AP_INIT_TAKE1("svm2_SV", svm2_SV, NULL, ACCESS_CONF, "Attribute 'SV' for svm2"),
    AP_INIT_TAKE2("svm2_supportdims", svm2_supportdims, NULL, ACCESS_CONF, "Attributes 'support_dims' for svm2"),
    AP_INIT_TAKE1("svm2_support", svm2_support, NULL, ACCESS_CONF, "Attribute 'support' for svm2"),
    AP_INIT_TAKE1("svm2_SVcoef", svm2_SVcoef, NULL, ACCESS_CONF, "Attribute 'sv_coef' for svm2"),
    AP_INIT_TAKE1("svm2_rho", svm2_rho, NULL, ACCESS_CONF, "Attribute 'rho' for svm2"),
    AP_INIT_TAKE1("svm2_nSV", svm2_nSV, NULL, ACCESS_CONF, "Attribute 'nSV' for svm2"),
    AP_INIT_TAKE2("svm2_SVcoefstrides", svm2_SVcoefstrides, NULL, ACCESS_CONF, "Attributes 'sv_coef_strides' for svm2"),
    AP_INIT_TAKE1("svm2_gamma", svm2_gamma, NULL, ACCESS_CONF, "Attributes 'gamma' for svm2"),
    AP_INIT_TAKE1("svm2_uris", svm2_uris, NULL, ACCESS_CONF, "Attribute 'uris' for svm2"),
    {NULL}
};


/*------------------*/
/* Module functions */
/*------------------*/

static void register_hooks(apr_pool_t *poll);
static int fixups_svm2(request_rec *r);


#endif // VULTURE_ENGINE_MOD_SVM2_H
