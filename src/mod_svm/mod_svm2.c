/**
 * \file     mod_svm2.c
 * \author   Kevin Guillemot
 * \version  0.1
 * \date     11/07/16
 * \license  GPLv3
 * \brief    Module to manage SVM calculs (svm2) and access to the resources protected by Vulture
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include "mod_svm2.h"


/***************/
/* Source code */
/***************/

/**
 *  Define the functions used to retrieve all the server and directory directives and for merging them
 */
module AP_MODULE_DECLARE_DATA svm2_module;
AP_DECLARE_MODULE(svm2) = {
        STANDARD20_MODULE_STUFF,
        create_conf,                /* create per-directory config structure */
        merge_conf,                 /* merge per-directory config structures */
        NULL,                       /* create per-server config structure */
        NULL,                       /* merge per-server config structures */
        svm_directives,             /* command apr_table_t */
        register_hooks
};


/**
 *  Integration of the module in the request management process
 *  Actually placed in the post_parse_request
 */
static void register_hooks(apr_pool_t *p) {
    ap_hook_fixups(fixups_svm2, NULL, NULL, APR_HOOK_REALLY_FIRST);
}


/**
 *  Create 'model' and 'param' attributes of svm_config struct with data retrieved from directives
 */
static int create_svm(svm_config *svm_cfg, cmd_parms *cmd) {
    // Verify if each directive is specified in application config file
    if (svm_cfg->activated && svm_cfg->nr_class_OK && svm_cfg->SV_dims_OK && svm_cfg->SV_OK &&
        svm_cfg->support_dims_OK && svm_cfg->support_OK && svm_cfg->sv_coef_OK && svm_cfg->rho_OK && svm_cfg->nSV_OK &&
        svm_cfg->sv_coef_strides_OK && svm_cfg->gamma_OK && !svm_cfg->svm_created) {
        // Allocate the 'param' attribute of the svm_config structure
        svm_cfg->param = (struct svm_parameter *) apr_pcalloc(cmd->pool, sizeof(struct svm_parameter));

        // Define all variables used in SVM
        int svm_type = 2;
        int kernel_type = 2;
        int degree = 3;
        double coef0 = 0;
        double cache_size = 200;
        int probability = 0;
        int nr_weight = 0;
        char *weight_label = NULL;
        char *weight = NULL;
        double C = 0;
        double epsilon = 0.1;
        int max_iter = 0;
        double nu = 0.5;
        int shrinking = 0;
        double tol = 0.1;
        int random_seed = -1;

        set_parameter(svm_cfg->param, svm_type, kernel_type, degree, svm_cfg->gamma, coef0, nu, cache_size, C, tol,
                      epsilon,
                      shrinking, probability, nr_weight, weight_label, weight, max_iter, random_seed);

        svm_cfg->model = set_model(svm_cfg->param, svm_cfg->nr_class, (char *) svm_cfg->SV,
                                   (long int *) svm_cfg->SV_dims, (char *) svm_cfg->support,
                                   (long int *) svm_cfg->support_dims, (long int *) svm_cfg->sv_coef_strides,
                                   (char *) svm_cfg->sv_coef, (char *) svm_cfg->rho, (char *) svm_cfg->nSV, NULL, NULL);

        return 1;
    }
    return 0;
}


/**
 *  Calculate the number of words splitted by "/" in uri
**/
static int calcul_nb_words_uri(char *uri, int length) {
    int result = 0;
    int cpt = 0;

    while (cpt < length - 1 && *(uri + 1) != '\0') {
        if (*(uri + cpt) == '/' && *(uri + cpt + 1) != '/') {
            result++;
        }
        cpt++;
    }

    return result;
}


/**
 *  Implementation of the mod_svm2's logic
 *  Contains all logging commands, directives, datas and sessions management
 */
static int fixups_svm2(request_rec *r) {
    svm_config *config = (svm_config *) ap_get_module_config(r->per_dir_config, &svm2_module);

    if (config->activated != 1 || config->svm_created != 1) {
        AP_LOG_DEBUG(r, "mod_svm2::Fixups: Application configuration loaded: Activated:%s Created:%s'",
                       config->activated ? "Yes" : "No", config->svm_created ? "Yes" : "No");
        return DECLINED;
    }

    // If the requested uri is '/' => don't perform Levenstein
    if (strncmp(r->uri, "/", 3) == 0) {
        AP_LOG_DEBUG(r, "mod_svm2::Fixups: Requested uri:'%s' => no need to perform svm.", r->uri);
        return DECLINED;
    }

    int cpt = 0;

    // Do a copy of r->uri and config->uris to not modify original with strtok_r
    char *uri = apr_palloc(r->pool, (strlen(r->unparsed_uri) + 1) * sizeof(char));
    strncpy(uri, r->unparsed_uri, strlen(r->unparsed_uri) + 1);
    char *uris = apr_palloc(r->pool, (strlen(config->uris) + 1) * sizeof(char));
    strncpy(uris, config->uris, strlen(config->uris) + 1);

    // Get the number of words splitting config->uris & r->uri by '/'
    int len_uri = calcul_nb_words_uri(uri, (int) strlen(uri));
    int len_uris = calcul_nb_words_uri(uris, (int) strlen(uris));

    AP_LOG_TRACE1(r, "mod_svm2::Fixups: Requested uri:'%s' | Number of words:%d", uri, len_uri);

    // Set X shape for svm_predict
    long int X_shape[2] = {len_uri, 2};

    // Allocate X data from X shape
    double *X_data = apr_palloc(r->pool, len_uri * 2 * sizeof(double));

    // Allocate result tab
    double *dec_values = apr_palloc(r->pool, len_uri * sizeof(double));


    // Define temporary variables
    char *parsed_uris = NULL;
    char *parsed_uri = NULL;
    char *tmp_uri = NULL;
    char *tmp_uris = NULL;
    char *tmp = NULL;
    char *tmp2 = NULL;
    int cpt2 = 0;
    apr_size_t sum = 0, tmp_sum = 0, cpt_sum = 0;

    // For each word of r->uri
    tmp_uri = uri;
    do {
        // Split r->uri by '/'
        parsed_uri = strtok_r(tmp_uri, "/", &tmp);
        if (parsed_uri == NULL) {
            break;
        }
        cpt2 = 0;
        sum = 0;
        tmp2 = NULL;
        // Re-copy original uri in temp uri cause 'strtok_r' modifies it
        strncpy(uris, config->uris, strlen(config->uris));
        // Save pointer
        tmp_uris = uris;
        do {
            // Split config->uris by '/'
            parsed_uris = strtok_r(tmp_uris, "/", &tmp2);
            if (parsed_uris == NULL) {
                break;
            }
            // Sum the levenshtein distance of each word of uri/uris
            tmp_sum = levenshtein(parsed_uri, parsed_uris, strlen(parsed_uri), strlen(parsed_uris));
            AP_LOG_TRACE3(r, "mod_svm2::Fixups: Calculating Levenstein distance('%s' , '%s') = %lu", parsed_uri, parsed_uris,
                          tmp_sum);
            sum += tmp_sum;
            cpt_sum++;

            tmp_uris = NULL;
            cpt2++;
        } while ( cpt2 <= len_uris );

        // Set X datas with levenstein distances calculated
        X_data[cpt * 2] = ((double) sum / (double) len_uris);
        AP_LOG_TRACE2(r, "mod_svm2::Fixups: X_data[%d] = %lu / %d = %f ", cpt * 2, sum, len_uris, X_data[cpt * 2]);
        X_data[cpt * 2 + 1] = (double) strlen(parsed_uri);
        AP_LOG_TRACE2(r, "mod_svm2::Fixups: parsed_uri = %s ", parsed_uri);
        AP_LOG_TRACE2(r, "mod_svm2::Fixups: X_data[%d] = %lu ", cpt * 2 + 1, strlen(parsed_uri));

        tmp_uri = NULL;
        cpt++;
    } while ( cpt <= len_uri);

    // Perform svm_predict calcul
    AP_LOG_TRACE2(r, "mod_svm2::Fixups: Predicting SVM...");
    int res = copy_predict((char *) X_data, config->model, X_shape, (char *) dec_values);
    AP_LOG_TRACE1(r, "mod_svm2::Fixups: SVM predict return code:%s", res < 0 ? "NOK" : "OK");

    // Retrieve and verify results (1 or -1)
    cpt = 0;
    while (cpt < len_uri) {
        AP_LOG_TRACE1(r, "mod_svm2::Fixups: Dec_values[%d]:%d", cpt, (int) dec_values[cpt]);
        // If svm_predict returns -1 => return HTTP_FORBIDDEN
        if ((int) dec_values[cpt] == -1) {
            AP_LOG_INFO(r, "mod_svm2::Fixups: Suspicious request '%s' !", r->unparsed_uri);
            apr_table_set(r->subprocess_env, "svm2", "1");
        }
        cpt++;
    }

    // Pass to the following hook
    return DECLINED;
}


/**
 *  Define the application configuration (in vhost section)
 */
void *create_conf(apr_pool_t *pool, char *context) {
    svm_config *svm_cfg = (svm_config *) apr_pcalloc(pool, sizeof(svm_config));

    if (svm_cfg) {
        svm_cfg->activated = 0;
        svm_cfg->nr_class = 0;
        svm_cfg->SV_dims[0] = 0;
        svm_cfg->SV_dims[1] = 0;
        svm_cfg->support_dims[0] = 0;
        svm_cfg->support_dims[1] = 0;
        svm_cfg->rho[0] = 0;
        svm_cfg->sv_coef_strides[0] = 0;
        svm_cfg->sv_coef_strides[1] = 0;
        svm_cfg->gamma = 0;

        svm_cfg->nr_class_OK = 0;
        svm_cfg->SV_dims_OK = 0;
        svm_cfg->SV_OK = 0;
        svm_cfg->support_dims_OK = 0;
        svm_cfg->support_OK = 0;
        svm_cfg->sv_coef_OK = 0;
        svm_cfg->rho_OK = 0;
        svm_cfg->nSV_OK = 0;
        svm_cfg->sv_coef_strides_OK = 0;
        svm_cfg->gamma_OK = 0;
        svm_cfg->svm_created = 0;

        strncpy(svm_cfg->uris, "/index.php/index.html", MAX_URIS);
    }

    return svm_cfg;
}


/**
 *  Merge application's configuration to the others which result in one configuration file withouy conflict
 */
void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    svm_config *conf = (svm_config *) create_conf(pool, "Merged configuration");
    svm_config *add = (svm_config *) ADD;

    //merge directives
    conf->activated = add->activated;
    conf->nr_class = add->nr_class;
    conf->SV_dims[0] = add->SV_dims[0];
    conf->SV_dims[1] = add->SV_dims[1];
    conf->SV = add->SV;
    conf->support_dims[0] = add->support_dims[0];
    conf->support_dims[1] = add->support_dims[1];
    conf->support = add->support;
    conf->sv_coef = add->sv_coef;
    conf->rho[0] = add->rho[0];
    conf->nSV = add->nSV;
    conf->sv_coef_strides[0] = add->sv_coef_strides[0];
    conf->sv_coef_strides[1] = add->sv_coef_strides[1];
    conf->gamma = add->gamma;

    conf->param = add->param;
    conf->model = add->model;

    conf->nr_class_OK = add->nr_class_OK;
    conf->SV_dims_OK = add->SV_dims_OK;
    conf->SV_OK = add->SV_OK;
    conf->support_dims_OK = add->support_dims_OK;
    conf->support_OK = add->support_OK;
    conf->sv_coef_OK = add->sv_coef_OK;
    conf->rho_OK = add->rho_OK;
    conf->nSV_OK = add->nSV_OK;
    conf->sv_coef_strides_OK = add->sv_coef_strides_OK;
    conf->gamma_OK = add->gamma_OK;
    conf->svm_created = add->svm_created;

    strncpy(conf->uris, add->uris, MAX_URIS);

    return conf;
}


/**
 *  Retrieve if the svm2 module is activated or not (On/Off)
 */
const char *svm2_activated(cmd_parms *cmd, void *cfg, int flag) {
    svm_config *conf = (svm_config *) cfg;

    if (flag != 0 && flag != 1) {
        return "svm2_nrclass value must be 0 (desactivated) or 1 (activated).";
    }
    conf->activated = flag;

    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_nrclass(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    int nrclass = atoi(arg);
    if (nrclass <= 0) {
        return "svm2_nrclass value must be a non-zero positive integer.";
    }
    conf->nr_class = nrclass;

    conf->nr_class_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_SVdims(cmd_parms *cmd, void *cfg, const char *SVdims1, const char *SVdims2) {
    svm_config *conf = (svm_config *) cfg;

    long int SVdims = atol(SVdims1);
    if (SVdims <= 0) {
        return "svm2_SVdims value must be a non-zero positive integer.";
    }
    conf->SV_dims[0] = SVdims;

    SVdims = atol(SVdims2);
    if (SVdims <= 0) {
        return "svm2_SVdims value must be a non-zero positive integer.";
    }
    conf->SV_dims[1] = SVdims;

    conf->SV_dims_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_SV(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->SV_dims[0] <= 0 || conf->SV_dims[1] <= 0) {
        return "svm2_SVdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->SV_dims[0] * conf->SV_dims[1] * 16)) {
        return "svm2_SV length must be (svm2_SVdims[0]*svm2_SVdims[1]*16)caracters.";
    }

    conf->SV = (double *) apr_pcalloc(cmd->pool, conf->SV_dims[0] * conf->SV_dims[1] * sizeof(double));
    int cpt = 0;
    unsigned long long int number = 0;
    double e = 0;
    char TMP[19] = "0x\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for (cpt = 0; cpt < (conf->SV_dims[0] * conf->SV_dims[1] * 16); cpt += 16) {
        memcpy(TMP + 2, arg + cpt, 16);
        number = strtoull(TMP, NULL, 0);
        e = *((double *) &number);
        conf->SV[cpt / 16] = e;
    }

    conf->SV_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_supportdims(cmd_parms *cmd, void *cfg, const char *supportdims1, const char *supportdims2) {
    svm_config *conf = (svm_config *) cfg;

    long int supportdims = atol(supportdims1);
    if (supportdims <= 0) {
        return "svm2_supportdims values must be a non-zero positive integer.";
    }
    conf->support_dims[0] = supportdims;

    supportdims = atol(supportdims2);
    if (supportdims <= 0) {
        return "svm2_supportdims values must be a non-zero positive integer.";
    }
    conf->support_dims[1] = supportdims;

    conf->support_dims_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_support(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->support_dims[0] <= 0 || conf->support_dims[1] <= 0) {
        return "svm2_supportdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->support_dims[0] * conf->support_dims[1] * 8)) {
        return "svm2_support length must be (svm2_supportdims[0]*svm2_supportdims[1]*8) caracters.";
    }

    conf->support = (int *) apr_pcalloc(cmd->pool, conf->support_dims[0] * conf->support_dims[1] * sizeof(int));
    int cpt = 0;
    int f = 0;
    char TMP[11] = "0x\0\0\0\0\0\0\0\0";
    for (cpt = 0; cpt < (conf->support_dims[0] * conf->support_dims[1] * 8); cpt += 8) {
        memcpy(TMP + 2, arg + cpt, 8);
        f = (int) strtol(TMP, NULL, 0);
        conf->support[cpt / 8] = f;
    }

    conf->support_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_SVcoef(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->support_dims[0] <= 0 || conf->support_dims[1] <= 0) {
        return "svm2_supportdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->support_dims[0] * conf->support_dims[1] * 8)) {
        return "svm2_SVcoef length must be (svm2_supportdims[0]*svm2_supportdims[1]*16) caracters.";
    }

    conf->sv_coef = (double *) apr_pcalloc(cmd->pool, conf->support_dims[0] * conf->support_dims[1] * sizeof(double));
    int cpt = 0;
    unsigned long long int number = 0;
    double e = 0;
    char TMP[19] = "0x\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for (cpt = 0; cpt < (conf->support_dims[0] * conf->support_dims[1] * 16); cpt += 16) {
        memcpy(TMP + 2, arg + cpt, 16);
        number = strtoull(TMP, NULL, 0);
        e = *((double *) &number);
        conf->sv_coef[cpt / 16] = e;
    }

    conf->sv_coef_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_rho(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    double e = 0;
    char TMP[19] = "0x\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    memcpy(TMP + 2, arg, 16);
    unsigned long long int number = strtoull(TMP, NULL, 0);
    if (number <= 0) {
        return "svm2_rho value must be an hexadecimal non-zero positive integer.";
    }
    e = *((double *) &number);
    conf->rho[0] = e;

    conf->rho_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_nSV(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->nr_class <= 0) {
        return "svm2_nrclass value must be a non-zero positive integer.";
    }

    conf->nSV = (int *) apr_pcalloc(cmd->pool, conf->nr_class * sizeof(int));
    char TMP[11] = "0x\0\0\0\0\0\0\0\0";
    int cpt = 0, f = 0;

    for (cpt = 0; cpt < (conf->nr_class * 8); cpt += 8) {
        memcpy(TMP + 2, arg + cpt, 8);
        f = (int) strtol(TMP, NULL, 0);
        conf->nSV[cpt / 8] = f;
    }

    conf->nSV_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_SVcoefstrides(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2) {
    svm_config *conf = (svm_config *) cfg;

    long int tmp = atol(arg1);
    if (tmp <= 0) {
        return "svm2_SVcoefstrides values must be a non-zero positive integer.";
    }
    conf->sv_coef_strides[0] = tmp;

    tmp = atol(arg2);
    if (tmp <= 0) {
        return "svm2_SVcoefstrides values must be a non-zero positive integer.";
    }
    conf->sv_coef_strides[1] = tmp;

    conf->sv_coef_strides_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_gamma(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    char *end_arg = NULL;
    double tmp = strtod(arg, &end_arg);
    if (end_arg == arg) {
        return "svm2_gamma value must be a double.";
    }
    conf->gamma = tmp;

    conf->gamma_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

const char *svm2_uris(cmd_parms *cmd, void *cfg, const char *uris) {
    svm_config *conf = (svm_config *) cfg;

    if (strlen(uris) > MAX_URIS) {
        return "svm2_uris length must be less than MAX_URI.";
    }
    strncpy(conf->uris, uris, MAX_URIS);

    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

