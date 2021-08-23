/*                       _                           _  _
 *   _ __ ___   ___   __| |    _____   ___ __ ___   | || |
 *  | '_ ` _ \ / _ \ / _` |   / __\ \ / / '_ ` _ \  | || |_
 *  | | | | | | (_) | (_| |   \__ \\ V /| | | | | | |__   _|
 *  |_| |_| |_|\___/ \__,_|___|___/ \_/ |_| |_| |_|    |_|
 *                       |_____|
 *  Copyright (c) 2016 Kevin Guillemot & Baptiste de Magnienville
 *  Released under the GPLv3
 */


#include "mod_svm4.h"

module AP_MODULE_DECLARE_DATA svm4_module;
AP_DECLARE_MODULE(svm4) = {
        STANDARD20_MODULE_STUFF,
        create_conf,                /* create per-directory config structure */
        merge_conf,                 /* merge per-directory config structures */
        NULL,                       /* create per-server config structure */
        NULL,                       /* merge per-server config structures */
        svm_directives,             /* command apr_table_t */
        register_hooks
};

static void register_hooks(apr_pool_t *p) {
    ap_hook_fixups(svm4_handler, NULL, NULL, APR_HOOK_FIRST + 1);
    ap_hook_insert_filter(insert_filters, NULL, NULL, APR_HOOK_FIRST + 1);
    ap_register_input_filter(INPUT_FILTER, svm4_input_filter, NULL, AP_FTYPE_RESOURCE);
    ap_register_output_filter(OUTPUT_FILTER, svm4_output_filter, NULL, AP_FTYPE_RESOURCE);
}


static void insert_filters(request_rec *r) {
    ap_add_input_filter(INPUT_FILTER, NULL, r, r->connection);
    ap_add_output_filter(OUTPUT_FILTER, NULL, r, r->connection);
}

int create_svm(svm_config *config, cmd_parms *cmd) {
    // Verify if each directive is specified in application config file
    if (config->activated && config->nr_class_OK && config->SV_dims_OK && config->SV_OK && config->support_dims_OK &&
        config->support_OK && config->sv_coef_OK && config->rho_OK && config->nSV_OK && config->sv_coef_strides_OK &&
        config->gamma_OK && !config->svm_created) {
        // Allocate the 'param' attribute of the svm_config structure
        config->param = (struct svm_parameter *) apr_pcalloc(cmd->pool, sizeof(struct svm_parameter));

        // Define all variables used in SVM
        int svm_type = 2;
        int kernel_type = 2;
        int degree = 3;
        double coef0 = 0;
        double cache_size = 100;
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

        set_parameter(config->param, svm_type, kernel_type, degree, config->gamma, coef0, nu, cache_size, C, tol,
                      epsilon,
                      shrinking, probability, nr_weight, weight_label, weight, max_iter, random_seed);

        // Don't allocate the 'model' attribute cause 'set_model()' does it
        config->model = set_model(config->param, config->nr_class, (char *) config->SV, (long int *) config->SV_dims,
                                  (char *) config->support, (long int *) config->support_dims,
                                  (long int *) config->sv_coef_strides, (char *) config->sv_coef, (char *) config->rho,
                                  (char *) config->nSV, NULL, NULL);

        return 1;
    }
    return 0;
}

/**
 *  Implementation of the mod_svm4's logic (in output filter)
 *  Retrieve HTTP code response and call svm_predict with bytes_recv/code_response
 */
static apr_status_t svm4_handler(request_rec *r) {
    svm_config *config = (svm_config *) ap_get_module_config(r->per_dir_config, &svm4_module);
    apr_table_set(r->subprocess_env, "svm4", "0");

    if (config->activated == 1 && config->svm_created == 1) {
        if (get_request_len_from_notes(r, REQUEST_LEN, "Handler") == -1) {
            apr_size_t bytes_rec = get_headers_in_len(r);
            AP_LOG_TRACE1(r, "Mod_svm4::Handler: Request length without body = %lu ", bytes_rec);
            set_request_len_in_notes(r, bytes_rec, REQUEST_LEN);
        }
    }
    return OK;
}


/**
 *  Implementation of the mod_svm4's logic (in input filter)
 *  Retrieve HTTP code response and call svm_predict with bytes_recv/code_response
 */
static apr_status_t svm4_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                      ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    svm_config *config = (svm_config *) ap_get_module_config(f->r->per_dir_config, &svm4_module);
    if (config->activated != 1 || config->svm_created != 1) {
        AP_LOG_DEBUG(f->r, "Mod_svm4::Input_filter: Conf Activated: %s, Created: %s",
                       config->activated ? "Yes" : "No", config->svm_created ? "Yes" : "No");
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
        AP_LOG_TRACE1(f->r, "Mod_svm4::Input_filter: End Of Stream");
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    // Try to retrieve bytes_recv from r->notes
    int bytes_recv = get_request_len_from_notes(f->r, REQUEST_LEN, "In");
    AP_LOG_TRACE1(f->r, "Mod_svm4::Input_filter: Bytes_recv: %d (int)", bytes_recv);
    if( bytes_recv < 0 )
        bytes_recv = 0;

    apr_status_t ret;
    if ((ret = ap_get_brigade(f->next, bb, mode, block, readbytes)) != APR_SUCCESS) {
        AP_LOG_ERROR(f->r, "Mod_svm4::Input_filter: Unable to get_brigade.");
        return ret;
    }

    // Read size of brigade
    apr_off_t off;
    apr_brigade_length(bb, 1, &off);
    AP_LOG_TRACE1(f->r, "Mod_svm4::Input_filter: Brigade length: %lu", off);

    // Set bytes_recv in request notes to retrieve it in next filters
    set_request_len_in_notes(f->r, (apr_size_t) off + bytes_recv, REQUEST_LEN);
    AP_LOG_TRACE1(f->r, "Mod_svm4::Input_filter: Request length: %lu", off + bytes_recv);
    return APR_SUCCESS;
}

/**
 *  Implementation of the mod_svm4's logic (in output filter)
 *  Retrieve HTTP code response and call svm_predict with bytes_recv/code_response
 */
static void debug_brigade(ap_filter_t *f, apr_bucket_brigade *bb) {
    for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_EOS(b)) { // If we ever see an EOS, make sure to FLUSH.
            apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
            APR_BUCKET_INSERT_BEFORE(b, flush);
        }
        AP_LOG_TRACE7(f->r, "Mod_svm4::Debug_brigade: Bucket: %s (%s-%s): %" APR_SIZE_T_FMT " bytes",
                       f->frec->name, (APR_BUCKET_IS_METADATA(b)) ? "metadata" : "data", b->type->name, b->length);

//        if (!(APR_BUCKET_IS_METADATA(b))) {
//            const char *buf;
//            apr_size_t nbytes;
//            apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ);
//            AP_LOG_TRACE7(f->r, "Bucket: %.*s", (int) nbytes, buf);
//        }
    }
}

/**
 *  Implementation of the mod_svm4's logic (in output filter)
 *  Retrieve HTTP code response and call svm_predict with bytes_recv/code_response
 */
static apr_status_t svm4_output_filter(ap_filter_t *f, apr_bucket_brigade *bb) {

//    debug_brigade(f, bb);

    if (apr_table_get(f->r->notes, "mod_svm.403") != NULL) {
        AP_LOG_DEBUG(f->r, "Mod_svm4::Output_filter: Request '%s' already blocked", f->r->uri);
        goto END;
    }

    svm_config *config = (svm_config *) ap_get_module_config(f->r->per_dir_config, &svm4_module);
    if (config->activated != 1 || config->svm_created != 1) {
        AP_LOG_DEBUG(f->r, "Mod_svm4::Output_filter: Conf Activated: %s, Created: %s",
                       config->activated ? "Yes" : "No", config->svm_created ? "Yes" : "No");
        goto END;
    }

    // Try to retrieve bytes_recv from r->notes
    int bytes_recv = get_request_len_from_notes(f->r, REQUEST_LEN, "Out");
    if (bytes_recv < 0) {
        AP_LOG_TRACE1(f->r, "Mod_svm4::Output_filter: bytes_recv < 0: %s",
                       apr_table_get(f->r->notes, REQUEST_LEN));
        goto END;
    } else {
        AP_LOG_DEBUG(f->r, "Mod_svm4::Output_filter: Bytes recv: %d", bytes_recv);
    }

    AP_LOG_DEBUG(f->r, "Mod_svm4::Output_filter: Code response: %d", f->r->status);

    // Perform svm_predict with bytes_recv & status_code
    // Set X shape for svm_predict
    long int X_shape[2] = {1, 2};

    // Set X data from request data (HTTP_Code & bytes_recv)
    double X_data[2] = {f->r->status, bytes_recv};

    double prediction;

    // Perform svm_predict calculus
    copy_predict((char *) X_data, config->model, X_shape, (char *) &prediction);

    // Verify result
    AP_LOG_DEBUG(f->r, "Mod_svm4::Output_filter: Prediction result: %d", (int) prediction);
    if ((int) prediction == -1) {
        AP_LOG_ERROR(f->r, "Mod_svm4::Output_filter: Suspicious request '%s'", f->r->uri);

        apr_table_setn(f->r->notes, "mod_svm.403", "1");
        apr_table_set(f->r->subprocess_env, "svm4", "1");
    }

    END:
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static void *create_conf(apr_pool_t *pool, char *context) {
    svm_config *config = (svm_config *) apr_pcalloc(pool, sizeof(svm_config));
    if (config) {
        config->activated = 0;
        config->nr_class = 0;
        config->SV_dims[0] = 0;
        config->SV_dims[1] = 0;
        config->support_dims[0] = 0;
        config->support_dims[1] = 0;
        config->rho[0] = 0;
        config->sv_coef_strides[0] = 0;
        config->sv_coef_strides[1] = 0;
        config->gamma = 0;

        config->nr_class_OK = 0;
        config->SV_dims_OK = 0;
        config->SV_OK = 0;
        config->support_dims_OK = 0;
        config->support_OK = 0;
        config->sv_coef_OK = 0;
        config->rho_OK = 0;
        config->nSV_OK = 0;
        config->sv_coef_strides_OK = 0;
        config->gamma_OK = 0;
        config->svm_created = 0;

        config->max_size = DEFAULT_MAX_SIZE;
    }

    return config;
}

static void *merge_conf(apr_pool_t *pool, void *BASE, void *ADD) {
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

    conf->max_size = add->max_size;

    return conf;
}

const char *svm4_activated(cmd_parms *cmd, void *cfg, int flag) {
    svm_config *conf = (svm_config *) cfg;

    if (flag != 0 && flag != 1) {
        return "svm4_activated value must be 0 (desactivated) or 1 (activated).";
    }
    conf->activated = flag;

    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm4_nrclass(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    int nrclass = atoi(arg);
    if (nrclass <= 0) {
        return "svm4_nrclass value must be a non-zero positive integer.";
    }
    conf->nr_class = nrclass;

    conf->nr_class_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm4_SVdims(cmd_parms *cmd, void *cfg, const char *SVdims1, const char *SVdims2) {
    svm_config *conf = (svm_config *) cfg;

    long int SVdims = atol(SVdims1);
    if (SVdims <= 0) {
        return "svm4_SVdims value must be a non-zero positive integer.";
    }
    conf->SV_dims[0] = SVdims;

    SVdims = atol(SVdims2);
    if (SVdims <= 0) {
        return "svm4_SVdims value must be a non-zero positive integer.";
    }
    conf->SV_dims[1] = SVdims;

    conf->SV_dims_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm4_SV(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->SV_dims[0] <= 0 || conf->SV_dims[1] <= 0) {
        return "svm4_SVdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->SV_dims[0] * conf->SV_dims[1] * 16)) {
        return "svm4_SV length must be (svm4_SVdims[0]*svm4_SVdims[1]*16)caracters.";
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

static const char *svm4_supportdims(cmd_parms *cmd, void *cfg, const char *supportdims1,
                                    const char *supportdims2) {
    svm_config *conf = (svm_config *) cfg;

    long int supportDims = atol(supportdims1);
    if (supportDims <= 0) {
        return "svm4_supportdims values must be a non-zero positive integer.";
    }
    conf->support_dims[0] = supportDims;

    supportDims = atol(supportdims2);
    if (supportDims <= 0) {
        return "svm4_supportdims values must be a non-zero positive integer.";
    }
    conf->support_dims[1] = supportDims;

    conf->support_dims_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm4_support(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->support_dims[0] <= 0 || conf->support_dims[1] <= 0) {
        return "svm4_supportdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->support_dims[0] * conf->support_dims[1] * 8)) {
        return "svm4_support length must be (svm4_supportdims[0]*svm4_supportdims[1]*8) caracters.";
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

static const char *svm4_SVcoef(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->support_dims[0] <= 0 || conf->support_dims[1] <= 0) {
        return "svm4_supportdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->support_dims[0] * conf->support_dims[1] * 8)) {
        return "svm4_SVcoef length must be (svm4_supportdims[0]*svm4_supportdims[1]*16) caracters.";
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

static const char *svm4_rho(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    double e = 0;
    char TMP[19] = "0x\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    memcpy(TMP + 2, arg, 16);
    unsigned long long int number = strtoull(TMP, NULL, 0);
    if (number <= 0) {
        return "svm4_rho value must be an hexadecimal non-zero positive integer.";
    }
    e = *((double *) &number);
    conf->rho[0] = e;

    conf->rho_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm4_nSV(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->nr_class <= 0) {
        return "svm4_nrclass value must be a non-zero positive integer.";
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


static const char *svm4_SVcoefstrides(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2) {
    svm_config *conf = (svm_config *) cfg;

    long int tmp = atol(arg1);
    if (tmp <= 0) {
        return "svm4_SVcoefstrides values must be a non-zero positive integer.";
    }
    conf->sv_coef_strides[0] = tmp;

    tmp = atol(arg2);
    if (tmp <= 0) {
        return "svm4_SVcoefstrides values must be a non-zero positive integer.";
    }
    conf->sv_coef_strides[1] = tmp;

    conf->sv_coef_strides_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm4_gamma(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    char *end_arg = NULL;
    double tmp = strtod(arg, &end_arg);
    if (end_arg == arg) {
        return "svm4_gamma value must be a double.";
    }
    conf->gamma = tmp;

    conf->gamma_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm4_maxsize(cmd_parms *cmd, void *_cfg, const char *arg) {
    svm_config *cfg = (svm_config *) _cfg; //ap_get_module_config(cmd->server->module_config, &dumpost_module);
    cfg->max_size = (apr_size_t) atoi(arg);
    if (cfg->max_size <= 0) {
        cfg->max_size = DEFAULT_MAX_SIZE;
        return "svm4_maxsize value must be a non-zero positive value. Setting DEFAULT_MAX_SIZE.";
    }
    return NULL;
}