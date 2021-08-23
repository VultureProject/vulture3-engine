/*                       _                           ____
 *   _ __ ___   ___   __| |    _____   ___ __ ___   | ___|
 *  | '_ ` _ \ / _ \ / _` |   / __\ \ / / '_ ` _ \  |___ \
 *  | | | | | | (_) | (_| |   \__ \\ V /| | | | | |  ___) |
 *  |_| |_| |_|\___/ \__,_|___|___/ \_/ |_| |_| |_| |____/
 *                       |_____|
 *  Copyright (c) 2016 Kevin Guillemot & Baptiste de Magnienville
 *  Released under the GPLv3
 */


#include <ap_mpm.h>
#include "mod_svm5.h"

module AP_MODULE_DECLARE_DATA svm5_module;
AP_DECLARE_MODULE(svm5) = {
        STANDARD20_MODULE_STUFF,
        create_conf,                /* create per-directory config structure */
        merge_conf,                 /* merge per-directory config structures */
        NULL,                       /* create per-server config structure */
        NULL,                       /* merge per-server config structures */
        svm_directives,             /* command apr_table_t */
        register_hooks
};

static void register_hooks(apr_pool_t *p) {
    ap_hook_fixups(svm5_handler, NULL, NULL, APR_HOOK_FIRST + 2);
    ap_hook_insert_filter(insert_filters, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_register_input_filter(INPUT_FILTER, svm5_input_filter, NULL, AP_FTYPE_RESOURCE);
    ap_register_output_filter(OUTPUT_FILTER, svm5_output_filter, NULL, AP_FTYPE_RESOURCE);
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
 *  Implementation of the mod_svm5's logic
 *  Retrieve bytes_recv from notes & set it if null
 */
apr_status_t svm5_handler(request_rec *r) {
    svm_config *config = (svm_config *) ap_get_module_config(r->per_dir_config, &svm5_module);

    if (config->activated == 1 && config->svm_created == 1) {
        if (get_request_len_from_notes(r, REQUEST_LEN, "Handler") == -1) {
            apr_size_t bytes_rec = get_headers_in_len(r);
            AP_LOG_TRACE1(r, "Mod_svm5::Handler: First line and headers length = %lu ", bytes_rec);
            set_request_len_in_notes(r, bytes_rec, REQUEST_LEN);
        }
    }
    return OK;
}

static void debug_brigade(ap_filter_t *f, apr_bucket_brigade *bb) {
    for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_EOS(b)) { // If we ever see an EOS, make sure to FLUSH.
            apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
            APR_BUCKET_INSERT_BEFORE(b, flush);
        }
        AP_LOG_TRACE7(f->r, "Bucket: %s (%s-%s): %" APR_SIZE_T_FMT " bytes",
                       f->frec->name, (APR_BUCKET_IS_METADATA(b)) ? "metadata" : "data", b->type->name, b->length);
    }
}

/**
 *  Implementation of the mod_svm5's logic (in input filter)
 *  Retrieve brigades length & update bytes_recv in notes's request_rec struct
 */

struct svm_int_state {
    apr_size_t bb_len;
};

static apr_status_t svm5_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                      ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    svm_config *config = (svm_config *) ap_get_module_config(f->r->per_dir_config, &svm5_module);
    if (config->activated != 1 || config->svm_created != 1) {
        AP_LOG_DEBUG(f->r, "Mod_svm5::Input_filter: Conf: Activated: %s, Created: %s",
                       config->activated ? "Yes" : "No", config->svm_created ? "Yes" : "No");
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    apr_status_t ret;
    if ((ret = ap_get_brigade(f->next, bb, mode, block, readbytes)) != APR_SUCCESS) {
        AP_LOG_ERROR(f->r, "Mod_svm5::Input_filter: Unable to get_brigade");
        return ret;
    }

    struct svm_int_state *state = f->ctx;
    if (state == NULL) {
        f->ctx = state = apr_palloc(f->r->pool, sizeof *state);
        state->bb_len = 0;
    }

    // Read size of brigade
    apr_off_t off;
    apr_brigade_length(bb, 1, &off);
    state->bb_len += off;
    AP_LOG_TRACE1(f->r, "Mod_svm5::Input_filter: Brigade len: %lu, brigades sum: %lu", off, state->bb_len);

    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
        AP_LOG_TRACE1(f->r, "Mod_svm5::Input_filter: End Of Stream");

        // Try to retrieve flh_len from r->notes
        int flh_len = get_request_len_from_notes(f->r, REQUEST_LEN, "In");
        AP_LOG_TRACE1(f->r, "Mod_svm5::Input_filter: First Line and Headers len: %d bytes", flh_len);
        if (flh_len < 0)
            flh_len = 0;

        // Set request len in request notes to retrieve it in next filters
        set_request_len_in_notes(f->r, state->bb_len + flh_len, REQUEST_LEN);
        AP_LOG_TRACE1(f->r, "Mod_svm5::Input_filter: Request length: %lu", state->bb_len + flh_len);

        ap_remove_input_filter(f);
    }
    return APR_SUCCESS;
}


/**
 *  Implementation of the mod_svm5's logic (in output filter)
 *  Retrieve HTTP code response and call svm_predict with bytes_recv/code_response
 *  Return 403 if SVM returns -1
 */
struct svm_out_state {
    apr_bucket_brigade *bb;
    apr_size_t bb_len;
};

static apr_status_t svm5_output_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    svm_config *config = (svm_config *) ap_get_module_config(f->r->per_dir_config, &svm5_module);
    if (config->activated != 1 || config->svm_created != 1) {
        AP_LOG_DEBUG(f->r, "Mod_svm5::Output_filter: Activated: %s, Created: %s",
                       config->activated ? "Yes" : "No", config->svm_created ? "Yes" : "No");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    if (apr_table_get(f->r->notes, "mod_svm.403") != NULL) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

//    debug_brigade(f, bb);

    struct svm_out_state *state = f->ctx;
    if (state == NULL) {
        f->ctx = state = apr_palloc(f->r->pool, sizeof *state);
        state->bb_len = 0;
        state->bb = NULL;
    }

    apr_off_t off;
    apr_brigade_length(bb, 1, &off);
    state->bb_len += (int) off;
    AP_LOG_TRACE1(f->r, "Mod_svm5::Output_filter: Brigade len: %lu, brigades sum: %lu", off, state->bb_len);

//    int eos = APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb));
//
//    apr_status_t ret;
//    if ((ret = ap_save_brigade(f, &state->bb, &bb, f->r->pool)) != APR_SUCCESS) {
//        AP_LOG_ERROR(f->r, "Mod_svm5::Output_filter: Unable to save_brigade");
//        return ret;
//    }
//
//    if (!eos)
//        return APR_SUCCESS;

    AP_LOG_TRACE1(f->r, "Mod_svm5::Output_filter: End Of Stream");

    apr_size_t response_len = (apr_size_t) get_content_len(f->r->headers_out);
    AP_LOG_TRACE1(f->r, "Mod_svm5::Output_filter: Content-Length header out: %lu", response_len);
    response_len += get_headers_out_len(f->r);
    AP_LOG_TRACE1(f->r, "Mod_svm5::Output_filter: + headers out len: %lu", response_len);
    response_len += get_keep_alive_header_len(f->r);
    AP_LOG_TRACE1(f->r, "Mod_svm5::Output_filter: + keep-alive header len: %lu", response_len);
//    print_headers_in(f->r);

    // Try to retrieve request_len from r->notes
    int request_len = get_request_len_from_notes(f->r, REQUEST_LEN, "Out");
    if (request_len < 0) {
        AP_LOG_WARNING(f->r, "Mod_svm5::Output_filter: Request len < 0: %d", request_len);
        return ap_pass_brigade(f->next, bb);
    }

    AP_LOG_DEBUG(f->r, "Mod_svm5::Output_filter: Request: %d bytes", request_len);

    response_len += state->bb_len;
    AP_LOG_DEBUG(f->r, "Mod_svm5::Output_filter: Response: %lu bytes", response_len);

    double ratio_input_output = (double) response_len / (double) request_len;
    AP_LOG_DEBUG(f->r, "Mod_svm5::Output_filter: Ratio input/output: %lf", ratio_input_output);
    AP_LOG_DEBUG(f->r, "Mod_svm5::Output_filter: Status code: %d", f->r->status);

    // Perform svm_predict with request_len & status_code
    // Set X shape for svm_predict
    long int X_shape[2] = {1, 2};

    // Set X data from request datas (HTTP_Code & request_len)
    double X_data[2] = {f->r->status, ratio_input_output};

    // Define result tab
    double prediction;

    // Perform svm_predict calculus
    copy_predict((char *) X_data, config->model, X_shape, (char *) &prediction);

    // Verify result
    AP_LOG_DEBUG(f->r, "Mod_svm5::Output_filter: Prediction result: %d", (int) prediction);
    if ((int) prediction == -1) {
        AP_LOG_ERROR(f->r, "Mod_svm5::Output_filter: Suspicious request '%s'", f->r->uri);
        apr_table_setn(f->r->notes, "mod_svm.403", "1");
        apr_table_set(f->r->subprocess_env, "svm5", "1");
    }

    //apr_status_t rc = ap_pass_brigade(f->next, state->bb);
    apr_status_t rc = ap_pass_brigade(f->next, bb);
    if (rc != APR_SUCCESS) {
        AP_LOG_DEBUG(f->r, "Mod_svm5::Output_filter: Unable to pass saved brigade");
        return rc;
    }

    return APR_SUCCESS;
}


/**
 *  Define the application configuration (in vhost section)
 */
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

        config->nr_class_OK = 0;
        config->SV_dims_OK = 0;
        config->SV_OK = 0;
        config->support_dims_OK = 0;
        config->support_OK = 0;
        config->sv_coef_OK = 0;
        config->rho_OK = 0;
        config->nSV_OK = 0;
        config->sv_coef_strides_OK = 0;
        config->svm_created = 0;

        config->max_size = DEFAULT_MAX_SIZE;
    }

    return config;
}


/**
 *  Merge application's configuration to the others which result in one configuration file withouy conflict
 */
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
    conf->svm_created = add->svm_created;

    conf->max_size = add->max_size;

    return conf;
}

static const char *svm5_activated(cmd_parms *cmd, void *cfg, int flag) {
    svm_config *conf = (svm_config *) cfg;

    if (flag != 0 && flag != 1) {
        return "RatioInputOutput01_nrclass value must be 0 (desactivated) or 1 (activated).";
    }
    conf->activated = flag;

    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm5_nrclass(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    int nrclass = atoi(arg);
    if (nrclass <= 0) {
        return "RatioInputOutput01_nrclass value must be a non-zero positive integer.";
    }
    conf->nr_class = nrclass;

    conf->nr_class_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm5_SVdims(cmd_parms *cmd, void *cfg, const char *SVdims1, const char *SVdims2) {
    svm_config *conf = (svm_config *) cfg;

    long int SVdims = atol(SVdims1);
    if (SVdims <= 0) {
        return "RatioInputOutput01_SVdims value must be a non-zero positive integer.";
    }
    conf->SV_dims[0] = SVdims;

    SVdims = atol(SVdims2);
    if (SVdims <= 0) {
        return "RatioInputOutput01_SVdims value must be a non-zero positive integer.";
    }
    conf->SV_dims[1] = SVdims;

    conf->SV_dims_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm5_SV(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->SV_dims[0] <= 0 || conf->SV_dims[1] <= 0) {
        return "RatioInputOutput01_SVdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->SV_dims[0] * conf->SV_dims[1] * 16)) {
        return "RatioInputOutput01_SV length must be (RatioInputOutput01_SVdims[0]*RatioInputOutput01_SVdims[1]*16)caracters.";
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

static const char *svm5_supportdims(cmd_parms *cmd, void *cfg, const char *supportdims1, const char *supportdims2) {
    svm_config *conf = (svm_config *) cfg;

    long int supportdims = atol(supportdims1);
    if (supportdims <= 0) {
        return "RatioInputOutput01_supportdims values must be a non-zero positive integer.";
    }
    conf->support_dims[0] = supportdims;

    supportdims = atol(supportdims2);
    if (supportdims <= 0) {
        return "RatioInputOutput01_supportdims values must be a non-zero positive integer.";
    }
    conf->support_dims[1] = supportdims;

    conf->support_dims_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm5_support(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->support_dims[0] <= 0 || conf->support_dims[1] <= 0) {
        return "RatioInputOutput01_supportdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->support_dims[0] * conf->support_dims[1] * 8)) {
        return "RatioInputOutput01_support length must be (RatioInputOutput01_supportdims[0]*RatioInputOutput01_supportdims[1]*8) caracters.";
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

static const char *svm5_SVcoef(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->support_dims[0] <= 0 || conf->support_dims[1] <= 0) {
        return "RatioInputOutput01_supportdims values must be a non-zero positive integer.";
    }
    if (strlen(arg) < (conf->support_dims[0] * conf->support_dims[1] * 8)) {
        return "RatioInputOutput01_SVcoef length must be (RatioInputOutput01_supportdims[0]*RatioInputOutput01_supportdims[1]*16) caracters.";
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

static const char *svm5_rho(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    double e = 0;
    char TMP[19] = "0x\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    memcpy(TMP + 2, arg, 16);
    unsigned long long int number = strtoull(TMP, NULL, 0);
    if (number <= 0) {
        return "RatioInputOutput01_rho value must be an hexadecimal non-zero positive integer.";
    }
    e = *((double *) &number);
    conf->rho[0] = e;

    conf->rho_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm5_nSV(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    if (conf->nr_class <= 0) {
        return "RatioInputOutput01_nrclass value must be a non-zero positive integer.";
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

static const char *svm5_SVcoefstrides(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2) {
    svm_config *conf = (svm_config *) cfg;

    long int tmp = atol(arg1);
    if (tmp <= 0) {
        return "RatioInputOutput01_SVcoefstrides values must be a non-zero positive integer.";
    }
    conf->sv_coef_strides[0] = tmp;

    tmp = atol(arg2);
    if (tmp <= 0) {
        return "RatioInputOutput01_SVcoefstrides values must be a non-zero positive integer.";
    }
    conf->sv_coef_strides[1] = tmp;

    conf->sv_coef_strides_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm5_gamma(cmd_parms *cmd, void *cfg, const char *arg) {
    svm_config *conf = (svm_config *) cfg;

    char *end_arg = NULL;
    double tmp = strtod(arg, &end_arg);
    if (end_arg == arg) {
        return "RatioInputOutput01_gamma value must be a double.";
    }
    conf->gamma = tmp;

    conf->gamma_OK = 1;
    if (!conf->svm_created) {
        conf->svm_created = create_svm(conf, cmd);
    }
    return NULL;
}

static const char *svm5_maxsize(cmd_parms *cmd, void *_cfg, const char *arg) {
    svm_config *cfg = (svm_config *) _cfg; //ap_get_module_config(cmd->server->module_config, &dumpost_module);
    cfg->max_size = (apr_size_t) atoi(arg);
    if (cfg->max_size <= 0) {
        cfg->max_size = DEFAULT_MAX_SIZE;
        return "RatioInputOutput01_maxsize value must be a non-zero positive value. Setting DEFAULT_MAX_SIZE.";
    }
    return NULL;
}

static int get_headers_out_len(request_rec *r) {
    const apr_array_header_t *fields = apr_table_elts(r->headers_out);
    apr_table_entry_t *entry = (apr_table_entry_t *) fields->elts;

    int response_length = 0;
    // Loop which iterate thought each fields
    for (int i = 0; i < fields->nelts; i++) {
        response_length += (strlen(entry[i].key) + strlen(entry[i].val) + 4);
    }
    response_length += strlen(r->status_line) + strlen(r->protocol) + 5;
    AP_LOG_TRACE2(r, "Mod_svm5::Output_filter: Headers length: %d", response_length);
    return response_length;
}

static int is_mpm_running(void) {
    int mpm_state = 0;
    if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
        return 0;
    }
    if (mpm_state == AP_MPMQ_STOPPING) {
        return 0;
    }
    return 1;
}


static apr_size_t get_keep_alive_header_len(request_rec *r) {
    apr_size_t headers_length = 0;
    int ka_sent = 0;
    int left = r->server->keep_alive_max - r->connection->keepalives;
    int wimpy = ap_find_token(r->pool,
                              apr_table_get(r->headers_out, "Connection"),
                              "close");
    const char *conn = apr_table_get(r->headers_in, "Connection");

    /* The following convoluted conditional determines whether or not
     * the current connection should remain persistent after this response
     * (a.k.a. HTTP Keep-Alive) and whether or not the output message
     * body should use the HTTP/1.1 chunked transfer-coding.  In English,
     *
     *   IF  we have not marked this connection as errored;
     *   and the client isn't expecting 100-continue (PR47087 - more
     *       input here could be the client continuing when we're
     *       closing the request).
     *   and the response body has a defined length due to the status code
     *       being 304 or 204, the request method being HEAD, already
     *       having defined Content-Length or Transfer-Encoding: chunked, or
     *       the request version being HTTP/1.1 and thus capable of being set
     *       as chunked [we know the (r->chunked = 1) side-effect is ugly];
     *   and the server configuration enables keep-alive;
     *   and the server configuration has a reasonable inter-request timeout;
     *   and there is no maximum # requests or the max hasn't been reached;
     *   and the response status does not require a close;
     *   and the response generator has not already indicated close;
     *   and the client did not request non-persistence (Connection: close);
     *   and    we haven't been configured to ignore the buggy twit
     *       or they're a buggy twit coming through a HTTP/1.1 proxy
     *   and    the client is requesting an HTTP/1.0-style keep-alive
     *       or the client claims to be HTTP/1.1 compliant (perhaps a proxy);
     *   and this MPM process is not already exiting
     *   THEN we can be persistent, which requires more headers be output.
     *
     * Note that the condition evaluation order is extremely important.
     */
    if ((r->connection->keepalive != AP_CONN_CLOSE)
        && !r->expecting_100
        && ((r->status == HTTP_NOT_MODIFIED)
            || (r->status == HTTP_NO_CONTENT)
            || r->header_only
            || apr_table_get(r->headers_out, "Content-Length")
            || ap_find_last_token(r->pool,
                                  apr_table_get(r->headers_out,
                                                "Transfer-Encoding"),
                                  "chunked")
            || ((r->proto_num >= HTTP_VERSION(1, 1)))) /* THIS CODE IS CORRECT, see above. */
        && r->server->keep_alive
        && (r->server->keep_alive_timeout > 0)
        && ((r->server->keep_alive_max == 0)
            || (left > 0))
        && !ap_status_drops_connection(r->status)
        && !wimpy
        && !ap_find_token(r->pool, conn, "close")
        && (!apr_table_get(r->subprocess_env, "nokeepalive")
            || apr_table_get(r->headers_in, "Via"))
        && ((ka_sent = ap_find_token(r->pool, conn, "keep-alive"))
            || (r->proto_num >= HTTP_VERSION(1, 1)))
        && is_mpm_running()) {

        /* If they sent a Keep-Alive token, send one back */
        if (ka_sent) {
            if (r->server->keep_alive_max) {
                headers_length = strlen("Keep-Alive") + strlen(apr_psprintf(r->pool, "timeout=%d, max=%d",
                                                                            (int) apr_time_sec(
                                                                                    r->server->keep_alive_timeout),
                                                                            left)) + 4;
            } else {
                headers_length = strlen("Keep-Alive") + strlen(apr_psprintf(r->pool, "timeout=%d",
                                                                            (int) apr_time_sec(
                                                                                    r->server->keep_alive_timeout))) +
                                 4;
            }
            /* If the header exists, we already have treated its length,
             *  so just add "Keep-Alive ," length 
             */
            if (apr_table_get(r->headers_out, "Connection") != NULL) {
                headers_length += strlen("Keep-Alive ,");
            }
                /* Else, add "Connection: Keep-Alive\r\n" length */
            else {
                headers_length += strlen("Connection") + strlen("Keep-Alive") + 4;
            }
            //apr_table_mergen(r->headers_out, "Connection", "Keep-Alive");
        }
        return headers_length;
    }

    /* Otherwise, we need to indicate that we will be closing this
     * connection immediately after the current response.
     *
     * We only really need to send "close" to HTTP/1.1 clients, but we
     * always send it anyway, because a broken proxy may identify itself
     * as HTTP/1.0, but pass our request along with our HTTP/1.1 tag
     * to a HTTP/1.1 client. Better safe than sorry.
     */
    if (!wimpy) {
        if (apr_table_get(r->headers_out, "Connection") != NULL) {
            headers_length += strlen("close ,");
        }
            /* Else, add "Connection: Keep-Alive\r\n" length */
        else {
            headers_length += strlen("Connection") + strlen("close") + 4;
        }
        //apr_table_mergen(r->headers_out, "Connection", "close");
    }

    AP_LOG_TRACE2(r, "Mod_svm5::Output_filter: Headers 'Connection' & 'Keep-Alive' length: %lu", headers_length);

    return headers_length;
}
