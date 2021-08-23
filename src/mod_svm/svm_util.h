/**
 * \file     svm_util.h
 * \author   Kevin Guillemot
 * \version  1.0
 * \date     19/10/17
 * \license  GPLv3
 * \brief    Headers of the mod_svm* modules
 */

#ifndef MOD_SVM_SVM_UTIL_H
#define MOD_SVM_SVM_UTIL_H


/*************************/
/* Inclusion of .H files */
/*************************/

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"
#include "libsvm/svm.h"


/*************/
/* Constants */
/*************/

/**
 * \def npy_intp
 *      Type used by scipy but not known, we have to redefine it
 */
#define npy_intp long int

/**
 * \def NB_MAX_DIGIT_INT
 *      The max number of digit for an integer
 */
#define NB_MAX_DIGIT_INT 11

/**
 * \def DEFAULT_MAX_SIZE
 *      Default value of directives "max size of bytes received"
 */
#define DEFAULT_MAX_SIZE 1024*1024

/**
 * \def MAX_URIS
 *      Max length of uri
 */
#define MAX_URIS 1024*1024

/**
 * \def REQUEST_LEN
 *      String used to stock/retrieve bytes_read value from notes
 */

#define REQUEST_LEN "mod_svm4.bytes_read"


#define AP_LOG_WRITE(log_level,r,format,...) { \
    ap_log_rerror(APLOG_MARK,log_level,0,r,format,## __VA_ARGS__); }

#define AP_LOG_TRACE8(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE8, r, format, ## __VA_ARGS__); }   /* trace-level 8 messages */

#define AP_LOG_TRACE7(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE7, r, format, ## __VA_ARGS__); }   /* trace-level 7 messages */

#define AP_LOG_TRACE6(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE6, r, format, ## __VA_ARGS__); }   /* trace-level 6 messages */

#define AP_LOG_TRACE5(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE5, r, format, ## __VA_ARGS__); }   /* trace-level 5 messages */

#define AP_LOG_TRACE4(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE4, r, format, ## __VA_ARGS__); }   /* trace-level 4 messages */

#define AP_LOG_TRACE3(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE3, r, format, ## __VA_ARGS__); }   /* trace-level 3 messages */

#define AP_LOG_TRACE2(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE2, r, format, ## __VA_ARGS__); }   /* trace-level 2 messages */

#define AP_LOG_TRACE1(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE1, r, format, ## __VA_ARGS__); }   /* trace-level 1 messages */

#define AP_LOG_DEBUG(r, format, ...) { \
    AP_LOG_WRITE(APLOG_DEBUG, r, format, ## __VA_ARGS__); }     /* debug-level messages */

#define AP_LOG_INFO(r, format, ...) { \
    AP_LOG_WRITE(APLOG_INFO, r, format, ## __VA_ARGS__); }      /* informational */

#define AP_LOG_NOTICE(r, format, ...) { \
    AP_LOG_WRITE(APLOG_NOTICE, r, format, ## __VA_ARGS__); }    /* normal but significant condition */

#define AP_LOG_WARNING(r, format, ...) { \
    AP_LOG_WRITE(APLOG_WARNING, r, format, ## __VA_ARGS__); }   /* warning conditions */

#define AP_LOG_ERROR(r, format, ...) { \
    AP_LOG_WRITE(APLOG_ERR, r, format, ## __VA_ARGS__); }       /* error conditions */

#define AP_LOG_CRIT(r, format, ...) { \
    AP_LOG_WRITE(APLOG_CRIT, r, format, ## __VA_ARGS__); }      /* critical conditions */

#define AP_LOG_ALERT(r, format, ...) { \
    AP_LOG_WRITE(APLOG_ALERT, r, format, ## __VA_ARGS__); }     /* action must be taken immediately */

#define AP_LOG_EMERG(r, format, ...) { \
    AP_LOG_WRITE(APLOG_EMERG, r, format, ## __VA_ARGS__); }     /* system is unusable */


/************************/
/* Functions signatures */
/************************/

/**
 * \brief    Retrieve "content_length" header value
 * \details  Retrieve "content_length" header value and return the integer
 * \param    headers    The headers table
 * \return   0 is header not found, the casted value otherwize
 */
long get_content_len(apr_table_t *headers);

/**
 * \brief    Calculate the headers length + request length
 * \details  Calculate the headers length + request length and return result
 * \param    r      A pointer to the request structure
 * \return   The calculated size
 */
apr_size_t get_headers_in_len(request_rec *r);

/**
 * \brief    Perform the levenshtein distance
 * \details  Calculate the levenshtein distance between word1 & word2
 * \param    word1      The word 1
 * \param    word2      The word 2
 * \param    len1       The word 1 length
 * \param    len2       The word 2 length
 * \return   The levenshtein distance calculated
 */
size_t levenshtein(const char *word1, const char *word2, size_t len1, size_t len2);

/**
 * \brief    Set the request length in request notes
 * \details  Set a key and value in request notes
 * \param    r              A pointer to the request structure
 * \param    bytes_recv     The value to set in request notes
 * \param    note_key       The key of the value to set in notes
 * \return   void
 */
void set_request_len_in_notes(request_rec *r, apr_size_t bytes_recv, const char* note_key);

/**
 * \brief    Retrieve the request_length in request notes
 * \details  Retrieve, convert and return a value in request notes
 * \param    r              A pointer to the request structure
 * \param    note_key       The key of the value to set in notes
 * \param    logger         The logger to use to log
 * \return   The retrieven value from notes
 */
int get_request_len_from_notes(request_rec *r, const char* note_key, const char *logger);


#endif //MOD_SVM_SVM_UTIL_H
