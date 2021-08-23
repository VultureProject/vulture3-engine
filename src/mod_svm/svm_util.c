#include "svm_util.h"

long get_content_len(apr_table_t *headers) {
    const char *content_len_str = apr_table_get(headers, "Content-Length");
    if (!content_len_str)
        return 0;
    return apr_atoi64(content_len_str);
}

void write_403(apr_bucket_brigade *bb, char *uri) {
    apr_brigade_printf(bb, NULL, NULL, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>403 Forbidden</title>\n"
            "</head><body>\n"
            "<h>Forbidden</h>\n"
            "<p>You don't have permission to access %s on this server.</p>\n"
            "<hr>\n"
            "<address>Vulture server</address>\n"
            "</body></html>\n", uri);
}

apr_size_t get_headers_in_len(request_rec *r) {
    // Retrieve each fields in the header's request in an array
    const apr_array_header_t *fields = apr_table_elts(r->headers_in);
    apr_table_entry_t *entry = (apr_table_entry_t *) fields->elts;

    apr_size_t headers_length = 0;
    // Loop which iterate thought each fields
    for (int i = 0; i < fields->nelts; i++) {
        headers_length += (strlen(entry[i].key) + strlen(entry[i].val) + strlen("\r\n\r\n"));
//        ap_log_rerror_(APLOG_MARK, APLOG_TRACE1, 0, r, "Header given %d %s:%s", i + 1, entry[i].key, entry[i].val);
    }
    headers_length += strlen("\r\n");

    // SVM add -> add headers_length in notes to retrieve it in other modules
    size_t firstLineLen = strlen(r->the_request) + strlen("\r\n");
    ap_log_rerror_(APLOG_MARK, APLOG_TRACE1, 0, r, "In: r->the_request (%lu): '%s'", firstLineLen, r->the_request);
    ap_log_rerror_(APLOG_MARK, APLOG_TRACE1, 0, r, "In: Headers length: %lu", headers_length);
    headers_length += firstLineLen;
    ap_log_rerror_(APLOG_MARK, APLOG_TRACE1, 0, r, "In: Req-URI + Headers len: %lu", headers_length);
    return headers_length;
}

/**
 *  Set bytes_recv in request notes with BYTES_READ_BYTES index
 */
void set_request_len_in_notes(request_rec *r, apr_size_t bytes_recv, const char *note_key) {
    // Transform req_len_str in char* and set it in r->notes to retrieve it in output_filter
    char *req_len_str = apr_palloc(r->pool, NB_MAX_DIGIT_INT * sizeof(char));
    apr_snprintf(req_len_str, NB_MAX_DIGIT_INT, "%lu", bytes_recv);
    apr_table_setn(r->notes, note_key, req_len_str);
}

/**
 *  Retrieve "BYTES_READ_NOTE" note from request, convert to int and return it
 */
int get_request_len_from_notes(request_rec *r, const char *note_key, const char *logger) {
    // Retrieve string from notes request
    const char *req_len_str = apr_table_get(r->notes, note_key);
    if (req_len_str == NULL)
        return -1;
    ap_log_rerror_(APLOG_MARK, APLOG_TRACE2, 0, r, "%s: request length: %s (str)", logger, req_len_str);
    return atoi(req_len_str); // Convert to int and return
}

/**
 *  // https://github.com/wooorm/levenshtein.c
 *  // MIT licensed.
 *  // Copyright (c) 2015 Titus Wormer <tituswormer@gmail.com>
 *
 * Returns a size_t, depicting the difference between `a` and `b`.
 * See <http://en.wikipedia.org/wiki/Levenshtein_distance> for more information.
 */
size_t levenshtein(const char *a, const char *b, size_t length, size_t bLength) {
    size_t *cache = calloc(length, sizeof(size_t));
    size_t index = 0;
    size_t bIndex = 0;
    size_t distance;
    size_t bDistance;
    size_t result;
    char code;

    // Shortcut optimizations / degenerate cases.
    if (a == b) {
        return 0;
    }

    if (length == 0) {
        return bLength;
    }

    if (bLength == 0) {
        return length;
    }

    // initialize the vector.
    while (index < length) {
        cache[index] = index + 1;
        index++;
    }

    // Loop.
    while (bIndex < bLength) {
        code = b[bIndex];
        result = distance = bIndex++;
        index = SIZE_MAX;

        while (++index < length) {
            bDistance = code == a[index] ? distance : distance + 1;
            distance = cache[index];

            cache[index] = result = distance > result
                                    ? bDistance > result
                                      ? result + 1
                                      : bDistance
                                    : bDistance > distance
                                      ? distance + 1
                                      : bDistance;
        }
    }

    free(cache);

    return result;
}
