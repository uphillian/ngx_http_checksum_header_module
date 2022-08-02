/*
 * Add a checksum header for files served by nginx
 */

#define OPENSSL_NO_DEPRECATED_3_0 1

#include<ngx_config.h>
#include<ngx_core.h>
#include<ngx_http.h>
#include<ngx_md5.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
//sprintf
#include<stdio.h>

static ngx_int_t ngx_http_checksum_header_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_checksum_header_filter(ngx_http_request_t *r);
static void * ngx_http_checksum_header_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_checksum_header_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

// module conf type
typedef struct{
    ngx_str_t checksum;
} ngx_http_checksum_header_loc_conf_t;

// Get the size of the file by its file descriptor
unsigned long get_size_by_fd(int fd) {
    struct stat statbuf;
    if (fstat(fd, &statbuf) < 0) exit(-1);
    return statbuf.st_size;
}

// return a checksum for the file passed by filename, use the function passed by reference
unsigned char *checksum_for_file(char *filename,unsigned char *(*checksum_function)(const unsigned char *, long unsigned int, unsigned char*), int digest_length) {
    int file_descript;
    unsigned long file_size;
    char *file_buffer;
    unsigned char *result = malloc(sizeof(*result) * digest_length);
    if (NULL == result) {
        printf("malloc failed\n");
        goto END;
    }

    file_descript = open(filename, O_RDONLY);
    if (file_descript < 0) exit(-1);

    file_size = get_size_by_fd(file_descript);

    file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
    checksum_function((unsigned char *) file_buffer, file_size, result);
    munmap(file_buffer, file_size);

    END:
    return result;
}

// Module config-file language
// checksum_header md5|sha256|sha512;
static ngx_command_t ngx_http_checksum_header_commands[] = {
    {
        ngx_string("checksum_header"),                           //name
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,                        //type use in location, take one value (md5,sha256,sha512)
        ngx_conf_set_str_slot,                                   //set string
        NGX_HTTP_LOC_CONF_OFFSET,                                //save in location conf
        offsetof(ngx_http_checksum_header_loc_conf_t, checksum), //where it goes
        NULL                                                     //nginx magic var
    },
    ngx_null_command //nginx magic var
};

//module context
static ngx_http_module_t ngx_http_checksum_header_module_ctx = {
    NULL,                           //preconf
    ngx_http_checksum_header_init,  //postconf

    NULL,       //create main conf
    NULL,       //init main conf

    NULL,       //create server conf
    NULL,       //merge server conf

    ngx_http_checksum_header_create_loc_conf,
    ngx_http_checksum_header_merge_loc_conf
};

// Methods to init the module
static ngx_int_t ngx_http_checksum_header_init(ngx_conf_t *cf) {

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_checksum_header_filter;

    return NGX_OK;
}

// Create empty config context
static void* ngx_http_checksum_header_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_checksum_header_loc_conf_t *conf;
    ngx_str_t checksum;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_checksum_header_loc_conf_t));
    if(conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->checksum = checksum;
    return conf;
}

// Read the config, check if checksum_header is one of md5, sha256 or sha512
static char* ngx_http_checksum_header_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_checksum_header_loc_conf_t *conf = child;

    if (
      (strncmp((char *)conf->checksum.data, "sha512",conf->checksum.len) != 0) &&
      (strncmp((char *)conf->checksum.data, "sha256",conf->checksum.len) != 0) &&
      (strncmp((char *)conf->checksum.data, "md5",conf->checksum.len) != 0)
    ) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "checksum_filter must be sha512, sha256 or md5");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

//create the nginx module context
ngx_module_t ngx_http_checksum_header_module = {
    NGX_MODULE_V1,
    &ngx_http_checksum_header_module_ctx,
    ngx_http_checksum_header_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

//add a header with the value of the appropriate checksum
static ngx_int_t ngx_http_checksum_header_filter(ngx_http_request_t *r)
{
  int            i;
	u_char        *p;
	size_t         root;
	ngx_str_t      path;
  int            digest_length;
  unsigned char *(*checksum_function)(const unsigned char *, long unsigned int,  unsigned char *);

  p = ngx_http_map_uri_to_path( r, &path, &root, 0 );
	if ( p == NULL ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_http_checksum_header_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_checksum_header_module);

  //content_checksum is the header container, add it to the list of headers
  ngx_table_elt_t *content_checksum = ngx_list_push(&r->headers_out.headers);
  content_checksum->hash = 1;

  //set the value of the header title
  //set the length of the checksum digest, create a pointer to the checksumming function (MD5, SHA256 or SHA512)
  if (strncmp((char *)conf->checksum.data, "sha512",conf->checksum.len) == 0) {
    content_checksum->key.len = sizeof("X-Checksum-Sha512") - 1;
    content_checksum->key.data = (u_char*) "X-Checksum-Sha512";
    digest_length = SHA512_DIGEST_LENGTH;
    checksum_function = SHA512;
  } else if (strncmp((char *)conf->checksum.data, "sha256",conf->checksum.len) == 0) {
    content_checksum->key.len = sizeof("X-Checksum-Sha256") - 1;
    content_checksum->key.data = (u_char*) "X-Checksum-Sha256";
    digest_length = SHA256_DIGEST_LENGTH * 2;
    checksum_function = SHA256;
  } else if (strncmp((char *)conf->checksum.data, "md5", conf->checksum.len) == 0) {
    content_checksum->key.len = sizeof("Content-MD5") - 1;
    content_checksum->key.data = (u_char*) "Content-MD5";
    digest_length = MD5_DIGEST_LENGTH * 2;
    checksum_function = MD5;
  } else {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  //run the checksum_function on the file
  unsigned char *checksum = malloc(sizeof(*checksum) * digest_length);
  checksum = checksum_for_file((char *)path.data, checksum_function, digest_length);

  //add the checksum to the header value
  content_checksum->value.data = ngx_pcalloc(r->pool, sizeof(char *) * digest_length);
  content_checksum->value.len = sizeof(*checksum) * digest_length;
  for (i = 0; i < digest_length; i++) {
    sprintf((char *) (content_checksum->value.data + (2*i)), "%02x", checksum[i]);
  }

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Checksum: Added Checksum Header %s:%s",
      content_checksum->key.data,content_checksum->value.data);
  return ngx_http_next_header_filter(r);
}
