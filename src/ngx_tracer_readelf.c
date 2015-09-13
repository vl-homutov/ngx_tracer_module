
/*
 * Copyright 2015 (C) Homutov Vladimir
 */

/*
 *  This file is part or ngx_tracer_module.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the FREE sOFTWare
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */


/*
 * functions to parse output of the 'readelf' utility and obtain DWARFv4
 * descriptions of all functions found in nginx binary.
 */

#include "ngx_tracer.h"


#define ngxt_type_is_final(tag)                                               \
    (((tag) == NGXT_DW_TAG_pointer_type)                                      \
     || ((tag) == NGXT_DW_TAG_base_type)                                      \
     || ((tag) == NGXT_DW_TAG_structure_type))


/* recognizable DIE tags */
typedef enum {
    NGXT_DW_TAG_NONE = 0,
    NGXT_DW_TAG_pointer_type,
    NGXT_DW_TAG_base_type,
    NGXT_DW_TAG_structure_type,
    NGXT_DW_TAG_formal_parameter,
    NGXT_DW_TAG_subprogram,
    NGXT_DW_TAG_typedef,
    NGXT_DW_TAG_OTHER,
    /* TODO: NGXT_DW_TAG_unspecified_parameters - f(x,...) - variable args */
} ngxt_dwarf_tags_t;


/* line types */
typedef enum {
    NGXT_LT_DIE_DECL = 0,               /* DIE declaration with tag */
    NGXT_LT_DW_AT_name,                 /* DIE attributes */
    NGXT_LT_DW_AT_type,
    NGXT_LT_DW_AT_byte_size,
    NGXT_LT_DW_AT_location,
    NGXT_LT_DW_AT_encoding,
    NGXT_LT_IGNORED,                    /* everything else */
} ngxt_dwarf_line_types_t;


typedef enum {
    ignoring,                           /* just started and non-DIEs */
    in_die,                             /* processing DIE */
    in_function,                        /* processing function */
    in_function_param                   /* processing formal parameter */
} ngxt_die_parser_mode_t;


/* DWARF Information Entry */
typedef struct {
    ngx_uint_t               offset;    /* binary offset in ELF file */
    ngxt_dwarf_tags_t        tag;
    ngx_str_t                name;      /* DW_AT_name attribute value */
    size_t                   bytes;     /* DW_AT_byte_size attribute value */
    ngxt_dwarf_encodings_t   encoding;  /* DW_AT_encoding attribute value */
    ngxt_func_t             *func;      /* non-NULL for DW_AT_subprogram DIEs */
} ngxt_die_t;


typedef struct {
    ngx_uint_t               fcount;     /* number of functions found */
    ngx_uint_t               max_offset; /* maximum die offset seen */
    ngxt_die_parser_mode_t   mode;       /* parsing state */
    ngxt_die_t              *dies;       /* array of ALL dies in ELF file */
    ngxt_die_t              *curr_die;   /* currently ngxt_processing die */
    ngxt_die_t              *func_die;   /* die containing current function */
    ngxt_func_t             *funcs;      /* head of found functions list */
    ngxt_func_t             *tail;       /* tail of found functions list */
} ngxt_die_parser_state_t;


static char *ngxt_die_tags[] = {
    "DW_TAG_pointer_type",
    "DW_TAG_base_type",
    "DW_TAG_structure_type",
    "DW_TAG_formal_parameter",
    "DW_TAG_subprogram",
    "DW_TAG_typedef",
    NULL
};

static char *ngxt_line_types[] = {
    "Abbrev Number:",
    "DW_AT_name",
    "DW_AT_type",
    "DW_AT_byte_size",
    "DW_AT_location",
    "DW_AT_encoding",
    NULL
};

static char *ngxt_known_types[] = {
    "char",                             /* NGXT_TYPE_HINT_CHAR     */
    "ngx_str_t",                        /* NGXT_TYPE_HINT_NGXSTR   */
    "ngx_connection_t",                 /* NGXT_TYPE_HINT_CONN     */
    "ngx_http_request_t",               /* NGXT_TYPE_HINT_HTTP_REQ */
    NULL
};


static ngxt_decl void ngxt_merge_symbols(ngxt_func_t **fp, int fcount,
    ngxt_func_symbol_t *symbols, int symcount);
static ngxt_decl ngx_uint_t ngxt_get_tag(u_char *tag);
static ngxt_decl ngx_uint_t ngxt_get_line_type(u_char *line);
static ngxt_decl ngx_uint_t ngxt_get_hint_type(u_char *typename);
static ngxt_decl int ngxt_cmp_funcp(const void *a, const void *b);
static ngxt_decl int ngxt_cmp_func_by_key(const void *key, const void *b);
static ngxt_decl ngx_int_t ngxt_str2int(u_char *s, int base, ngx_int_t *result);
static ngxt_decl ngx_str_t ngxt_get_last_token(u_char *line, size_t len);
static ngxt_decl ngx_int_t ngxt_get_dw_name(u_char *line, size_t len,
    ngx_str_t *result);
static ngxt_decl ngx_int_t ngxt_get_dw_type(u_char *line, size_t len,
    ngx_int_t *result);
static ngxt_decl ngx_int_t ngxt_get_dw_location(u_char *line, size_t len,
    ngx_int_t *result);
static ngxt_decl ngx_uint_t ngxt_get_dw_bytes(u_char *line, size_t len,
    ngx_int_t *result);
static ngxt_decl ngx_uint_t ngxt_get_dw_encoding(u_char *line, size_t len,
    ngx_int_t *result);
static ngxt_decl ngxt_die_t *ngxt_die_found(ngxt_die_parser_state_t *ctx,
    u_char *line, size_t len);
static ngxt_decl ngx_int_t ngxt_parse_line(ngxt_die_parser_state_t *ctx,
    u_char *line, size_t len);
static ngxt_decl ngxt_func_t **ngxt_extract_functions(
    ngxt_die_parser_state_t *ctx);
static ngxt_decl ngxt_dwarf_type_t ngxt_resolve_type(ngxt_die_t *dwarr,
    ngx_uint_t offset);
static ngxt_decl ngxt_func_t **ngxt_process(ngxt_die_parser_state_t *ctx,
    int fd);
#if (NGXT_DEBUG)
static ngxt_decl void ngxt_pretty_print_func(ngxt_func_t *f);
static ngxt_decl int ngxt_dump_type(ngxt_dwarf_type_t *type);
static ngxt_decl void ngxt_dump_funcs(ngxt_func_t **fp, ngx_uint_t fcount);
#endif


static ngx_uint_t
ngxt_get_tag(u_char *tag)
{
    ngx_uint_t  i;

    for (i = 0; ngxt_die_tags[i]; i++) {
        if (ngx_strcmp(ngxt_die_tags[i], tag) == 0) {
            return i + 1;
        }
    }

    return NGXT_DW_TAG_OTHER;
}


static ngx_uint_t
ngxt_get_line_type(u_char *line)
{
    ngx_uint_t  i;

    for (i = 0; ngxt_line_types[i]; i++) {
        if (ngx_strstr(line, ngxt_line_types[i])) {
            return i;
        }
    }

    return NGXT_LT_IGNORED;
}


static ngx_uint_t
ngxt_get_hint_type(u_char *typename)
{
    ngx_uint_t  i;

    for (i = 0; ngxt_known_types[i]; i++) {
        if (ngx_strstr(typename, ngxt_known_types[i])) {
            return i + 1;
        }
    }

    return NGXT_TYPE_HINT_VOID;
}


static ngxt_dwarf_type_t
ngxt_resolve_type(ngxt_die_t *dwarr, ngx_uint_t offset)
{
    ngxt_dwarf_type_t    type;
    ngx_uint_t  tag, type_offset;

    type_offset = 0;

    do {
        tag = dwarr[offset].tag;
        if (tag == NGXT_DW_TAG_typedef) {
            type_offset = offset;
        }
        offset = dwarr[offset].offset;

    } while (!ngxt_type_is_final(tag));


    switch (tag) {
    case NGXT_DW_TAG_pointer_type:
        type.type = NGXT_DWARF_TYPE_PTR;
        type_offset = offset;
        break;
    case NGXT_DW_TAG_base_type:
        type.type = NGXT_DWARF_TYPE_BASE;
        break;
    case NGXT_DW_TAG_structure_type:
        type.type = NGXT_DWARF_TYPE_AGREG;
        break;
    default:
        type.type = NGXT_DWARF_TYPE_OTHER;
    }

    type.bytes = dwarr[offset].bytes;
    type.encoding = dwarr[offset].encoding;

    /* take a look into pointed type... */

    if (type_offset && dwarr[type_offset].name.data) {
        type.hint = ngxt_get_hint_type(dwarr[type_offset].name.data);

    } else {
        type.hint = 0;
    }

    return type;
}


static ngx_int_t
ngxt_str2int(u_char *s, int base, ngx_int_t *result)
{
    ngx_int_t  res;

    errno = 0;
    res = strtol((char*)s, NULL, base);
    if ((errno == ERANGE && (res == LONG_MAX || res == LONG_MIN))
            || (errno != 0 && res == 0))
    {
        fprintf(stderr, "offset conversion: %s\n", strerror(errno));
        return NGX_ERROR;
    }

    *result = res;

    return NGX_OK;
}


static ngx_str_t
ngxt_get_last_token(u_char *line, size_t len)
{
    u_char    *p;
    ngx_str_t  res;

    /* start from the right */
    p = &line[len - 1];

    /* skip non-letters */
    while (!isalnum(*p)) { p--; }

    /* last token letter */
    res.data = p--;

    /* token itself: functions names/negative /hex/decimal numbers */
    while (isalnum(*p) || *p == '_' || *p == '-') { p--; }

    res.len = res.data - p;
    res.data = p + 1;

    return res;
}


/*
 * <c1f9>   DW_AT_name        : buf>---
 */
static ngx_int_t
ngxt_get_dw_name(u_char *line, size_t len, ngx_str_t *result)
{
    ngx_str_t  token, res;

    token = ngxt_get_last_token(line, len);

    res.data = malloc(token.len + 1);
    if (res.data == NULL) {
        perror("malloc");
        return NGX_ERROR;
    }

    memcpy(res.data, token.data, token.len);
    res.len = token.len;
    res.data[token.len] = 0;

    *result = res;

    return NGX_OK;
}


/*
 * <c1ff>   DW_AT_type        : <0x67f9>>--
 */
static ngx_int_t
ngxt_get_dw_type(u_char *line, size_t len, ngx_int_t *result)
{
    ngx_str_t  token;

    token = ngxt_get_last_token(line, len);

    return ngxt_str2int(token.data, 16, result);
}


/*
 *  <c1f5>   DW_AT_location    : 2 byte block: 91 6c >--(DW_OP_fbreg: -20)
 */
static ngx_int_t
ngxt_get_dw_location(u_char *line, size_t len, ngx_int_t *result)
{
    ngx_str_t  token;

    /* TODO: handle different types: (now just assume DW_OP_fbreg) */

    token = ngxt_get_last_token(line, len);

    return ngxt_str2int(token.data, 10, result);
}


/*
 * <6773>   DW_AT_byte_size   : 8>-
 */
static ngx_uint_t
ngxt_get_dw_bytes(u_char *line, size_t len, ngx_int_t *result)
{
    ngx_str_t  token;

    token = ngxt_get_last_token(line, len);

    return ngxt_str2int(token.data, 10, result);
}


/*
 * <6743>   DW_AT_encoding    : 8>-(unsigned char)
 */
static ngx_uint_t
ngxt_get_dw_encoding(u_char *line, size_t len, ngx_int_t *result)
{
    u_char     *p;
    ngx_str_t   token;

    /* start from right */
    p = &line[len - 1];
    /* find end of interesting piece */
    while (*p != '(') { p--; }
    /* skip non-letters */
    while (!isalnum(*p)) { p--; }

    /* end of token is here */
    token.data = p--;

    /* encoding is a positive decimal */
    while (isdigit(*p)) { p--; }

    token.len = token.data - p;
    token.data = p + 1;

    /* replace original symbol */
    token.data[token.len] = 0;


    return ngxt_str2int(token.data, 10, result);
}


/*
 *  <1><c1ca>: Abbrev Number: 43 (NGXT_DW_TAG_subprogram)
 */
static ngxt_die_t*
ngxt_die_found(ngxt_die_parser_state_t *ctx, u_char *line, size_t len)
{
    ngxt_die_t       *die;
    u_char      *p, *offset_token;
    ngx_str_t    tag_token;
    ngx_uint_t   offset;
    ngx_int_t   xoffset;

    tag_token = ngxt_get_last_token(line, len);
    tag_token.data[tag_token.len] = 0;

    p = line;
    while (*p++ != '<') {}
    while (*p++ != '<') {}

    offset_token = p;

    while (*p++ != '>') {}
    offset_token[p - offset_token] = 0;

    if (ngxt_str2int(offset_token, 16, &xoffset) != NGX_OK) {
        return NULL;
    }
    offset = xoffset;

    if (offset > NGXT_DIES_MAX) {
        fprintf(stderr, "Ooops, file too big, too many DIEs: offset=%lx\n",
                                                                       offset);
        return NULL;
    }

    if (offset > ctx->max_offset) {
        ctx->max_offset = offset;
    }

    die = &ctx->dies[offset];
    die->offset = offset;

    die->tag = ngxt_get_tag(tag_token.data);

    return die;
}


static ngx_int_t
ngxt_parse_line(ngxt_die_parser_state_t *ctx, u_char *line, size_t len)
{
    ngxt_func_arg_t       *param;
    ngx_int_t      res;
    ngx_uint_t     ltype;
    ngxt_func_t  *curr_func;

#if (NGXT_DEBUG_DWARF)
    printf(">> %s\n", line);
#endif

    ltype = ngxt_get_line_type(line);

#if (NGXT_DEBUG_DWARF)
    printf("\tline type: %ld\n", ltype);
#endif

    switch (ltype) {
    case NGXT_LT_DIE_DECL:

        if (line[len - 1] == '0') {
            /* Abbrev Number: 0 */

            /* end group */
            ctx->curr_die = NULL;
            ctx->func_die = NULL;

#if (NGXT_DEBUG_DWARF)
            printf("\t - NULL Abbrev, terminate currents\n");
#endif

            return NGX_OK;
        }

        ctx->curr_die = ngxt_die_found(ctx, line, len);
        if (ctx->curr_die == NULL) {
            return NGX_ERROR;
        }

        switch (ctx->curr_die->tag) {
        case NGXT_DW_TAG_subprogram:
#if (NGXT_DEBUG_DWARF)
            printf("\tnew subprogram, fcount = %ld\n", ctx->fcount);
#endif
            ctx->mode = in_function;

            curr_func = calloc(1, sizeof(ngxt_func_t));
            if (curr_func == NULL) {
                perror("malloc");
                return NGX_ERROR;
            }

            if (ctx->funcs == NULL) {
                ctx->funcs = curr_func;
                ctx->tail = curr_func;

            } else {
                ctx->tail->next = curr_func;
                ctx->tail = curr_func;
            }

            ctx->curr_die->func = curr_func;
            ctx->func_die = ctx->curr_die;

            ctx->fcount++;
            break;

        case NGXT_DW_TAG_formal_parameter:

            if (ctx->func_die == NULL) {
                /* subroutine/other entity with parameters */
#if (NGXT_DEBUG_DWARF)
                printf("\tignored (param)\n");
#endif
                return NGX_OK;
            }

            ctx->mode = in_function_param;


            curr_func = ctx->func_die->func;

#if (NGXT_DEBUG_DWARF)
            printf("\tnew param, argc = %ld\n", curr_func->argc);
#endif
            param = malloc(sizeof(ngxt_func_arg_t));
            if (param == NULL) {
                perror("malloc");
                return NGX_ERROR;
            }
            param->next = NULL;

            if (curr_func->argv == NULL) {
                curr_func->argv = param;
                curr_func->last_arg = param;

            } else {
                curr_func->last_arg->next = param;
                curr_func->last_arg = param;
            }

            curr_func->argc++;

            break;

        default:
            ctx->mode = in_die;
#if (NGXT_DEBUG_DWARF)
            printf("\tswitched to DIE mode\n");
#endif
        }
        break;

    case NGXT_LT_DW_AT_name:

        switch (ctx->mode) {
        case in_function:
            if (ngxt_get_dw_name(line, len, &ctx->curr_die->func->name)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
#if (NGXT_DEBUG_DWARF)
            printf("\tfunction name: %s\n", ctx->curr_die->func->name.data);
#endif

            break;
        case in_function_param:

            if (ngxt_get_dw_name(line, len,
                                 &ctx->func_die->func->last_arg->name)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
#if (NGXT_DEBUG_DWARF)
            printf("\tparam name: %s\n",
                                     ctx->func_die->func->last_arg->name.data);
#endif
            break;

        case in_die:

            if (ngxt_get_dw_name(line, len, &ctx->curr_die->name) != NGX_OK) {
                return NGX_ERROR;
            }
#if (NGXT_DEBUG_DWARF)
            printf("\tdie name: %s\n", ctx->curr_die->name.data);
#endif
            break;

        default:
#if (NGXT_DEBUG_DWARF)
            printf("\tignored (name)\n");
#endif

            return NGX_OK;
        }
        break;

    case NGXT_LT_DW_AT_type:

        switch (ctx->mode) {
        case in_die:
            if (ngxt_get_dw_type(line, len, &res) != NGX_OK) {
                return NGX_ERROR;
            }
            ctx->curr_die->offset = res;
#if (NGXT_DEBUG_DWARF)
            printf("\tDIE type: offset=0x%lx\n", ctx->curr_die->offset);
#endif
            break;
        case in_function:

            if (ngxt_get_dw_type(line, len, &res) != NGX_OK) {
                return NGX_ERROR;
            }
            ctx->curr_die->func->rtype.offset = res;
#if (NGXT_DEBUG_DWARF)
            printf("\tfunction return type: offset=0x%lx\n",
                                            ctx->curr_die->func->rtype.offset);
#endif
            break;
        case in_function_param:
            if (ngxt_get_dw_type(line, len, &res) != NGX_OK) {
                return NGX_ERROR;
            }
            ctx->func_die->func->last_arg->type.offset = res;
#if (NGXT_DEBUG_DWARF)
            printf("\tparam type: offset=0x%lx\n",
                                   ctx->func_die->func->last_arg->type.offset);
#endif
            break;
        default:
#if (NGXT_DEBUG_DWARF)
            printf("\tignored (type offset)\n");
#endif
            return NGX_OK;
        }
        break;

    case NGXT_LT_DW_AT_byte_size:

        switch (ctx->mode) {
        case in_die:
            if (ngxt_get_dw_bytes(line, len, &res) != NGX_OK) {
                return NGX_ERROR;
            }
            ctx->curr_die->bytes = res;
#if (NGXT_DEBUG_DWARF)
            printf("\tDIE byte size: %ld\n", ctx->curr_die->bytes);
#endif
            break;
        default:
#if (NGXT_DEBUG_DWARF)
            printf("\tignored (bytes)\n");
#endif
            return NGX_OK;
        }
        break;

    case NGXT_LT_DW_AT_location:

        switch (ctx->mode) {
        case in_function_param:
            if (ngxt_get_dw_location(line, len, &res) != NGX_OK) {
                return NGX_ERROR;
            }
            ctx->func_die->func->last_arg->location = res;
#if (NGXT_DEBUG_DWARF)
            printf("\tparam location: %ld\n",
                                      ctx->func_die->func->last_arg->location);
#endif
            break;
        default:
#if (NGXT_DEBUG_DWARF)
            printf("\tignored (location)\n");
#endif
            return NGX_OK;
        }
        break;

    case NGXT_LT_DW_AT_encoding:

        switch (ctx->mode) {
        case in_die:
            if (ngxt_get_dw_encoding(line, len, &res) != NGX_OK) {
                return NGX_ERROR;
            }
            ctx->curr_die->encoding = res;
#if (NGXT_DEBUG_DWARF)
            printf("\tDIE encoding: %d\n", ctx->curr_die->encoding);
#endif
            break;
        default:
#if (NGXT_DEBUG_DWARF)
            printf("\tignored (encoding)\n");
#endif
            return NGX_OK;
        }
        break;

    default:
        /* ignore */
#if (NGXT_DEBUG_DWARF)
            printf("\tignored (unknown)\n");
#endif
        return NGX_OK;
    }

    return NGX_OK;
}


static ngxt_func_t**
ngxt_extract_functions(ngxt_die_parser_state_t *ctx)
{
    ngxt_func_arg_t       *param;
    ngx_uint_t     i;
    ngxt_func_t  *curr_func, **fp;

    /* resolve types in functions declarations */
    for (i = 0; i < ctx->max_offset; i++) {
        if (ctx->dies[i].tag == NGXT_DW_TAG_NONE) {
            /* skip empty dies */
            continue;
        }

        if (ctx->dies[i].func) {

            curr_func = ctx->dies[i].func;

            if (curr_func->rtype.offset) {
                curr_func->rtype = ngxt_resolve_type(ctx->dies,
                                                      curr_func->rtype.offset);

            } else {
                curr_func->rtype.type = NGXT_DWARF_TYPE_NONE;
                /* unused for void */
                curr_func->rtype.bytes = 0;
                curr_func->rtype.encoding = 7; /* unsigned int */
            }

            for (param = curr_func->argv; param; param = param->next) {
                param->type = ngxt_resolve_type(ctx->dies, param->type.offset);
            }
        }
    }

    fp = malloc(sizeof(ngxt_func_t*) * ctx->fcount);
    if (fp == NULL) {
        perror("malloc");
        return NULL;
    }

    i = 0;
    curr_func = ctx->funcs;
    while (curr_func) {
        fp[i++] = curr_func;
        curr_func = curr_func->next;
    }

    return fp;
}


static ngxt_func_t **
ngxt_process(ngxt_die_parser_state_t *ctx, int fd)
{
    u_char buf[NGXT_PARSER_BUF_SIZE];
    u_char linebuf[NGXT_PARSER_MAXLINE];

    ssize_t         n;
    ngx_uint_t      i, k;
    ngxt_func_t  **fp;

    ctx->dies = calloc(NGXT_DIES_MAX, sizeof(ngxt_die_t));
    if (NULL == ctx->dies) {
        perror("calloc");
        return NULL;
    }

    k = 0;
    while (1) {
        n = read(fd, buf, NGXT_PARSER_BUF_SIZE);

        if (-1 == n) {
            perror("pipe read");
            return NULL;

        } else if (n == 0) {
            break;
        }

        for (i = 0; i < (size_t) n; i++) {
            if (k == NGXT_PARSER_MAXLINE) {
                fprintf(stderr, "Line too long, rewriting head\n");
                k = 0;
            }

            if (buf[i] != '\n') {
                linebuf[k++] = buf[i];

            } else {
                linebuf[k] = 0;
                if (ngxt_parse_line(ctx, linebuf, k) != NGX_OK) {
                    return NULL;
                }
                k = 0;
            }
        }
    }

    fp = ngxt_extract_functions(ctx);

    /* no longer needed, all types resolved, function list obtained */
    free(ctx->dies);

    return fp;
}


static int
ngxt_cmp_funcp(const void *a, const void *b)
{
    const ngxt_func_t **ap = (const ngxt_func_t **) a;
    const ngxt_func_t **bp = (const ngxt_func_t **) b;

    return ngx_strcmp((*ap)->name.data, (*bp)->name.data);
}


static int
ngxt_cmp_func_by_key(const void *key, const void *b)
{
     char *k1 = (char *) key;
     ngxt_func_t **f = (ngxt_func_t **) b;

     return strcmp(k1, (char *)(*f)->name.data);
}


static
void ngxt_merge_symbols(ngxt_func_t **fp, int fcount,
    ngxt_func_symbol_t *symbols, int symcount)
{
    int i;
    ngxt_func_t **res;

    for (i = 0; i < symcount ; i++) {

        res = bsearch(symbols[i].name, fp, fcount ,
                      sizeof(ngxt_func_t *), ngxt_cmp_func_by_key);
        if (res) {
            symbols[i].spec = *res;
        }
    }
}


ngx_int_t
ngxt_readelf(ngxt_ctx_t *nctx)
{
    const char  *envp[] = {"LANG=C", NULL};

    int               link[2], rc;
    pid_t             pid;
    ngxt_func_t    **fp;
    ngxt_die_parser_state_t    ctx;

    rc = pipe(link);
    if (-1 == rc) {
        fprintf(stderr, "pipe(): %s\n", strerror(errno));
        return NGX_ERROR;
    }

    pid = fork();
    if (-1 == pid) {
        fprintf(stderr, "fork(): %s\n", strerror(errno));
        return NGX_ERROR;
    }

    if(pid == 0) {
        dup2 (link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);
        execle(NGX_TRACER_READELF_PATH, "readelf", "-wi", nctx->progname,
                                                                   NULL, envp);
        ngxt_die(errno, "exec(file='%s',prog='%s')",NGX_TRACER_READELF_PATH,
                                                               nctx->progname);
    } else {
        inform(("executing readelf to obtain debuginfo...\n"));
    }

    close(link[1]);

    ctx.mode = ignoring;
    ctx.fcount = 0;
    ctx.max_offset  = 0;
    ctx.funcs = NULL;
    ctx.tail = NULL;
    ctx.curr_die = NULL;
    ctx.func_die = NULL;

    inform(("please wait, parsing readelf's output...\n"));

    fp = ngxt_process(&ctx, link[0]);

    wait(NULL);

    if (ctx.fcount == 0) {
        fprintf(stderr, "No functions found in output, possible reasonse are:"
                        "\n  no DWARF symbols in file"
                        "\n  readelf output changed\n");

        return NGX_ERROR;
    }

    inform(("building function declarations index (%ld found)...\n",
                                                                  ctx.fcount));
    qsort(fp, ctx.fcount, sizeof(ngxt_func_t*), ngxt_cmp_funcp);

    ngxt_merge_symbols(fp, ctx.fcount, nctx->symbols, nctx->symcount);

#if NGXT_DEBUG
    inform(("Sorted function list:\n"));
    ngxt_dump_funcs(fp, ctx.fcount);
#endif

    return NGX_OK;
}


#if (NGXT_DEBUG)

static char*
ngxt_type_to_str(ngxt_dwarf_type_t *type)
{
    switch (type->type) {
    case NGXT_DWARF_TYPE_NONE:
        return "void";
    case NGXT_DWARF_TYPE_BASE:
        switch (type->encoding) {
        case NGXT_DWARF_ENC_FLOAT:
            return "float";
        case NGXT_DWARF_ENC_SIGNED:
            return "int";
        case NGXT_DWARF_ENC_SIGNED_CHAR:
            return "char";
        case NGXT_DWARF_ENC_UNSIGNED:
            return "uint";
        case NGXT_DWARF_ENC_UNSIGNED_CHAR:
            return "uchar";
        default:
            return "basic";
        }
    case NGXT_DWARF_TYPE_AGREG:
        return "agreg";
    case NGXT_DWARF_TYPE_PTR:
        return "ptr";
    default: /* NGXT_DWARF_TYPE_OTHER */
        return "other";
    }
}


static int
ngxt_dump_type(ngxt_dwarf_type_t *type)
{
    int num;

    num = printf("%s", ngxt_type_to_str(type));

    if (type->bytes) {
        num += printf("{%ld}", type->bytes);
    }

    if (type->hint) {
        num += printf(":%d", type->hint);
    }

    return num;
}


static void
ngxt_pretty_print_func(ngxt_func_t *f)
{
    ngxt_func_arg_t  *param;

    if (ngxt_dump_type(&f->rtype) <= 3) {
        printf("\t");
    }

    printf("\t%s(",f->name.data);

    if (f->argv == NULL) {
        printf(");\n");
        return;
    }

    for (param = f->argv; param; param = param->next) {

        ngxt_dump_type(&param->type);

        printf(" %s", param->name.data);
        if (param->next) {
            printf(", ");
        }
    }
    printf(");\n");
}


static void
ngxt_dump_funcs(ngxt_func_t **fp, ngx_uint_t fcount)
{
    ngx_uint_t  i;

    for (i = 0; i < fcount; i++) {
        printf("[%04ld/%04ld] ", i + 1, fcount);
        ngxt_pretty_print_func(fp[i]);
    }
}

#endif
