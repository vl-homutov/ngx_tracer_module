
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
 * functions to pretty dump memory according to declared type
 */

#include <ngx_http.h>

#include "ngx_tracer.h"


#if (NGX_FREEBSD)

/* real file is used, as no device here with suitable semantics */
#define NGXT_WRT_DEV        NGX_PREFIX "./garbage"
#define NGXT_WRT_DEV_FLAGS  O_CREAT|O_WRONLY
#define NGXT_WRT_DEV_MODE   S_IRWXU

#else

#define NGXT_WRT_DEV        "/dev/random"
#define NGXT_WRT_DEV_FLAGS  O_WRONLY
#define NGXT_WRT_DEV_MODE   0

#endif


#define ngxt_deref(addr, type)  (*(type *) addr)

/* symbols to show in string dumps */
#define ngxt_isprint(c)                                                       \
    (isprint((c)) || (c) == '\t' || (c) == '\r' || (c) == '\n')

#define ngxt_bytes_readable(addr, bytes)                                      \
    ((ngxt_get_readable_size((addr), (bytes)) == (bytes)) ? 1 : 0)


typedef char *(*ngxt_type_handler_pt)(char *buf, char *last, void *p);


static ngxt_decl char *ngxt_dump_char_ptr(char *buf, char *last, void *p);
static ngxt_decl char *ngxt_dump_ngx_str_t(char *buf, char *last, void *p);
static ngxt_decl char *ngxt_dump_ngx_conn(char *buf, char *last, void *p);
static ngxt_decl char *ngxt_dump_ngx_http_req(char *buf, char *last, void *p);

static ngxt_decl char *ngxt_dump_chars(char *buf, char *last, char *s,
    size_t maxlen);
static ngxt_decl char *ngxt_retval_string(ngx_int_t code);
static ngxt_decl ngx_uint_t ngxt_get_readable_size(char *start,
    ngx_uint_t maxlen);


static int nullfd;

static ngxt_type_handler_pt  ngxt_type_handlers[] = {
    NULL,                     /* NGXT_TYPE_HINT_VOID     */
    ngxt_dump_char_ptr,       /* NGXT_TYPE_HINT_CHAR     */
    ngxt_dump_ngx_str_t,      /* NGXT_TYPE_HINT_NGXSTR   */
    ngxt_dump_ngx_conn,       /* NGXT_TYPE_HINT_CONN     */
    ngxt_dump_ngx_http_req,   /* NGXT_TYPE_HINT_HTTP_REQ */
};


void
ngxt_mem_init()
{
    nullfd = open(NGXT_WRT_DEV, NGXT_WRT_DEV_FLAGS, NGXT_WRT_DEV_MODE);

    if (nullfd == -1) {
        ngxt_die(errno, "failed to open '%s'", NGXT_WRT_DEV);
    }

#if (NGX_FREEBSD)
    {
    int  rc;

    rc = unlink(NGXT_WRT_DEV);
    if (rc == -1) {
        ngxt_die(errno, "failed to unlink '%s'", NGXT_WRT_DEV);
    }
    }
#endif
}


static char*
ngxt_retval_string(ngx_int_t code)
{
    switch (code) {
    case 0:
        return "NGX_OK";
    case -1:
        return "NGX_ERROR";
    case -2:
        return "NGX_AGAIN";
    case -3:
        return "NGX_BUSY";
    case -4:
        return "NGX_DONE";
    case -5:
        return "NGX_DECLINED";
    case -6:
        return "NGX_ABORT";
    default:
        return NULL;
    }
}


/* returns approximate number of bytes, readable from addr */
static ngx_uint_t
ngxt_get_readable_size(char *addr, ngx_uint_t maxlen)
{
    int         rc;
    ngx_uint_t  readable;

    readable = maxlen;

    while (readable > 0) {
        rc = write(nullfd, addr, readable);
        if (rc == -1) {
            if (errno == EFAULT) {
                /* try again with lesser interval */
                readable /= 2;
                continue;
            }
            /* something strange; to be safe, consider as unreadable */
            return 0;

        }
        /* ok, this works */
        break;
    }

    return readable;
}


static char*
ngxt_dump_char_ptr(char *buf, char *last, void *p)
{
    /* the length is unknown, hope that at least 64 bytes is readable */
    return ngxt_dump_chars(buf, last, p, 64);
}


static char *
ngxt_dump_ngx_str_t(char *buf, char *last, void *p)
{
    ngx_str_t *nsp =  p;

    if (!ngxt_bytes_readable(p, sizeof(ngx_str_t))) {
        return ngxt_sprintf(buf, last, "<unreadable>");
    }

    buf = ngxt_sprintf(buf, last, "{");
    buf = ngxt_dump_chars(buf, last, (char *) nsp->data, nsp->len);
    buf = ngxt_sprintf(buf, last, "}[%ld]", nsp->len);

    return buf;
}


static char *
ngxt_dump_ngx_conn(char *buf, char *last, void *p)
{
    ngx_connection_t *c = p;

    if (!ngxt_bytes_readable(p, sizeof(ngx_connection_t))) {
        return ngxt_sprintf(buf, last, "<unreadable>");
    }

    return ngxt_sprintf(buf, last, "*%lu c.data=%p,c.fd=%d",
                        c->log->connection, c->data, c->fd);
}


static char *
ngxt_dump_ngx_http_req(char *buf, char *last, void *p)
{
    ngx_http_request_t *r = p;

    if (!ngxt_bytes_readable(p, sizeof(ngx_http_request_t))) {
        return ngxt_sprintf(buf, last, "<unreadable>");
    }

    return ngxt_sprintf(buf, last, "*%lu", r->connection->log->connection);
}


/* very simple memory decoder based on type information from DWARF */
char *
ngxt_dump_value(char *buf, char *last, void *p, ngxt_dwarf_type_t *type)
{
    char      *ptr, *errs, *fmt;
    long int   val;

    if (p == NULL) {
        /* bug? */
        return ngxt_sprintf(buf, last, "<NOPTR>");
    }

    switch(type->type) {

    case NGXT_DWARF_TYPE_NONE:
        /* should never happen, no variable can have 'void' type */
        return buf;

    case NGXT_DWARF_TYPE_BASE:

        switch (type->encoding) {

        case NGXT_DWARF_ENC_FLOAT:
            buf = ngxt_sprintf(buf, last,"%.2f", ngxt_deref(p, float));
            break;

        case NGXT_DWARF_ENC_SIGNED:

            if (type->bytes == sizeof(int)) {
                val = *(int *) p;
                fmt = "%d";

            } else {
                val = *(long int *) p;
                fmt = "%ld";
            }

            errs = ngxt_retval_string(val);

            if (errs) {
                buf = ngxt_sprintf(buf, last, "%s", errs);

            } else {
                buf = ngxt_sprintf(buf, last, fmt, val);
            }

            break;

        case NGXT_DWARF_ENC_SIGNED_CHAR:
            buf = ngxt_sprintf(buf, last, "%c", ngxt_deref(p, char));
            break;

        case NGXT_DWARF_ENC_UNSIGNED:

            if (type->bytes == sizeof(unsigned int)) {
                buf = ngxt_sprintf(buf, last, "%u",
                                                  ngxt_deref(p, unsigned int));

            } else {
                buf = ngxt_sprintf(buf, last, "%lu",
                                             ngxt_deref(p, long unsigned int));
            }
            break;

        case NGXT_DWARF_ENC_UNSIGNED_CHAR:
            buf = ngxt_sprintf(buf, last, "'%c'", ngxt_deref(p, unsigned char));
            break;

        default:
            buf = ngxt_sprintf(buf, last,"<?enc>");
        }
        break;

    case NGXT_DWARF_TYPE_AGREG:

        buf = ngxt_sprintf(buf, last, "{{");

        if (type->hint) {
            buf = ngxt_type_handlers[type->hint](buf, last, p);

        } else {
            buf = ngxt_sprintf(buf, last, "struct");
        }

        buf = ngxt_sprintf(buf, last, "}}");

        break;

    case NGXT_DWARF_TYPE_PTR:

        ptr = ngxt_deref(p, char *);

        buf = ngxt_sprintf(buf, last, "%p", ptr);

        if (!type->hint || ptr == NULL) {
            return buf;
        }

        buf = ngxt_sprintf(buf, last, "<");
        buf = ngxt_type_handlers[type->hint](buf, last, ptr);
        buf = ngxt_sprintf(buf, last, ">");

        break;

    default: /* NGXT_DWARF_TYPE_OTHER */
        buf = ngxt_sprintf(buf, last, "<type?>");
        break;
    }
    return buf;
}


static char *
ngxt_dump_chars(char *buf, char *last, char *s, size_t maxlen)
{
    char        *sp;
    ngx_uint_t   cnt, rsize;

    rsize = ngxt_get_readable_size(s, maxlen);

    if (rsize != maxlen) {
        return ngxt_sprintf(buf, last, "\"<unreadable:%ld/%ld>\"",
                            rsize, maxlen);
    }

    if (rsize == 0) {
        return ngxt_sprintf(buf, last, "<empty>");
    }

    buf = ngxt_sprintf(buf, last, "\"");
    for (sp = s, cnt = 0;
         sp != 0 && ngxt_isprint(*sp) && cnt < maxlen;
         sp++, cnt++)
    {
        switch (*sp) {
            case '\n':
                buf = ngxt_sprintf(buf, last, "\\n");
                break;
            case '\r':
                buf = ngxt_sprintf(buf, last, "\\r");
                break;
            case '\t':
                buf = ngxt_sprintf(buf, last, "\\t");
                break;
            default:
                buf = ngxt_sprintf(buf, last, "%c", *sp);
        }
    }

    if (cnt == 0) {
        /* nothing printable, binary data or uninitialized buffer */
        buf = ngxt_sprintf(buf, last, "<...>");
    }

    buf = ngxt_sprintf(buf, last, "\"");

    return buf;
}
