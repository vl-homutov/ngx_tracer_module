#ifndef __NGX_TRACER_H_H_
#define __NGX_TRACER_H_H_

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


#include <ngx_config.h>
#include <ngx_core.h>

#define NGXT_DEBUG        1  /* dump loaded symbol table and functions */
#define NGXT_VERBOSE      1  /* display progress notes */
#define NGXT_DEBUG_DWARF  0  /* debug for readelf DWARF output parser */

#define NGXT_PROGNAME_BUFSIZE   255  /* path to binary*/
#define NGXT_DUMP_BUF_SIZE      255  /* output buffer */
#define NGXT_MAX_SYMBOL_LEN     255  /* symbol name */
#define NGXT_PARSER_MAXLINE    1024  /* maximum expected line length */
#define NGXT_PARSER_BUF_SIZE   4096  /* buffer to use when reading from pipe */

/* All DIEs are indexed by offset directly, what requires lot of memory.
 * Increase this value if there are more DIEs in binary.
 */
#define NGXT_DIES_MAX (16 * 1024 * 1024)

#if (NGXT_VERBOSE)
#define inform(x) printf x
#else
#define inform(x)
#endif

/* all module functions should not be instrumented itself */
#define ngxt_decl __attribute__ ((no_instrument_function))


/* hints used to match specific type as seen in function declaration */
typedef enum {
    NGXT_TYPE_HINT_VOID = 0,
    NGXT_TYPE_HINT_CHAR,
    NGXT_TYPE_HINT_NGXSTR,
    NGXT_TYPE_HINT_CONN,
    NGXT_TYPE_HINT_HTTP_REQ
} ngxt_dwarf_type_hints_t;


typedef enum {
    NGXT_DWARF_ENC_FLOAT = 4,     /* number matches declaration in spec */
    NGXT_DWARF_ENC_SIGNED,
    NGXT_DWARF_ENC_SIGNED_CHAR,
    NGXT_DWARF_ENC_UNSIGNED,
    NGXT_DWARF_ENC_UNSIGNED_CHAR
} ngxt_dwarf_encodings_t;


typedef enum {
    NGXT_DWARF_TYPE_NONE = 0,     /* no type info */
    NGXT_DWARF_TYPE_BASE,         /* basic types */
    NGXT_DWARF_TYPE_AGREG,        /* structures & arrays */
    NGXT_DWARF_TYPE_PTR,          /* pointers to anything */
    NGXT_DWARF_TYPE_OTHER         /* TODO: unions, arrays... */
} ngxt_dwarf_types_t;


/* all information about C type extracted from DWARF */
typedef struct {
    ngxt_dwarf_types_t       type;
    ngxt_dwarf_encodings_t   encoding;
    ngxt_dwarf_type_hints_t  hint;
    ngx_uint_t               bytes;
    ngx_uint_t               offset; /* offset of DIE with this type */
} ngxt_dwarf_type_t;


typedef struct ngxt_func_arg_s  ngxt_func_arg_t;

struct ngxt_func_arg_s {
    ngxt_dwarf_type_t        type;
    ngx_str_t                name;
    ngx_int_t                location;  /* on the stack */
    ngxt_func_arg_t         *next;
};


typedef struct ngxt_func_s  ngxt_func_t;

/* all available properties of C function */
struct ngxt_func_s {
    ngx_str_t                name;
    ngxt_dwarf_type_t        rtype;
    ngx_uint_t               argc;
    ngxt_func_arg_t         *argv;
    ngxt_func_arg_t         *last_arg;
    ngxt_func_t             *next;
};

/* symbol table entry, fp is optional */
typedef struct {
    ngx_uint_t               address;   /* in a process address space */
    const char              *name;      /* function name */
    ngxt_func_t             *spec;      /* description (if DWARF available) */
    char                    *procname;  /* function starts a new process */
} ngxt_func_symbol_t;


typedef struct ngxt_open_binary_s  ngxt_open_binary_t;

/* tracer context */
typedef struct {
    char                     progname[NGXT_PROGNAME_BUFSIZE];
    const char              *procname;  /* process name: master/worker/... */
    ngx_uint_t               symcount;  /* number of symbols loaded */
    pid_t                    pid;

    FILE                    *log;       /* trace log file */
    ngx_int_t                depth;     /* indentation */

    ngxt_func_symbol_t      *symbols;   /* symbol table (functions only) */
    ngxt_open_binary_t      *ob;        /* opaque pointer to open binary */
    struct timeval           started;   /* start time */
} ngxt_ctx_t;


ngxt_decl void ngxt_mem_init();
ngxt_decl void  ngxt_die(int eno, char *fmt, ...);
ngxt_decl ngx_int_t ngxt_load_symbols(ngxt_ctx_t *ctx);
ngxt_decl char *ngxt_sprintf(char *buf, char *last, char* fmt, ...);
ngxt_decl char *ngxt_dump_value(char *buf, char *last, void *addr,
    ngxt_dwarf_type_t *type);
ngxt_decl char *ngxt_dump_call_location(char *buf, char *last, ngx_uint_t addr,
    ngxt_ctx_t *ctx);


#if (NGX_HAVE_READELF)
ngxt_decl ngx_int_t ngxt_readelf(ngxt_ctx_t *ctx);
#endif

#if (NGX_THREADS)

typedef struct {
    FILE                    *log;
    ngx_int_t                depth;
    pid_t                    tid;
} ngxt_thread_ctx_t;

ngxt_decl ngxt_thread_ctx_t * ngxt_thread_init_ctx();
ngxt_decl ngxt_thread_ctx_t * ngxt_thread_get_ctx();
#endif

#endif
