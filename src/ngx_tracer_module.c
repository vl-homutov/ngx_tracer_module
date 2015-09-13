
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
 *  tracer module: uses instrumentation to catch nginx functions calls and
 *                 generate logs with call traces, including return codes,
 *                 passed arguments and caller information.
 */

#include "ngx_tracer.h"

ngxt_decl void __attribute__ ((constructor)) premain();
ngxt_decl void __cyg_profile_func_enter(void *, void *);
ngxt_decl void __cyg_profile_func_exit(void *, void *);

static ngxt_decl void  ngxt_init_log(const char* log_filename);
static ngxt_decl void  ngxt_logmsg(char *msg);
static ngxt_decl char *ngxt_dump_args(char *buf, char *last, char *frame,
    ngxt_func_t *fspec);
static ngxt_decl ngxt_func_symbol_t *ngxt_sym_from_addr(ngx_uint_t addr,
    ngxt_ctx_t *ctx, ngx_uint_t range);


static ngxt_ctx_t ngxt_ctx;


static ngx_core_module_t  ngx_tracer_module_ctx = {
    ngx_string("tracer"),
    NULL,
    NULL
};


ngx_module_t
ngx_tracer_module =
{
    NGX_MODULE_V1,
    &ngx_tracer_module_ctx,                /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


void
ngxt_die(int eno, char *fmt, ...)
{
    va_list  args;

    fprintf(stderr, "Fatal error");

    if (eno) {
        fprintf(stderr, " '%s'", strerror(eno));
    }

    fprintf(stderr, ": ");

    va_start(args, fmt);
    (void) vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, ", exiting...\n");

    exit(EXIT_FAILURE);
}


void
__attribute__ ((constructor)) premain()
{
    int         rc;
    ngx_uint_t  i;

    /* TODO:
     * Solaris: getexecname()
     * Mac OS X: _NSGetExecutablePath()
     */

    char *procs[] = {
        "/proc/self/exe",     /* Linux */
        "/proc/curproc/file", /* FreeBSD, DragonflyBSD */
        "/proc/curproc/exe",  /* NetBSD */
        NULL
    };

    for (i = 0; procs[i]; i++) {
        rc = readlink(procs[i], ngxt_ctx.progname, NGXT_PROGNAME_BUFSIZE - 1);
        if (-1 != rc) {
            ngxt_ctx.progname[rc] = 0;
            goto gotname;
        }
    }

#if (NGX_FREEBSD)
    {
    int     mib[4];
    size_t  cb;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PATHNAME;
    mib[3] = -1;

    cb = NGXT_PROGNAME_BUFSIZE;

    if (sysctl(mib, 4, ngxt_ctx.progname, &cb, NULL, 0) != -1) {
        goto gotname;
    }

    }
#endif

    /* or fallback to hardcoded path (may be not real) */
    strcpy(ngxt_ctx.progname, NGX_PREFIX "/sbin/nginx");

    inform(("Warning, fallback to hardcoded PREFIX, binary may be wrong!\n"));

gotname:

    inform(("Loading symbols from '%s'...\n", ngxt_ctx.progname));

    if (ngxt_load_symbols(&ngxt_ctx) != NGX_OK) {
        ngxt_die(0, "failed to load symbols");
    }

#if (NGXT_DEBUG)
    printf("Loaded symbol table:\n");
    for (i = 0; i < ngxt_ctx.symcount ; i++) {
        printf("[%lu] 0x%lX <=> %s\n", i,
               ngxt_ctx.symbols[i].address, ngxt_ctx.symbols[i].name);
    }
#endif

#if (NGX_HAVE_READELF)
    if (ngxt_readelf(&ngxt_ctx) != NGX_OK) {
        ngxt_die(0, "failed to read DWARF from ELF");
    }
#endif

    /* some functions start new processes, will need to catch such calls */

    for (i = 0; i < ngxt_ctx.symcount ; i++) {

        if (strcmp(ngxt_ctx.symbols[i].name,
                   "ngx_worker_process_cycle") == 0)
        {
            ngxt_ctx.symbols[i].procname = "worker";

        } else if (strcmp(ngxt_ctx.symbols[i].name,
                          "ngx_cache_manager_process_cycle") == 0)
        {
            ngxt_ctx.symbols[i].procname = "cache_manager";

        } else if (strcmp(ngxt_ctx.symbols[i].name,
                          "ngx_cache_loader_process_handler") == 0)
        {
            ngxt_ctx.symbols[i].procname = "cache_loader";

        } else if (strcmp(ngxt_ctx.symbols[i].name,
                          "ngx_cache_manager_process_handler") == 0)
        {
            ngxt_ctx.symbols[i].procname = "cache_manager_handler";
        }
    }

    inform(("all debug info loaded ok from %s\n", ngxt_ctx.progname));

    ngxt_mem_init();

    if (gettimeofday(&ngxt_ctx.started, NULL) == -1) {
        ngxt_die(errno, "gettimeofday");
    }

    ngxt_init_log("master");
    ngxt_logmsg("master process: started under tracer\n");
}


static void
ngxt_init_log(const char* log_filename)
{
    char logfile[NGX_MAX_PATH];

    sprintf(logfile, "%s/logs/trace-%s-%lu.log", NGX_PREFIX, log_filename,
                                                     (unsigned long) getpid());

    ngxt_ctx.log = fopen(logfile, "a+");
    if (ngxt_ctx.log == NULL) {
        ngxt_die(errno, "tracer: failed to open log file '%s'", logfile);
    }

    inform(("tracer: started logging to %s\n", logfile));
}


char*
ngxt_sprintf(char *buf, char *last, char* fmt, ...)
{
    int      n;
    size_t   left;
    va_list  args;

    if (buf == NULL || last <= buf) {
        return 0;
    }

    left = last - buf;

    va_start(args, fmt);
    n = vsnprintf(buf, left, fmt, args);
    va_end(args);

    if (n >= (ssize_t) left) {
        return 0;
    }

    return buf + n;
}


static void
ngxt_logmsg(char *msg)
{
    time_t          sec;
    struct timeval  now;

    if (ngxt_ctx.log == NULL) {
        return;
    }

    if (gettimeofday(&now, NULL) == -1) {
        now = ngxt_ctx.started;

    } else {
        /* Ensure tv_usec is less than second to print correctly */
        if (now.tv_usec > 1000000) {
            sec = now.tv_usec / 1000000;
            now.tv_usec -= sec * 1000000;
            now.tv_sec += sec;
        }
    }

    fprintf(ngxt_ctx.log, "%lu.%06ld [%lu] %s",
            now.tv_sec - ngxt_ctx.started.tv_sec,
            now.tv_usec, (unsigned long) getpid(), msg);

    fflush(ngxt_ctx.log);
}


static ngxt_func_symbol_t*
ngxt_sym_from_addr(ngx_uint_t addr, ngxt_ctx_t *ctx, ngx_uint_t range)
{
    ngx_uint_t  first, last, mid;

    first = 0;
    last = ctx->symcount;

    while (first < last) {

        mid = first + (last - first) / 2;

        if (addr <= ctx->symbols[mid].address) {
            last = mid;

        } else {
            first = mid + 1;
        }
    }

    if (last == ctx->symcount) {
        /* address to high, not found, 1st entry is reserved for this */
        last = 0;
    }

    if (range && last) {
        /* address inside function body, function name is in previous entry */
        last--;
    }

    return &ctx->symbols[last];
}


static char *
ngxt_dump_args(char *buf, char* last, char *frame, ngxt_func_t *fspec)
{
    char             *arg_base, *p;
    ngxt_func_arg_t  *arg;

    if (fspec->argc == 0) {
        return buf;
    }

    /*
     * NOTE: compiler-specific code below
     *
     * GCC pushes to stack %rbp and %rbx before saving arguments
     * of the instrumented function, thus offset between the result
     * of __builtin_frame_address(1) and DW_AT_location from DWARF
     * for specific argument is 16 bytes.
     *
     * The only recognizable DW_AT_location expression is fbreg(),
     * i.e. we are expecting arguments to be on stack. This is only
     * true with disabled optimizations(-O0).
     *
     * clang:
     *
     * DWARF locations of arguments refer to results of reordering that
     * is done AFTER __cyg_profile_func_enter() leaves and before actual
     * function starts, so we do not know where arguments of traced function
     * are when we are inside tracing function.
     */
    arg_base = frame + 16;

    for (p = buf, arg = fspec->argv; arg; arg = arg->next) {

        p = ngxt_sprintf(p, last, "%s=", arg->name.data);
        p = ngxt_dump_value(p, last, arg_base + arg->location, &arg->type);

        if (arg->next) {
            p = ngxt_sprintf(p, last, ", ");
        }
    }

    return p;
}


void
__cyg_profile_func_enter(void *this_fn, void *call_site)
{
    char                *p, *last;
    ngxt_func_symbol_t  *fsym;

    char  buf[NGXT_DUMP_BUF_SIZE];

    fsym = ngxt_sym_from_addr((ngx_uint_t) this_fn, &ngxt_ctx, 0);

    if (fsym->procname) {
        ngxt_init_log(fsym->procname);
    }

    p = buf;
    last = buf + NGXT_DUMP_BUF_SIZE;

    memset(buf, ' ', ngxt_ctx.depth); /* indentation */
    p += ngxt_ctx.depth;

    p = ngxt_sprintf(p, last, "{ %s(", fsym->name);

#if (NGX_HAVE_READELF)
    if (fsym->spec) {
        p = ngxt_dump_args(p, last, (char *) __builtin_frame_address(1),
                           fsym->spec);
    }
#endif

    p = ngxt_sprintf(p, last, ") from ");

#if (NGX_HAVE_LIBBFD)
    p = ngxt_dump_call_location(p, last, (ngx_uint_t) call_site, &ngxt_ctx);
#else
    fsym = ngxt_sym_from_addr((ngx_uint_t) call_site, &ngxt_ctx, 1);
    p = ngxt_sprintf(p, last, "%s()", fsym->name);
#endif

    p = ngxt_sprintf(p, last, "\n");

    ngxt_logmsg(buf);

    ngxt_ctx.depth++;
}


void
__cyg_profile_func_exit(void *this_fn, void *call_site)
{
    char                *ptr, *p, *last;
    ngx_uint_t           rv;
    ngxt_func_symbol_t  *fsym;

    char  buf[NGXT_DUMP_BUF_SIZE];

    ngxt_ctx.depth--;

    p = buf;
    last = buf + NGXT_DUMP_BUF_SIZE;

    memset(buf, ' ', ngxt_ctx.depth);
    p = buf + ngxt_ctx.depth;

    fsym = ngxt_sym_from_addr((ngx_uint_t) this_fn, &ngxt_ctx, 0);

    /* function description is available, decode return value */
    if (fsym->spec) {
        if (fsym->spec->rtype.type == NGXT_DWARF_TYPE_NONE) {
            /* void function */
            goto done;
        }

        /* AMD64: function return value is in RBX */
        __asm__ __volatile__("movq %%rbx, %0" : "=a"(rv));
        ptr = (char *) &rv;

        p = ngxt_sprintf(p, last,"[done:%s = ", fsym->name);
        p = ngxt_dump_value(p, last, ptr, &fsym->spec->rtype);
        p = ngxt_sprintf(p, last, "]}\n");
        ngxt_logmsg(buf);

        return;
    }

done:

    (void) ngxt_sprintf(p, last,"[done:%s]}\n", fsym->name);

    ngxt_logmsg(buf);
}
