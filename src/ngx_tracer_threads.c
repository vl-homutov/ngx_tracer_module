
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

#include "ngx_tracer.h"


static void ngxt_decl ngxt_thread_create_key();


static pthread_once_t ngxt_thread_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t  ngxt_thread_key;

extern ngxt_ctx_t ngxt_ctx;

static
void ngxt_thread_create_key()
{
    (void) pthread_key_create(&ngxt_thread_key, NULL);
    /* TODO: if threads are destroyed during lifecycle, destructor needed */
}


/* new process - force new ctx */
ngxt_thread_ctx_t *
ngxt_thread_init_ctx()
{
    ngxt_thread_ctx_t  *tctx;

    char  logfile[NGX_MAX_PATH];

    tctx = malloc(sizeof(ngxt_thread_ctx_t));
    if (tctx == NULL) {
        return NULL;
    }

    tctx->depth = 0;

#if (NGX_LINUX)
    tctx->tid = syscall (SYS_gettid);
#else
    tctx->tid = pthread_self();
#endif

    sprintf(logfile, "%s/logs/trace-%s-%lu-%lu.log", NGX_PREFIX,
                     ngxt_ctx.procname, (unsigned long) getpid(),
                     (unsigned long) tctx->tid);

    tctx->log = fopen(logfile, "a+");
    if (tctx->log == NULL) {
        free(tctx);
        return NULL;
    }

    (void) setvbuf(tctx->log, NULL, _IOLBF, 0);

    (void) pthread_once(&ngxt_thread_key_once, ngxt_thread_create_key);

    if (pthread_setspecific(ngxt_thread_key, tctx) != 0) {
        (void) fclose(tctx->log);
        free(tctx);
        return NULL;
    }

    inform(("tracer: started thread logging to %s\n", logfile));

    return tctx;
}



ngxt_thread_ctx_t *
ngxt_thread_get_ctx()
{
    ngxt_thread_ctx_t  *tctx;

    (void) pthread_once(&ngxt_thread_key_once, ngxt_thread_create_key);

    /* Try to get data using the key */
    tctx = pthread_getspecific(ngxt_thread_key);

    if (tctx) {
        /* per-thread data already set and thus initialized */
        return tctx;
    }

    return ngxt_thread_init_ctx();
}

