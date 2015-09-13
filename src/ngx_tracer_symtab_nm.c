
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
 * functions to to load symbol table from nginx binary using 'nm' utility.
 */

#include "ngx_tracer.h"


typedef struct ngxt_func_list_s ngxt_func_list_t;

struct ngxt_func_list_s {
    ngxt_func_symbol_t   symbol;
    ngxt_func_list_t    *next;
};


ngxt_decl static ngx_int_t ngxt_parse_line(u_char *line, ngx_uint_t len,
    ngxt_func_list_t **tail, ngx_uint_t *cnt);
ngxt_decl static int ngxt_cmp_func_addr(const void *e1,const void *e2);


/* converts address to source line */
char *
ngxt_dump_call_location(char *buf, char *last, ngx_uint_t addr, ngxt_ctx_t *ctx)
{
    /* stub: unsupported with nm */
    return buf;
}


static int
ngxt_cmp_func_addr(const void *a, const void *b)
{
    const ngxt_func_symbol_t *ap = (const ngxt_func_symbol_t *) a;
    const ngxt_func_symbol_t *bp = (const ngxt_func_symbol_t *) b;

    return ap->address - bp->address;
}


static ngx_int_t
ngxt_parse_line(u_char *line, ngx_uint_t len, ngxt_func_list_t **tail,
    ngx_uint_t *cnt)
{
    int                rc;
    char               name[NGXT_MAX_SYMBOL_LEN];
    char               scope;
    unsigned int       address;
    ngxt_func_list_t  *item;

    rc = sscanf((char*) line,"%X %c %s", &address, &scope, name);

    if (rc == 3 && (scope == 'T' || scope == 't')) {

        item = calloc(1, sizeof(ngxt_func_list_t));

        item->symbol.address = address;
        item->symbol.name = strdup(name);
        if (item->symbol.name == NULL) {
            return NGX_ERROR;
        }

        if (*tail) {
            (*tail)->next = item;
        }

        *tail = item;

        (*cnt)++;
    }

    return NGX_OK;
}


ngx_int_t
ngxt_load_symbols(ngxt_ctx_t *ctx)
{
    const char  *envp[] = {"LANG=C", NULL};

    int                  link[2], rc;
    pid_t                pid;
    ssize_t              n;
    ngx_uint_t           symcnt, i, k;
    ngxt_func_list_t    *head, *item, *last;
    ngxt_func_symbol_t  *symbols;

    u_char buf[NGXT_PARSER_BUF_SIZE];
    u_char linebuf[NGXT_PARSER_MAXLINE];

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

    if (pid == 0) {
        dup2(link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);
        execle(NGX_TRACER_NM_PATH, "nm", ctx->progname, NULL, envp);
        ngxt_die(errno, "exec(file='%s',prog='%s')",NGX_TRACER_NM_PATH,
                                                                ctx->progname);
    } else {
        inform(("executing nm to obtain symbols...\n"));
    }

    (void) close(link[1]);

    inform(("please wait, parsing nm's output...\n"));

    head = NULL;
    last = NULL;
    symcnt = 0;
    k = 0;

    while (1) {
        n = read(link[0], buf, NGXT_PARSER_BUF_SIZE);

        if (-1 == n) {
            perror("pipe read");
            return NGX_ERROR;

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

                if (ngxt_parse_line(linebuf, k, &last, &symcnt) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (head == NULL) {
                    head = last;
                }

                k = 0;
            }
        }
    }

    if (symcnt == 0) {
        return NGX_ERROR;
    }

    symbols = calloc(symcnt + 1, sizeof(ngxt_func_symbol_t));
    if (symbols == NULL) {
        return NGX_ERROR;
    }

    i = 1;

    symbols[0].name = "notfound";
    symbols[0].address = 0;

    for (item = head; item != NULL; item = item->next) {
        symbols[i].name = item->symbol.name;
        symbols[i].address = item->symbol.address;
#if (NGXT_DEBUG)
        printf("put: [%ld] 0x%lX <=> %s\n",i, symbols[i].address,
               symbols[i].name);
#endif
        i++;
    }

    qsort(&symbols[1], i - 1, sizeof(ngxt_func_symbol_t), ngxt_cmp_func_addr);

    ctx->symcount = i;
    ctx->symbols = symbols;

    return NGX_OK;
}
