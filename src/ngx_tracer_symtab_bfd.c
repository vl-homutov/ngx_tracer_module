
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
 * functions to to load symbol table from nginx binary and perform address to
 * line translation using libbfd.
 */


#include "ngx_tracer.h"

/* originally defined in config.h created during binutils build */
#define PACKAGE tracer
#include <bfd.h>

#include "libiberty.h"
#include "demangle.h"


struct ngxt_open_binary_s {
    asymbol        **symbols;
    bfd             *bfd;
};


ngxt_decl static int ngxt_cmp_fs(const void *e1, const void *e2);


static int
ngxt_cmp_fs(const void *e1,const void *e2)
{
    ngxt_func_symbol_t *fs1 = (ngxt_func_symbol_t *) e1;
    ngxt_func_symbol_t *fs2 = (ngxt_func_symbol_t *) e2;

    return fs1->address - fs2->address;
}


ngx_int_t
ngxt_load_symbols(ngxt_ctx_t *ctx)
{
    bfd                   *bfd;
    ssize_t                symtab_size;
    asymbol              **symbols;
    const char            *symbol;
    ngx_uint_t             i, k, address, nsym;
    bfd_boolean            dynamic;
    ngxt_func_symbol_t    *fsymbols;

    ctx->ob = malloc(sizeof(ngxt_open_binary_t));
    if (ctx->ob == NULL) {
        return NGX_ERROR;
    }

    /* initialize library internals; must be the very first BFD call */
    bfd_init();

    /* opens BFD with specified target (autodetected here) */
    bfd = bfd_openr(ctx->progname, NULL);
    if (NULL == bfd) {
        return NGX_ERROR;
    }

    /* makes bfd to automatically decompress compressed sections */
    bfd->flags |= BFD_DECOMPRESS;

    /* verify that open file is really of 'bfd_object' type */
    if (!bfd_check_format(bfd, bfd_object)) {
        return NGX_ERROR;
    }

    /* no symbols in open bfd */
    if ((bfd_get_file_flags(bfd) & HAS_SYMS) == 0) {
        return NGX_ERROR;
    }

    dynamic = FALSE;

    /* number of bytes to store vector of pointers to all symbols in bfd */
    symtab_size = bfd_get_symtab_upper_bound(bfd);
    if (symtab_size == 0) {
        /* get the same for the dynamic symbols */
        symtab_size = bfd_get_dynamic_symtab_upper_bound(ctx->ob->bfd);
        dynamic = TRUE;
    }

    if (symtab_size < 0) {
        return NGX_ERROR;
    }

    symbols = malloc(symtab_size);
    if (symbols == NULL) {
        return NGX_ERROR;
    }

    /* read symbols and fill in the pointers to symbols, adds NULL entry */
    if (dynamic) {
        nsym = bfd_canonicalize_dynamic_symtab(bfd, symbols);

    } else {
        nsym = bfd_canonicalize_symtab(bfd, symbols);
    }

    /*
     *  If there are no symbols left after canonicalization and
     *  we have not tried the dynamic symbols then give them a go.
     */
    if (nsym == 0 && ! dynamic
        && (symtab_size = bfd_get_dynamic_symtab_upper_bound(bfd)) > 0)
    {
        free(symbols);
        symbols = malloc(symtab_size);
        nsym = bfd_canonicalize_dynamic_symtab(bfd, symbols);
    }

    if (nsym <= 0) {
        return NGX_ERROR;
    }

    fsymbols = calloc(nsym + 1, sizeof(ngxt_func_symbol_t));
    if (fsymbols == NULL) {
        free(symbols);
        return NGX_ERROR;
    }

    fsymbols[0].address = 0;
    fsymbols[0].name = "notfound";

    for (i = 0, k = 1; i < nsym; i++) {
        address = bfd_asymbol_value(symbols[i]);
        symbol = bfd_asymbol_name(symbols[i]);

        if (address == 0 || *symbol == '.') {
            continue;
        }

        fsymbols[k].address = address;
        fsymbols[k].name = symbol;
        k++;
    }

    qsort(&fsymbols[1], k - 1, sizeof(ngxt_func_symbol_t), ngxt_cmp_fs);

    /* BFD specific */
    ctx->ob->bfd = bfd;
    ctx->ob->symbols = symbols;

    /* functions table */
    ctx->symbols = fsymbols;
    ctx->symcount = k;

    return NGX_OK;
}


/*
 * converts address to source line
 * actually, this is heavily stripped down version of addr2line from binutils.
 */
char *
ngxt_dump_call_location(char *buf, char *last, ngx_uint_t addr, ngxt_ctx_t *ctx)
{
    ngxt_open_binary_t* ob = ctx->ob;

    char           *alloc, *p;
    bfd_vma         vma, pc;
    asection       *s;
    ngx_uint_t      found;
    const char     *name, *filename, *functionname;
    unsigned int    line, discriminator;
    bfd_size_type   size;

    pc = addr;
    p = buf;

    found = 0;
    line = 0;
    discriminator = 0;
    filename = 0;
    functionname = 0;

    for (s = ob->bfd->sections; s != NULL; s = s->next) {

        if ((bfd_get_section_flags(ob->bfd, s) & SEC_ALLOC) == 0) {
            continue;
        }

        vma = bfd_get_section_vma(ob->bfd, s);
        if (pc < vma) {
            continue;
        }

        size = bfd_get_section_size(s);
        if (pc >= vma + size) {
            continue;
        }

        if (bfd_find_nearest_line_discriminator(ob->bfd, s,ob->symbols,
                                                pc - vma, &filename,
                                                &functionname, &line,
                                                &discriminator))
        {
            found = 1;
            break;
        }
    }

    if (!found) {
        p = ngxt_sprintf(p, last, "<not found>");
        return p;
    }

    while (1) {

        alloc = NULL;

        name = functionname;
        if (name == NULL || *name == '\0') {
            name = "??";

        } else {
            alloc = bfd_demangle(ob->bfd, name, DMGL_ANSI | DMGL_PARAMS);
            if (alloc != NULL) {
                name = alloc;
            }
        }

        p = ngxt_sprintf(p, last, "%s at ", name);

        if (alloc != NULL) {
            free (alloc);
        }

        /* strip directory name */
        if (filename != NULL) {
            char *h;

            h = strrchr(filename, '/');
            if (h != NULL) {
                filename = h + 1;
            }
        }

        p = ngxt_sprintf(p, last, "%s:", filename ? filename : "??");
        if (line != 0) {

            if (discriminator != 0) {
                p = ngxt_sprintf(p, last, "%u (dsc %u)", line, discriminator);

            } else {
                p = ngxt_sprintf(p, last, "%u", line);
            }

        } else {
            p = ngxt_sprintf(p, last, "?");
        }

        found = bfd_find_inliner_info(ob->bfd, &filename, &functionname, &line);

        if (!found) {
            break;
        }

        p = ngxt_sprintf(p, last, " (inlined by) ");
    }

    return p;
}
