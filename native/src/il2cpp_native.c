#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "il2cpp_native.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#define strtok_r strtok_s
#endif

#if defined(__GNUC__) || defined(__clang__)
#define I2C_PRINTF_FORMAT(format_index, first_argument)                                            \
    __attribute__((format(printf, format_index, first_argument)))
#else
#define I2C_PRINTF_FORMAT(format_index, first_argument)
#endif

#define I2C_MAX_OFFSET 0x10000000u
#define I2C_MAX_DEPTH 8192
#define I2C_MAX_OFFSETS_BYTES ((size_t)128U * 1024U * 1024U)
#define I2C_MAX_SIDECAR_OFFSET 0x01000000u
#define I2C_MAX_SIDECAR_LAYOUT_BYTES ((uint64_t)512U * 1024U * 1024U)
#define I2C_MAX_JSON_DEPTH 64U
#define I2C_MAX_JSON_STRING_BYTES ((size_t)1024U * 1024U)
#define I2C_MAX_JSON_TYPES ((size_t)100000U)
#define I2C_MAX_JSON_FIELDS ((size_t)2000000U)
#define I2C_MAGIC 0x46473249u /* I2GF, little endian */
#define I2C_VERSION 3u
#define I2C_API_VERSION 4u

/* ---------------- allocation / strings ---------------- */
static void *xcalloc(size_t n, size_t s) {
    return calloc(n, s);
}
static void *xrealloc(void *p, size_t n) {
    return realloc(p, n);
}
static char *xstrdup(const char *s) {
    if (!s)
        return NULL;
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p)
        memcpy(p, s, n);
    return p;
}
static char *xstrndup(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (!p)
        return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}
static int str_printf(char **out, const char *format, ...) I2C_PRINTF_FORMAT(2, 3);
static int str_printf(char **out, const char *format, ...) {
    if (!out)
        return -1;
    *out = NULL;
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0) {
        va_end(args);
        return -1;
    }
    char *buffer = malloc((size_t)needed + 1);
    if (!buffer) {
        va_end(args);
        return -1;
    }
    int written = vsnprintf(buffer, (size_t)needed + 1, format, args);
    va_end(args);
    if (written < 0) {
        free(buffer);
        return -1;
    }
    *out = buffer;
    return written;
}
static uint64_t hash_str(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

/* ---------------- compact open-addressing string map ---------------- */
typedef struct {
    char *key;
    uintptr_t value;
    uint64_t hash;
} MapEnt;
typedef struct {
    MapEnt *e;
    size_t cap, len;
} StrMap;
static bool map_init(StrMap *m, size_t cap) {
    size_t p = 16;
    while (p < cap * 2)
        p <<= 1;
    m->e = xcalloc(p, sizeof(MapEnt));
    m->cap = m->e ? p : 0;
    m->len = 0;
    return m->e != NULL;
}
static void map_free(StrMap *m, bool free_keys) {
    if (m->e && free_keys)
        for (size_t i = 0; i < m->cap; i++)
            free(m->e[i].key);
    free(m->e);
    memset(m, 0, sizeof(*m));
}
static bool map_rehash(StrMap *m) {
    StrMap n = {0};
    if (!map_init(&n, m->cap))
        return false;
    for (size_t i = 0; i < m->cap; i++)
        if (m->e[i].key) {
            size_t mask = n.cap - 1, j = (size_t)m->e[i].hash & mask;
            while (n.e[j].key)
                j = (j + 1) & mask;
            n.e[j] = m->e[i];
            n.len++;
        }
    free(m->e);
    *m = n;
    return true;
}
static bool map_put_owned(StrMap *m, char *key, uintptr_t value, bool replace) {
    if (!m->cap && !map_init(m, 16)) {
        free(key);
        return false;
    }
    if ((m->len + 1) * 10 >= m->cap * 7 && !map_rehash(m)) {
        free(key);
        return false;
    }
    uint64_t h = hash_str(key);
    size_t mask = m->cap - 1, i = (size_t)h & mask;
    while (m->e[i].key) {
        if (m->e[i].hash == h && strcmp(m->e[i].key, key) == 0) {
            if (replace)
                m->e[i].value = value;
            free(key);
            return true;
        }
        i = (i + 1) & mask;
    }
    m->e[i] = (MapEnt){key, value, h};
    m->len++;
    return true;
}
static bool map_put(StrMap *m, const char *key, uintptr_t value, bool replace) {
    return map_put_owned(m, xstrdup(key), value, replace);
}
static bool map_get(const StrMap *m, const char *key, uintptr_t *out) {
    if (!m->cap)
        return false;
    uint64_t h = hash_str(key);
    size_t mask = m->cap - 1, i = (size_t)h & mask;
    while (m->e[i].key) {
        if (m->e[i].hash == h && strcmp(m->e[i].key, key) == 0) {
            if (out)
                *out = m->e[i].value;
            return true;
        }
        i = (i + 1) & mask;
    }
    return false;
}

/* ---------------- source model ---------------- */
typedef struct {
    char *ctype, *name;
} Member;
typedef struct {
    char *name, *parent;
    bool is_union;
    bool is_anonymous;
    Member *members;
    size_t n, cap;
} StructDef;
typedef struct {
    StructDef *v;
    size_t n, cap;
    StrMap by_name;
} StructTable;
static bool vec_grow(void **p, size_t *cap, size_t elem, size_t need) {
    if (*cap >= need)
        return true;
    if (!elem || need > SIZE_MAX / elem)
        return false;
    size_t c = *cap ? *cap : 8;
    while (c < need) {
        if (c > SIZE_MAX / 2) {
            c = need;
            break;
        }
        c *= 2;
    }
    void *q = xrealloc(*p, c * elem);
    if (!q)
        return false;
    *p = q;
    *cap = c;
    return true;
}
static bool member_push(StructDef *s, char *ctype, char *name) {
    if (!vec_grow((void **)&s->members, &s->cap, sizeof(Member), s->n + 1))
        return false;
    s->members[s->n++] = (Member){ctype, name};
    return true;
}
static void structs_free(StructTable *t) {
    for (size_t i = 0; i < t->n; i++) {
        StructDef *s = &t->v[i];
        free(s->name);
        free(s->parent);
        for (size_t j = 0; j < s->n; j++) {
            free(s->members[j].ctype);
            free(s->members[j].name);
        }
        free(s->members);
    }
    free(t->v);
    map_free(&t->by_name, true);
    memset(t, 0, sizeof(*t));
}
static StructDef *struct_find(StructTable *t, const char *name) {
    uintptr_t x;
    return map_get(&t->by_name, name, &x) ? &t->v[x] : NULL;
}
static bool struct_store(StructTable *t, StructDef *sd) {
    uintptr_t old;
    if (map_get(&t->by_name, sd->name, &old)) {
        StructDef *o = &t->v[old];
        free(o->name);
        free(o->parent);
        for (size_t q = 0; q < o->n; q++) {
            free(o->members[q].ctype);
            free(o->members[q].name);
        }
        free(o->members);
        *o = *sd;
        memset(sd, 0, sizeof(*sd));
        return true;
    }
    if (!vec_grow((void **)&t->v, &t->cap, sizeof(StructDef), t->n + 1) ||
        !map_put(&t->by_name, sd->name, t->n, true))
        return false;
    t->v[t->n++] = *sd;
    memset(sd, 0, sizeof(*sd));
    return true;
}

/* Header lexer and parser. */
typedef enum {
    T_ID,
    T_LBRACE,
    T_RBRACE,
    T_SEMI,
    T_STAR,
    T_COLON,
    T_COMMA,
    T_LBRACK,
    T_RBRACK,
    T_LPAR,
    T_RPAR,
    T_OTHER,
    T_EOF
} TType;
typedef struct {
    TType t;
    const char *s;
    uint32_t len;
} Tok;
static inline bool is_idc(char c) {
    return isalnum((unsigned char)c) || c == '_';
}
static Tok *lex(const char *data, size_t n, size_t *count) {
    size_t cap = 4096, c = 0, i = 0;
    Tok *tk = malloc(cap * sizeof(Tok));
    if (!tk)
        return NULL;
    while (i < n) {
        char ch = data[i];
        if (isspace((unsigned char)ch)) {
            i++;
            continue;
        }
        if (ch == '/' && i + 1 < n && data[i + 1] == '/') {
            i += 2;
            while (i < n && data[i] != '\n')
                i++;
            continue;
        }
        if (ch == '/' && i + 1 < n && data[i + 1] == '*') {
            i += 2;
            while (i + 1 < n && !(data[i] == '*' && data[i + 1] == '/'))
                i++;
            if (i + 1 < n)
                i += 2;
            continue;
        }
        if (c + 1 >= cap) {
            if (cap > SIZE_MAX / 2 || cap * 2 > SIZE_MAX / sizeof(Tok)) {
                free(tk);
                return NULL;
            }
            cap *= 2;
            Tok *q = xrealloc(tk, cap * sizeof(Tok));
            if (!q) {
                free(tk);
                return NULL;
            }
            tk = q;
        }
        Tok *t = &tk[c];
        t->s = data + i;
        t->len = 1;
        if (is_idc(ch)) {
            size_t j = i;
            while (j < n && is_idc(data[j]))
                j++;
            t->t = T_ID;
            t->len = (uint32_t)(j - i);
            i = j;
        } else {
            switch (ch) {
            case '{':
                t->t = T_LBRACE;
                break;
            case '}':
                t->t = T_RBRACE;
                break;
            case ';':
                t->t = T_SEMI;
                break;
            case '*':
                t->t = T_STAR;
                break;
            case ':':
                t->t = T_COLON;
                break;
            case ',':
                t->t = T_COMMA;
                break;
            case '[':
                t->t = T_LBRACK;
                break;
            case ']':
                t->t = T_RBRACK;
                break;
            case '(':
                t->t = T_LPAR;
                break;
            case ')':
                t->t = T_RPAR;
                break;
            default:
                t->t = T_OTHER;
                break;
            }
            i++;
        }
        c++;
    }
    tk[c] = (Tok){T_EOF, data + n, 0};
    *count = c;
    return tk;
}
static bool tok_kw(const Tok *t, const char *kw) {
    size_t n = strlen(kw);
    return t->t == T_ID && t->len == n && !strncmp(t->s, kw, n);
}
static char *clean_type_span(const Tok *a, const Tok *b) {
    const char *s = a->s, *e = b->s;
    size_t n = (size_t)(e - s);
    char *o = malloc(n + 1);
    if (!o)
        return NULL;
    size_t w = 0;
    bool space = false;
    for (size_t i = 0; i < n;) {
        if (i + 1 < n && s[i] == '/' && s[i + 1] == '/') {
            i += 2;
            while (i < n && s[i] != '\n')
                i++;
            space = true;
            continue;
        }
        if (i + 1 < n && s[i] == '/' && s[i + 1] == '*') {
            i += 2;
            while (i + 1 < n && !(s[i] == '*' && s[i + 1] == '/'))
                i++;
            if (i + 1 < n)
                i += 2;
            space = true;
            continue;
        }
        unsigned char ch = (unsigned char)s[i++];
        if (isspace(ch)) {
            space = true;
            continue;
        }
        if (space && w && o[w - 1] != '*' && ch != '*' && ch != ',' && ch != ']') {
            o[w++] = ' ';
        }
        space = false;
        o[w++] = (char)ch;
    }
    while (w && isspace((unsigned char)o[w - 1])) {
        w--;
    }
    o[w] = 0;
    return o;
}
static bool append_text(char **text, const char *suffix) {
    size_t a = *text ? strlen(*text) : 0, b = strlen(suffix);
    if (a > SIZE_MAX - b - 1)
        return false;
    char *q = realloc(*text, a + b + 1);
    if (!q)
        return false;
    memcpy(q + a, suffix, b + 1);
    *text = q;
    return true;
}
static void struct_def_dispose(StructDef *s) {
    free(s->name);
    free(s->parent);
    for (size_t i = 0; i < s->n; i++) {
        free(s->members[i].ctype);
        free(s->members[i].name);
    }
    free(s->members);
    memset(s, 0, sizeof(*s));
}
static size_t parse_body(Tok *tk, size_t i, size_t n, StructDef *sd, StructTable *table,
                         char **error) {
    while (i < n && tk[i].t != T_EOF) {
        if (tk[i].t == T_RBRACE)
            return i + 1;
        size_t start = i, j = i;
        bool par = false, brace = false;
        int depth = 0;
        bool bitfield = false;
        while (j < n && tk[j].t != T_EOF) {
            TType t = tk[j].t;
            if (t == T_LBRACE) {
                brace = true;
                depth++;
            } else if (t == T_RBRACE) {
                if (depth == 0)
                    return j + 1;
                depth--;
            } else if (t == T_LPAR)
                par = true;
            else if (t == T_COLON && depth == 0)
                bitfield = true;
            else if (t == T_SEMI && depth == 0)
                break;
            j++;
        }
        if (j >= n || tk[j].t == T_EOF)
            return j;
        if (bitfield) {
            str_printf(error, "bitfield declarations are unsupported in %s", sd->name);
            return j + 1;
        }
        if (brace && j > start && (tok_kw(&tk[start], "struct") || tok_kw(&tk[start], "union")) &&
            start + 1 < j && tk[start + 1].t == T_LBRACE) {
            char *synthetic = NULL;
            if (str_printf(&synthetic, "%s__anonymous_%zu_Fields", sd->name, sd->n) < 0) {
                *error = xstrdup("anonymous aggregate name OOM");
                return j + 1;
            }
            StructDef nested = {
                .name = synthetic,
                .is_union = tok_kw(&tk[start], "union"),
                .is_anonymous = true,
            };
            size_t after = parse_body(tk, start + 2, n, &nested, table, error);
            if (*error) {
                struct_def_dispose(&nested);
                return j + 1;
            }
            bool promoted = after == j;
            if (!promoted && tk[after].t != T_ID) {
                struct_def_dispose(&nested);
                str_printf(error, "anonymous aggregate in %s has an unsupported declarator",
                           sd->name);
                return j + 1;
            }
            for (size_t q = promoted ? after : after + 1; q < j; q++)
                if (tk[q].t == T_COMMA) {
                    struct_def_dispose(&nested);
                    str_printf(error,
                               "multiple anonymous aggregate declarators are unsupported in %s",
                               sd->name);
                    return j + 1;
                }
            char *member_name = NULL, *member_type = NULL;
            if (promoted)
                str_printf(&member_name, "__anonymous_%zu", sd->n);
            else
                member_name = xstrndup(tk[after].s, tk[after].len);
            if (str_printf(&member_type, "struct %s", nested.name) < 0 || !member_name) {
                free(member_name);
                free(member_type);
                struct_def_dispose(&nested);
                *error = xstrdup("anonymous aggregate member OOM");
                return j + 1;
            }
            if (!promoted && after + 1 < j) {
                char *suffix = clean_type_span(&tk[after + 1], &tk[j]);
                if (!suffix || !append_text(&member_type, suffix)) {
                    free(suffix);
                    free(member_name);
                    free(member_type);
                    struct_def_dispose(&nested);
                    *error = xstrdup("anonymous aggregate suffix OOM");
                    return j + 1;
                }
                free(suffix);
            }
            if (!struct_store(table, &nested)) {
                free(member_name);
                free(member_type);
                struct_def_dispose(&nested);
                *error = xstrdup("anonymous aggregate table OOM");
                return j + 1;
            }
            if (!member_push(sd, member_type, member_name)) {
                free(member_name);
                free(member_type);
                *error = xstrdup("anonymous aggregate member OOM");
                return j + 1;
            }
        } else if (!brace && j > start) {
            size_t fp = SIZE_MAX;
            for (size_t k = start; k + 3 < j; k++)
                if (tk[k].t == T_LPAR && tk[k + 1].t == T_STAR && tk[k + 2].t == T_ID) {
                    fp = k;
                    break;
                }
            if (fp != SIZE_MAX) {
                size_t close = fp + 3;
                char *dims = xstrdup("");
                while (close < j && tk[close].t == T_LBRACK) {
                    size_t rb = close + 1;
                    if (rb >= j || tk[rb].t != T_ID || rb + 1 >= j || tk[rb + 1].t != T_RBRACK) {
                        free(dims);
                        dims = NULL;
                        break;
                    }
                    char *part = xstrndup(tk[close].s,
                                          (size_t)((tk[rb + 1].s + tk[rb + 1].len) - tk[close].s));
                    if (!part || !append_text(&dims, part)) {
                        free(part);
                        free(dims);
                        dims = NULL;
                        break;
                    }
                    free(part);
                    close = rb + 2;
                }
                if (dims && close < j && tk[close].t == T_RPAR) {
                    char *name = xstrndup(tk[fp + 2].s, tk[fp + 2].len);
                    char *ret = clean_type_span(&tk[start], &tk[fp]);
                    char *args =
                        close + 1 < j ? clean_type_span(&tk[close + 1], &tk[j]) : xstrdup("()");
                    char *ct = NULL;
                    if (name && ret && args &&
                        str_printf(&ct, "%s (*)%s%s", ret, args, dims) >= 0) {
                        if (!member_push(sd, ct, name)) {
                            free(ct);
                            free(name);
                            *error = xstrdup("function pointer member OOM");
                        }
                    } else {
                        free(ct);
                        free(name);
                        *error = xstrdup("function pointer member OOM");
                    }
                    free(ret);
                    free(args);
                    free(dims);
                }
            } else if (!par) {
                size_t e = j, first_suffix = j;
                while (e > start && tk[e - 1].t == T_RBRACK) {
                    int d = 0;
                    size_t k = e;
                    while (k > start) {
                        if (tk[k - 1].t == T_RBRACK)
                            d++;
                        else if (tk[k - 1].t == T_LBRACK && --d == 0) {
                            k--;
                            break;
                        }
                        k--;
                    }
                    if (d != 0 || k <= start)
                        break;
                    first_suffix = k;
                    e = k;
                }
                if (e > start && tk[e - 1].t == T_ID) {
                    Tok *nm = &tk[e - 1];
                    char *name = xstrndup(nm->s, nm->len);
                    char *ct = clean_type_span(&tk[start], nm);
                    char *suffix =
                        first_suffix < j ? clean_type_span(&tk[first_suffix], &tk[j]) : NULL;
                    if (ct && suffix && !append_text(&ct, suffix)) {
                        free(ct);
                        ct = NULL;
                    }
                    free(suffix);
                    if (ct && *ct && name) {
                        if (!member_push(sd, ct, name)) {
                            free(ct);
                            free(name);
                            *error = xstrdup("member table OOM");
                        }
                    } else {
                        free(ct);
                        free(name);
                        if (!ct || !name)
                            *error = xstrdup("member parser OOM");
                    }
                }
            }
        }
        if (*error)
            return j + 1;
        i = j + 1;
    }
    return i;
}
static char *slurp(const char *path, size_t *outn, size_t maximum_size, bool *too_large) {
    if (too_large)
        *too_large = false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END)) {
        fclose(f);
        return NULL;
    }
    long z = ftell(f);
    if (z < 0 || (uintmax_t)z > (uintmax_t)maximum_size ||
        (uintmax_t)z > (uintmax_t)(SIZE_MAX - 1U)) {
        if (z >= 0 && too_large)
            *too_large = true;
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *b = malloc((size_t)z + 1);
    if (!b) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(b, 1, (size_t)z, f);
    if (n != (size_t)z) {
        free(b);
        fclose(f);
        return NULL;
    }
    fclose(f);
    b[n] = 0;
    if (outn)
        *outn = n;
    return b;
}
static bool has_suffix(const char *s, const char *suffix) {
    size_t n = strlen(s), z = strlen(suffix);
    return n >= z && !strcmp(s + n - z, suffix);
}
typedef enum { FIELD_STORAGE_NONE, FIELD_STORAGE_INSTANCE, FIELD_STORAGE_STATIC } FieldStorageKind;
static FieldStorageKind field_storage_kind(const char *name) {
    if (has_suffix(name, "_StaticFields"))
        return FIELD_STORAGE_STATIC;
    if (has_suffix(name, "_Fields"))
        return FIELD_STORAGE_INSTANCE;
    return FIELD_STORAGE_NONE;
}
static FieldStorageKind field_storage_kind_for(StructTable *structures, const char *name) {
    StructDef *definition = struct_find(structures, name);
    return definition && definition->is_anonymous ? FIELD_STORAGE_NONE : field_storage_kind(name);
}
static bool normalize_converted_inheritance(StructTable *t) {
    for (size_t i = 0; i < t->n; i++) {
        StructDef *s = &t->v[i];
        if (s->parent || s->is_union ||
            field_storage_kind_for(t, s->name) != FIELD_STORAGE_INSTANCE || !s->n ||
            strcmp(s->members[0].name, "super"))
            continue;
        const char *p = s->members[0].ctype;
        while (isspace((unsigned char)*p))
            p++;
        if (!strncmp(p, "struct ", 7))
            p += 7;
        const char *e = p;
        while (is_idc(*e))
            e++;
        while (isspace((unsigned char)*e))
            e++;
        if (!*p || *e || field_storage_kind_for(t, p) != FIELD_STORAGE_INSTANCE ||
            !struct_find(t, p))
            continue;
        s->parent = xstrdup(p);
        if (!s->parent)
            return false;
        free(s->members[0].ctype);
        free(s->members[0].name);
        memmove(s->members, s->members + 1, (s->n - 1) * sizeof(Member));
        s->n--;
    }
    return true;
}
static bool parse_header(const char *path, StructTable *t, char **err) {
    size_t dn = 0, nt = 0;
    char *data = slurp(path, &dn, SIZE_MAX - 1U, NULL);
    if (!data) {
        str_printf(err, "cannot read header: %s", path);
        return false;
    }
    Tok *tk = lex(data, dn, &nt);
    if (!tk) {
        free(data);
        *err = xstrdup("header lexer OOM");
        return false;
    }
    if (!map_init(&t->by_name, nt / 16 + 16)) {
        free(tk);
        free(data);
        *err = xstrdup("header map OOM");
        return false;
    }
    for (size_t i = 0; i < nt;) {
        bool is_union = tok_kw(&tk[i], "union");
        if ((is_union || tok_kw(&tk[i], "struct")) && i + 2 < nt && tk[i + 1].t == T_ID) {
            size_t p = i + 2;
            char *parent = NULL;
            if (tk[p].t == T_COLON && p + 1 < nt && tk[p + 1].t == T_ID) {
                parent = xstrndup(tk[p + 1].s, tk[p + 1].len);
                p += 2;
            }
            if (tk[p].t == T_LBRACE) {
                char *name = xstrndup(tk[i + 1].s, tk[i + 1].len);
                StructDef sd = {.name = name, .parent = parent, .is_union = is_union};
                char *body_error = NULL;
                size_t after = parse_body(tk, p + 1, nt, &sd, t, &body_error);
                if (body_error || !name) {
                    struct_def_dispose(&sd);
                    free(tk);
                    free(data);
                    *err = body_error ? body_error : xstrdup("header parser OOM");
                    return false;
                }
                if (!struct_store(t, &sd)) {
                    struct_def_dispose(&sd);
                    free(tk);
                    free(data);
                    *err = xstrdup("struct table OOM");
                    return false;
                }
                i = after;
                continue;
            }
            free(parent);
        }
        i++;
    }
    free(tk);
    free(data);
    if (!normalize_converted_inheritance(t)) {
        *err = xstrdup("converted inheritance OOM");
        return false;
    }
    return true;
}

/* ---------------- offsets model / parsers ---------------- */
typedef struct {
    char *name;
    StrMap fields, static_fields;
    StrMap unresolved_fields;
    char *layout_provenance;
    uint32_t instance_size;
    bool has_instance_size;
} OffClass;
typedef enum {
    OFFSET_SOURCE_LEGACY_UNKNOWN = 0,
    OFFSET_SOURCE_HEADER_ONLY = 1,
    OFFSET_SOURCE_TYPE_OFFSETS_JSON = 2,
    OFFSET_SOURCE_DUMP_CS = 3
} OffsetSource;
typedef struct {
    OffClass *v;
    size_t n, cap;
    StrMap by_name;
    bool exact_json;
    uint32_t schema_version;
    uint32_t pointer_size;
    bool has_pointer_size;
    OffsetSource source;
} Offsets;
static OffClass *off_class(Offsets *o, const char *name, bool create) {
    uintptr_t x;
    if (map_get(&o->by_name, name, &x))
        return &o->v[x];
    if (!create)
        return NULL;
    if (!vec_grow((void **)&o->v, &o->cap, sizeof(OffClass), o->n + 1))
        return NULL;
    OffClass *c = &o->v[o->n];
    memset(c, 0, sizeof(*c));
    c->name = xstrdup(name);
    if (!c->name || !map_init(&c->fields, 8) || !map_init(&c->static_fields, 8) ||
        !map_init(&c->unresolved_fields, 8) || !map_put(&o->by_name, name, o->n, true)) {
        free(c->name);
        map_free(&c->fields, true);
        map_free(&c->static_fields, true);
        map_free(&c->unresolved_fields, true);
        memset(c, 0, sizeof(*c));
        return NULL;
    }
    o->n++;
    return c;
}
static void offsets_free(Offsets *o) {
    for (size_t i = 0; i < o->n; i++) {
        free(o->v[i].name);
        free(o->v[i].layout_provenance);
        map_free(&o->v[i].fields, true);
        map_free(&o->v[i].static_fields, true);
        map_free(&o->v[i].unresolved_fields, true);
    }
    free(o->v);
    map_free(&o->by_name, true);
    memset(o, 0, sizeof(*o));
}
static void mangle_inplace(char *s) {
    for (; *s; s++)
        if (!is_idc(*s))
            *s = '_';
}
static char *mangle_field(const char *s) {
    char *o = xstrdup(s);
    if (o)
        mangle_inplace(o);
    return o;
}
static char *mangle_name(const char *ns, const char *name) {
    size_t nn = ns ? strlen(ns) : 0, nm = strlen(name);
    char *base = xstrdup(name);
    if (!base)
        return NULL;
    if (nm >= 2 && base[nm - 1] == '>') {
        int d = 0;
        size_t k = nm;
        while (k) {
            char c = base[k - 1];
            if (c == '>')
                d++;
            else if (c == '<' && --d == 0) {
                k--;
                break;
            }
            k--;
        }
        int commas = 0;
        for (size_t j = k + 1; j + 1 < nm; j++)
            if (base[j] == ',')
                commas++;
        char *q = NULL;
        str_printf(&q, "%.*s_%d", (int)k, base, commas + 1);
        free(base);
        base = q;
    }
    mangle_inplace(base);
    size_t base_len = strlen(base);
    size_t cap = nn + base_len + 2;
    char *out = malloc(cap);
    if (!out) {
        free(base);
        return NULL;
    }
    size_t w = 0;
    if (ns && *ns) {
        for (const char *p = ns; *p; p++)
            out[w++] = *p == '.' ? '_' : *p;
        out[w++] = '_';
    }
    memcpy(out + w, base, base_len + 1);
    free(base);
    return out;
}
static char *dump_classname(const char *line, const char *ns) {
    const char *s = line;
    while (*s == ' ' || *s == '\t')
        s++;
    const char *quals[] = {"public ",   "internal ", "private ",  "protected ", "sealed ",
                           "abstract ", "static ",   "readonly ", NULL};
    bool again = true;
    while (again) {
        again = false;
        for (int i = 0; quals[i]; i++) {
            size_t n = strlen(quals[i]);
            if (!strncmp(s, quals[i], n)) {
                s += n;
                again = true;
                break;
            }
        }
    }
    const char *kws[] = {"class ", "struct ", "enum ", "interface ", NULL};
    for (int i = 0; kws[i]; i++) {
        size_t n = strlen(kws[i]);
        if (!strncmp(s, kws[i], n)) {
            s += n;
            const char *e = s;
            int depth = 0;
            while (*e) {
                if (*e == '<')
                    depth++;
                else if (*e == '>')
                    depth--;
                else if (isspace((unsigned char)*e) && depth == 0)
                    break;
                e++;
            }
            char *nm = xstrndup(s, (size_t)(e - s));
            char *r = mangle_name(ns, nm);
            free(nm);
            return r;
        }
    }
    return NULL;
}
static bool parse_dumpcs(const char *path, Offsets *o, char **err) {
    size_t n = 0;
    bool too_large = false;
    char *d = slurp(path, &n, I2C_MAX_OFFSETS_BYTES, &too_large);
    if (!d) {
        if (too_large)
            str_printf(err, "offset input exceeds %zu byte limit: %s", I2C_MAX_OFFSETS_BYTES, path);
        else
            str_printf(err, "cannot read offsets: %s", path);
        return false;
    }
    char *cur = NULL, *ns = xstrdup("");
    char *save = NULL;
    for (char *line = strtok_r(d, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *t = xstrdup(line);
        if (!t) {
            free(cur);
            free(ns);
            free(d);
            *err = xstrdup("dump.cs parser OOM");
            return false;
        }
        char *trim = t;
        while (*trim && isspace((unsigned char)*trim))
            trim++;
        size_t tl = strlen(trim);
        while (tl && isspace((unsigned char)trim[tl - 1]))
            trim[--tl] = 0;
        if (!strncmp(trim, "//", 2)) {
            char *p = strstr(trim, "Namespace:");
            if (p) {
                p += 10;
                while (isspace((unsigned char)*p))
                    p++;
                free(ns);
                ns = xstrdup(p);
            }
            free(t);
            continue;
        }
        char *cn = dump_classname(trim, ns);
        if (cn) {
            free(cur);
            cur = cn;
            off_class(o, cur, true);
            free(t);
            continue;
        }
        if (cur) {
            char *hex = strstr(line, "// 0x");
            if (hex) {
                char *semi = NULL;
                for (char *p = line; p < hex; p++)
                    if (*p == ';')
                        semi = p;
                if (semi) {
                    bool is_static = false;
                    for (char *p = line; p + 6 <= semi; p++)
                        if (!strncmp(p, "static", 6) && (p == line || !is_idc(p[-1])) &&
                            (p + 6 == semi || !is_idc(p[6]))) {
                            is_static = true;
                            break;
                        }
                    errno = 0;
                    char *end = NULL;
                    uint64_t off = strtoull(hex + 5, &end, 16);
                    if (errno != ERANGE && end > hex + 5 && off <= UINT32_MAX) {
                        char *e = semi;
                        while (e > line && isspace((unsigned char)e[-1]))
                            e--;
                        char *b = e;
                        while (b > line && !isspace((unsigned char)b[-1]))
                            b--;
                        if (b < e) {
                            char *raw = xstrndup(b, (size_t)(e - b));
                            char *fn = raw ? mangle_field(raw) : NULL;
                            OffClass *c = off_class(o, cur, true);
                            if (!raw || !fn || !c) {
                                free(raw);
                                free(fn);
                                free(t);
                                free(cur);
                                free(ns);
                                free(d);
                                *err = xstrdup("dump.cs parser OOM");
                                return false;
                            }
                            StrMap *target = is_static ? &c->static_fields : &c->fields;
                            uint64_t limit = is_static ? UINT32_MAX : I2C_MAX_OFFSET;
                            if (target && fn && off <= limit &&
                                !map_put(target, fn, (uintptr_t)off, true)) {
                                free(raw);
                                free(fn);
                                free(t);
                                free(cur);
                                free(ns);
                                free(d);
                                *err = xstrdup("dump.cs parser OOM");
                                return false;
                            }
                            free(raw);
                            free(fn);
                        }
                    }
                }
            }
        }
        free(t);
    }
    free(cur);
    free(ns);
    free(d);
    return true;
}

typedef struct {
    const char *p, *end;
    const char *err;
    size_t field_count;
} Json;
static bool j_fail(Json *j, const char *message) {
    if (!j->err)
        j->err = message;
    return false;
}
static void j_ws(Json *j) {
    while (j->p < j->end && strchr(" \t\r\n", *j->p))
        j->p++;
}
static bool j_ch(Json *j, char c) {
    j_ws(j);
    if (j->p < j->end && *j->p == c) {
        j->p++;
        return true;
    }
    return false;
}
static int j_hex_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
static char *j_string(Json *j) {
    j_ws(j);
    if (j->p >= j->end || *j->p != '"')
        return NULL;
    j->p++;
    size_t cap = 64, n = 0;
    char *out = malloc(cap);
    if (!out)
        return NULL;
    while (j->p < j->end) {
        unsigned char c = (unsigned char)*j->p++;
        if (c == '"') {
            out[n] = 0;
            return out;
        }
        if (c < 0x20U) {
            j_fail(j, "type_offsets.json contains an unescaped control character");
            break;
        }
        if (c == '\\') {
            if (j->p >= j->end)
                break;
            c = (unsigned char)*j->p++;
            switch (c) {
            case '"':
            case '\\':
            case '/':
                break;
            case 'b':
                c = '\b';
                break;
            case 'f':
                c = '\f';
                break;
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            case 'u': {
                if ((size_t)(j->end - j->p) < 4U) {
                    j_fail(j, "type_offsets.json contains a truncated Unicode escape");
                    goto invalid_string;
                }
                unsigned v = 0;
                for (unsigned k = 0; k < 4U; k++) {
                    int digit = j_hex_value(*j->p++);
                    if (digit < 0) {
                        j_fail(j, "type_offsets.json contains an invalid Unicode escape");
                        goto invalid_string;
                    }
                    v = (v << 4) | (unsigned)digit;
                }
                if (v == 0U) {
                    j_fail(j, "type_offsets.json strings cannot contain NUL");
                    goto invalid_string;
                }
                c = v < 128U ? (unsigned char)v : (unsigned char)'_';
                break;
            }
            default:
                j_fail(j, "type_offsets.json contains an invalid escape");
                goto invalid_string;
            }
        }
        if (n >= I2C_MAX_JSON_STRING_BYTES) {
            j_fail(j, "type_offsets.json string exceeds limit");
            break;
        }
        if (n + 2 > cap) {
            if (cap > I2C_MAX_JSON_STRING_BYTES / 2U) {
                j_fail(j, "type_offsets.json string exceeds limit");
                break;
            }
            cap *= 2U;
            char *q = realloc(out, cap);
            if (!q) {
                j_fail(j, "type_offsets.json string allocation failed");
                free(out);
                return NULL;
            }
            out = q;
        }
        out[n++] = (char)c;
    }
invalid_string:
    free(out);
    return NULL;
}
static bool j_skip(Json *j, unsigned depth);
static bool j_skip_obj(Json *j, unsigned depth) {
    if (!j_ch(j, '{'))
        return false;
    j_ws(j);
    if (j_ch(j, '}'))
        return true;
    for (;;) {
        char *k = j_string(j);
        if (!k)
            return false;
        free(k);
        if (!j_ch(j, ':') || !j_skip(j, depth))
            return false;
        if (j_ch(j, '}'))
            return true;
        if (!j_ch(j, ','))
            return false;
    }
}
static bool j_skip_arr(Json *j, unsigned depth) {
    if (!j_ch(j, '['))
        return false;
    if (j_ch(j, ']'))
        return true;
    for (;;) {
        if (!j_skip(j, depth))
            return false;
        if (j_ch(j, ']'))
            return true;
        if (!j_ch(j, ','))
            return false;
    }
}
static bool j_skip_number(Json *j) {
    const char *p = j->p;
    if (p < j->end && *p == '-')
        p++;
    if (p >= j->end)
        return false;
    if (*p == '0')
        p++;
    else if (*p >= '1' && *p <= '9') {
        do {
            p++;
        } while (p < j->end && *p >= '0' && *p <= '9');
    } else
        return false;
    if (p < j->end && *p == '.') {
        p++;
        if (p >= j->end || *p < '0' || *p > '9')
            return false;
        do {
            p++;
        } while (p < j->end && *p >= '0' && *p <= '9');
    }
    if (p < j->end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < j->end && (*p == '+' || *p == '-'))
            p++;
        if (p >= j->end || *p < '0' || *p > '9')
            return false;
        do {
            p++;
        } while (p < j->end && *p >= '0' && *p <= '9');
    }
    j->p = p;
    return true;
}
static bool j_skip_literal(Json *j, const char *literal) {
    size_t length = strlen(literal);
    if ((size_t)(j->end - j->p) < length || strncmp(j->p, literal, length))
        return false;
    j->p += length;
    return true;
}
static bool j_skip(Json *j, unsigned depth) {
    j_ws(j);
    if (j->p >= j->end)
        return false;
    if (*j->p == '{' || *j->p == '[') {
        if (depth >= I2C_MAX_JSON_DEPTH)
            return j_fail(j, "type_offsets.json nesting exceeds limit");
        return *j->p == '{' ? j_skip_obj(j, depth + 1U) : j_skip_arr(j, depth + 1U);
    }
    if (*j->p == '"') {
        char *s = j_string(j);
        free(s);
        return s != NULL;
    }
    if (*j->p == '-' || (*j->p >= '0' && *j->p <= '9'))
        return j_skip_number(j);
    return j_skip_literal(j, "true") || j_skip_literal(j, "false") || j_skip_literal(j, "null");
}
static bool j_uint(Json *j, uint64_t *out) {
    j_ws(j);
    if (j->p >= j->end || *j->p < '0' || *j->p > '9')
        return false;
    const char *p = j->p;
    uint64_t v = 0;
    if (*p == '0') {
        p++;
        if (p < j->end && *p >= '0' && *p <= '9')
            return false;
    } else {
        while (p < j->end && *p >= '0' && *p <= '9') {
            unsigned digit = (unsigned)(*p - '0');
            if (v > (UINT64_MAX - digit) / 10U)
                return false;
            v = v * 10U + digit;
            p++;
        }
    }
    if (p < j->end && !strchr(",}] \t\r\n", *p))
        return false;
    j->p = p;
    *out = v;
    return true;
}
static bool parse_field_object(Json *j, StrMap *fields, bool static_offsets) {
    if (!j_ch(j, '{'))
        return false;
    if (j_ch(j, '}'))
        return true;
    for (;;) {
        char *k = j_string(j);
        if (!k)
            return false;
        if (j->field_count >= I2C_MAX_JSON_FIELDS) {
            free(k);
            return j_fail(j, "type_offsets.json field count exceeds limit");
        }
        uintptr_t previous;
        if (map_get(fields, k, &previous)) {
            free(k);
            return j_fail(j, "type_offsets.json contains a duplicate field");
        }
        if (!j_ch(j, ':')) {
            free(k);
            return false;
        }
        uint64_t v;
        bool valid_offset =
            j_uint(j, &v) && v <= UINT32_MAX &&
            (v <= I2C_MAX_SIDECAR_OFFSET || (static_offsets && (v & UINT32_C(0x80000000))));
        if (!valid_offset || !map_put(fields, k, (uintptr_t)v, false)) {
            free(k);
            return false;
        }
        j->field_count++;
        free(k);
        if (j_ch(j, '}'))
            return true;
        if (!j_ch(j, ','))
            return false;
    }
}
enum { UNRESOLVED_OTHER = 1, UNRESOLVED_OPEN_GENERIC = 2 };

static bool parse_unresolved_object(Json *j, StrMap *fields) {
    if (!j_ch(j, '{'))
        return false;
    if (j_ch(j, '}'))
        return true;
    for (;;) {
        char *field = j_string(j);
        if (!field || !j_ch(j, ':')) {
            free(field);
            return false;
        }
        if (j->field_count >= I2C_MAX_JSON_FIELDS) {
            free(field);
            return j_fail(j, "type_offsets.json field count exceeds limit");
        }
        uintptr_t previous;
        if (map_get(fields, field, &previous)) {
            free(field);
            return j_fail(j, "type_offsets.json contains a duplicate unresolved field");
        }
        char *reason = j_string(j);
        if (!reason || !map_put(fields, field,
                                !strcmp(reason, "openGenericLayout") ? UNRESOLVED_OPEN_GENERIC
                                                                     : UNRESOLVED_OTHER,
                                false)) {
            free(field);
            free(reason);
            return false;
        }
        free(field);
        free(reason);
        j->field_count++;
        if (j_ch(j, '}'))
            return true;
        if (!j_ch(j, ','))
            return false;
    }
}

static bool parse_type_object(Json *j, OffClass *c) {
    if (!j_ch(j, '{'))
        return false;
    if (j_ch(j, '}'))
        return true;
    unsigned seen = 0;
    for (;;) {
        char *k = j_string(j);
        if (!k)
            return false;
        if (!j_ch(j, ':')) {
            free(k);
            return false;
        }
        bool ok;
        unsigned property = 0;
        if (!strcmp(k, "fields"))
            property = 1U;
        else if (!strcmp(k, "staticFields"))
            property = 2U;
        else if (!strcmp(k, "unresolvedFields"))
            property = 4U;
        else if (!strcmp(k, "layoutProvenance"))
            property = 8U;
        else if (!strcmp(k, "instanceSize"))
            property = 16U;
        if (property && (seen & property)) {
            free(k);
            return j_fail(j, "type_offsets.json contains a duplicate type property");
        }
        seen |= property;
        if (property == 1U)
            ok = parse_field_object(j, &c->fields, false);
        else if (property == 2U)
            ok = parse_field_object(j, &c->static_fields, true);
        else if (property == 4U)
            ok = parse_unresolved_object(j, &c->unresolved_fields);
        else if (!strcmp(k, "layoutProvenance")) {
            char *provenance = j_string(j);
            ok = provenance != NULL;
            if (ok) {
                free(c->layout_provenance);
                c->layout_provenance = provenance;
            }
        } else if (property == 16U) {
            uint64_t instance_size;
            ok = j_uint(j, &instance_size) && instance_size > 0 &&
                 instance_size <= I2C_MAX_SIDECAR_OFFSET;
            if (ok) {
                c->instance_size = (uint32_t)instance_size;
                c->has_instance_size = true;
            }
        } else
            ok = j_skip(j, 0U);
        free(k);
        if (!ok)
            return false;
        if (j_ch(j, '}'))
            return true;
        if (!j_ch(j, ','))
            return false;
    }
}
static bool parse_types_object(Json *j, Offsets *o) {
    if (!j_ch(j, '{'))
        return false;
    if (j_ch(j, '}'))
        return true;
    for (;;) {
        char *k = j_string(j);
        if (!k)
            return false;
        if (!j_ch(j, ':')) {
            free(k);
            return false;
        }
        if (o->n >= I2C_MAX_JSON_TYPES) {
            free(k);
            return j_fail(j, "type_offsets.json type count exceeds limit");
        }
        if (off_class(o, k, false)) {
            free(k);
            return j_fail(j, "type_offsets.json contains a duplicate type");
        }
        OffClass *c = off_class(o, k, true);
        free(k);
        if (!c || !parse_type_object(j, c))
            return false;
        if (j_ch(j, '}'))
            return true;
        if (!j_ch(j, ','))
            return false;
    }
}
static bool parse_json_offsets(const char *path, Offsets *o, char **err) {
    size_t n = 0;
    bool too_large = false;
    char *d = slurp(path, &n, I2C_MAX_OFFSETS_BYTES, &too_large);
    if (!d) {
        if (too_large)
            str_printf(err, "type_offsets.json exceeds %zu byte limit: %s", I2C_MAX_OFFSETS_BYTES,
                       path);
        else
            str_printf(err, "cannot read offsets: %s", path);
        return false;
    }
    Json j = {.p = d, .end = d + n};
    bool found = false;
    bool found_version = false, found_pointer_size = false;
    if (!j_ch(&j, '{'))
        goto bad;
    if (!j_ch(&j, '}'))
        for (;;) {
            char *k = j_string(&j);
            if (!k || !j_ch(&j, ':')) {
                free(k);
                goto bad;
            }
            bool ok;
            if (!strcmp(k, "version")) {
                if (found_version) {
                    free(k);
                    j_fail(&j, "type_offsets.json contains a duplicate version");
                    goto bad;
                }
                found_version = true;
                uint64_t version;
                ok = j_uint(&j, &version) && version <= UINT32_MAX;
                if (ok)
                    o->schema_version = (uint32_t)version;
            } else if (!strcmp(k, "pointerSize")) {
                if (found_pointer_size) {
                    free(k);
                    j_fail(&j, "type_offsets.json contains a duplicate pointerSize");
                    goto bad;
                }
                found_pointer_size = true;
                uint64_t pointer_size;
                ok = j_uint(&j, &pointer_size) && (pointer_size == 4 || pointer_size == 8);
                if (ok) {
                    o->pointer_size = (uint32_t)pointer_size;
                    o->has_pointer_size = true;
                }
            } else if (!strcmp(k, "types")) {
                if (found) {
                    free(k);
                    j_fail(&j, "type_offsets.json contains a duplicate types object");
                    goto bad;
                }
                found = true;
                ok = parse_types_object(&j, o);
            } else
                ok = j_skip(&j, 0U);
            free(k);
            if (!ok)
                goto bad;
            if (j_ch(&j, '}'))
                break;
            if (!j_ch(&j, ','))
                goto bad;
        }
    j_ws(&j);
    if (j.p != j.end) {
        j_fail(&j, "type_offsets.json contains trailing data");
        goto bad;
    }
    free(d);
    if (!found) {
        *err = xstrdup("offset JSON has no top-level 'types' object");
        return false;
    }
    if (o->schema_version > 3) {
        str_printf(err, "unsupported type_offsets.json schema version %u", o->schema_version);
        return false;
    }
    if (o->schema_version < 3) {
        for (size_t i = 0; i < o->n; i++) {
            if (o->v[i].has_instance_size) {
                *err = xstrdup("type_offsets.json instanceSize requires schema version 3");
                return false;
            }
        }
    }
    o->exact_json = true;
    return true;
bad:
    free(d);
    *err = xstrdup(j.err ? j.err : "invalid type_offsets.json");
    return false;
}
static bool parse_offsets(const char *path, Offsets *o, char **err) {
    if (!map_init(&o->by_name, 1024)) {
        *err = xstrdup("offset map OOM");
        return false;
    }
    if (!path || !*path) {
        o->source = OFFSET_SOURCE_HEADER_ONLY;
        return true;
    }
    size_t n = strlen(path);
    if (n >= 5 && !strcmp(path + n - 5, ".json")) {
        o->source = OFFSET_SOURCE_TYPE_OFFSETS_JSON;
        return parse_json_offsets(path, o, err);
    }
    o->source = OFFSET_SOURCE_DUMP_CS;
    return parse_dumpcs(path, o, err);
}

/* ---------------- flattening / resolution ---------------- */
typedef struct {
    Member **v;
    size_t n, cap;
    bool ok;
} MemberRefs;
typedef struct {
    StructDef **v;
    size_t n, cap;
    bool ok;
} StructRefs;
static bool sref_push(StructRefs *r, StructDef *s) {
    if (!vec_grow((void **)&r->v, &r->cap, sizeof(*r->v), r->n + 1))
        return false;
    r->v[r->n++] = s;
    return true;
}
static bool mref_push(MemberRefs *r, Member *m) {
    if (!vec_grow((void **)&r->v, &r->cap, sizeof(*r->v), r->n + 1))
        return false;
    r->v[r->n++] = m;
    return true;
}
static bool chain_rec(StructTable *t, StructDef *s, StructRefs *out, StrMap *seen, int depth) {
    if (!s || map_get(seen, s->name, NULL))
        return true;
    if (depth > I2C_MAX_DEPTH || !map_put(seen, s->name, 1, false))
        return false;
    if (s->parent && !chain_rec(t, struct_find(t, s->parent), out, seen, depth + 1))
        return false;
    return sref_push(out, s);
}
static StructRefs fields_chain(StructTable *t, const char *name) {
    StructRefs r = {.ok = true};
    StrMap seen = {0};
    if (!map_init(&seen, 16) || !chain_rec(t, struct_find(t, name), &r, &seen, 0))
        r.ok = false;
    map_free(&seen, true);
    return r;
}
static MemberRefs flatten(StructTable *t, const char *name) {
    MemberRefs r = {.ok = true};
    StructRefs c = fields_chain(t, name);
    if (!c.ok)
        r.ok = false;
    for (size_t i = 0; i < c.n && r.ok; i++)
        for (size_t j = 0; j < c.v[i]->n; j++)
            if (!mref_push(&r, &c.v[i]->members[j])) {
                r.ok = false;
                break;
            }
    free(c.v);
    return r;
}
static char *strip_fields(const char *s) {
    size_t n = strlen(s);
    FieldStorageKind kind = field_storage_kind(s);
    size_t suffix = kind == FIELD_STORAGE_STATIC     ? strlen("_StaticFields")
                    : kind == FIELD_STORAGE_INSTANCE ? strlen("_Fields")
                                                     : 0;
    return suffix && n > suffix ? xstrndup(s, n - suffix) : xstrdup(s);
}
static StrMap *stored_offsets(OffClass *type, FieldStorageKind kind) {
    if (kind == FIELD_STORAGE_STATIC)
        return &type->static_fields;
    return kind == FIELD_STORAGE_INSTANCE ? &type->fields : NULL;
}
static OffClass *nested_match(StructDef *fs, const char *cls, Offsets *o, FieldStorageKind kind) {
    int best = -1;
    OffClass *bc = NULL;
    for (const char *p = cls; (p = strchr(p, '_'));) {
        p++;
        OffClass *c = off_class(o, p, false);
        if (!c)
            continue;
        StrMap *offsets = stored_offsets(c, kind);
        if (!offsets)
            continue;
        int score = 0;
        for (size_t i = 0; i < fs->n; i++)
            if (map_get(offsets, fs->members[i].name, NULL))
                score++;
        if (score > best || (score == best && bc && strlen(c->name) > strlen(bc->name))) {
            best = score;
            bc = c;
        }
    }
    return best > 0 || (!fs->n && bc) ? bc : NULL;
}
static bool build_offset_map(StructTable *t, const char *fields_name, Offsets *o, StrMap *out) {
    if (!map_init(out, 32))
        return false;
    StructRefs c = fields_chain(t, fields_name);
    bool ok = c.ok;
    for (size_t i = 0; i < c.n && ok; i++) {
        StructDef *fs = c.v[i];
        FieldStorageKind kind = field_storage_kind_for(t, fs->name);
        if (kind == FIELD_STORAGE_NONE)
            continue;
        char *cls = strip_fields(fs->name);
        if (!cls) {
            ok = false;
            break;
        }
        OffClass *oc = off_class(o, cls, false);
        if (!oc && !o->exact_json && kind == FIELD_STORAGE_INSTANCE)
            oc = nested_match(fs, cls, o, kind);
        StrMap *offsets = oc ? stored_offsets(oc, kind) : NULL;
        if (offsets)
            for (size_t q = 0; q < offsets->cap; q++)
                if (offsets->e[q].key &&
                    (kind != FIELD_STORAGE_STATIC ||
                     !(offsets->e[q].value & UINT32_C(0x80000000))) &&
                    !map_put(out, offsets->e[q].key, offsets->e[q].value, true)) {
                    ok = false;
                    break;
                }
        free(cls);
    }
    free(c.v);
    return ok;
}
static bool lookup_instance_size(const char *fields_name, Offsets *offsets, uint32_t *size) {
    if (!offsets->exact_json || field_storage_kind(fields_name) != FIELD_STORAGE_INSTANCE)
        return false;
    char *name = strip_fields(fields_name);
    if (!name)
        return false;
    OffClass *type = off_class(offsets, name, false);
    free(name);
    if (!type || !type->has_instance_size)
        return false;
    *size = type->instance_size;
    return true;
}
static bool lookup_off(StrMap *m, const char *name, uint32_t *out) {
    uintptr_t x;
    if (map_get(m, name, &x)) {
        *out = (uint32_t)x;
        return true;
    }
    if (name[0] == '_' && name[1] && map_get(m, name + 1, &x)) {
        *out = (uint32_t)x;
        return true;
    }
    return false;
}
static bool lookup_map_value(StrMap *m, const char *name, uintptr_t *out) {
    if (map_get(m, name, out))
        return true;
    return name[0] == '_' && name[1] && map_get(m, name + 1, out);
}

typedef enum {
    MISSING_OPEN_GENERIC,
    MISSING_CONCRETE_SIDECAR,
    MISSING_GENERIC_PARENT,
    MISSING_OBJECT_HEADER,
    MISSING_UNSUPPORTED_LAYOUT,
    MISSING_REASON_COUNT
} MissingReason;

static StructDef *member_owner(StructTable *t, const char *fields_name, Member *member) {
    StructRefs chain = fields_chain(t, fields_name);
    StructDef *owner = NULL;
    if (chain.ok)
        for (size_t i = 0; i < chain.n && !owner; i++)
            for (size_t j = 0; j < chain.v[i]->n; j++)
                if (&chain.v[i]->members[j] == member) {
                    owner = chain.v[i];
                    break;
                }
    free(chain.v);
    return owner;
}

static bool is_open_generic(const OffClass *type) {
    return type && type->layout_provenance &&
           !strcmp(type->layout_provenance, "unresolvedOpenGeneric");
}

static MissingReason classify_missing_offset(StructTable *t, Offsets *offsets,
                                             const char *root_fields, Member *member) {
    if (offsets->schema_version < 2)
        return MISSING_UNSUPPORTED_LAYOUT;
    char *root_name = strip_fields(root_fields);
    StructDef *owner = member_owner(t, root_fields, member);
    char *owner_name = owner ? strip_fields(owner->name) : NULL;
    OffClass *root = root_name ? off_class(offsets, root_name, false) : NULL;
    OffClass *declaring = owner_name ? off_class(offsets, owner_name, false) : NULL;
    uintptr_t unresolved = 0;
    bool unresolved_open =
        declaring && lookup_map_value(&declaring->unresolved_fields, member->name, &unresolved) &&
        unresolved == UNRESOLVED_OPEN_GENERIC;
    MissingReason reason;
    if (is_open_generic(root))
        reason = MISSING_OPEN_GENERIC;
    else if (is_open_generic(declaring) || unresolved_open)
        reason = MISSING_GENERIC_PARENT;
    else if (!root)
        reason = MISSING_CONCRETE_SIDECAR;
    else
        reason = MISSING_UNSUPPORTED_LAYOUT;
    free(owner_name);
    free(root_name);
    return reason;
}

static char *normalize_type(const char *ctype) {
    char *c = xstrdup(ctype);
    if (!c)
        return NULL;
    size_t n = strlen(c);
    while (n && isspace((unsigned char)c[n - 1]))
        c[--n] = 0;
    char *p = c;
    while (isspace((unsigned char)*p))
        p++;
    if (p != c)
        memmove(c, p, strlen(p) + 1);
    n = strlen(c);
    char *br = strchr(c, '['), *arr = NULL;
    if (br) {
        arr = xstrdup(br);
        if (!arr) {
            free(c);
            return NULL;
        }
        *br = 0;
        n = strlen(c);
    }
    if (strstr(c, "(*)") || (n && c[n - 1] == '*')) {
        if (arr && !append_text(&c, arr)) {
            free(arr);
            free(c);
            return NULL;
        }
        free(arr);
        return c;
    }
    if (!strncmp(c, "struct ", 7)) {
        char *body = c + 7;
        size_t bl = strlen(body);
        if (bl > 2 && !strcmp(body + bl - 2, "_o")) {
            bool ok = true;
            for (char *q = body; *q; q++)
                if (!is_idc(*q)) {
                    ok = false;
                    break;
                }
            if (ok) {
                char *r = NULL;
                str_printf(&r, "struct %.*s_Fields%s", (int)(bl - 2), body, arr ? arr : "");
                free(arr);
                free(c);
                return r;
            }
        }
    }
    if (arr && !append_text(&c, arr)) {
        free(arr);
        free(c);
        return NULL;
    }
    free(arr);
    return c;
}

/* ---------------- emitted model / sizing ---------------- */
typedef struct {
    char *name, *type;
    uint32_t off;
    uint32_t order;
    uint32_t evidence;
} OutField;
typedef enum {
    LAYOUT_EVIDENCE_LEGACY_UNKNOWN = 0,
    LAYOUT_EVIDENCE_SIDECAR_COPIED = 1,
    LAYOUT_EVIDENCE_HEADER_INFERRED = 2,
    LAYOUT_EVIDENCE_ABI_DEFINED = 3
} LayoutEvidence;
typedef struct {
    char *name;
    uint32_t length;
    uint32_t length_evidence;
    OutField *f;
    size_t n, cap;
} OutStruct;
typedef enum { LAYOUT_NEW, LAYOUT_VISITING, LAYOUT_DONE, LAYOUT_UNRESOLVED } LayoutState;
typedef struct {
    char *name;
    uint32_t size, align;
    LayoutState state;
} LayoutRec;
typedef struct {
    OutStruct *v;
    size_t n, cap;
    StrMap by_name;
    LayoutRec *layouts;
    size_t layouts_n, layouts_cap;
    StrMap layout_by_name;
    uint32_t missing;
    uint32_t missing_reasons[MISSING_REASON_COUNT];
    int ptr;
    bool layout_error;
    StructTable *st;
    Offsets *offs;
    OffsetSource offset_source;
    uint32_t offset_schema_version;
} OutModel;
static void record_missing(OutModel *model, MissingReason reason) {
    model->missing++;
    model->missing_reasons[reason]++;
}

static OutStruct *out_struct(OutModel *m, const char *name, bool create) {
    uintptr_t x;
    if (map_get(&m->by_name, name, &x))
        return &m->v[x];
    if (!create)
        return NULL;
    if (!vec_grow((void **)&m->v, &m->cap, sizeof(OutStruct), m->n + 1))
        return NULL;
    OutStruct *s = &m->v[m->n];
    memset(s, 0, sizeof(*s));
    s->name = xstrdup(name);
    if (!s->name || !map_put(&m->by_name, name, m->n, true)) {
        free(s->name);
        memset(s, 0, sizeof(*s));
        return NULL;
    }
    m->n++;
    return s;
}
static bool out_field_push(OutStruct *s, char *name, char *type, uint32_t off, uint32_t order,
                           LayoutEvidence evidence) {
    if (!name || !type || !vec_grow((void **)&s->f, &s->cap, sizeof(OutField), s->n + 1)) {
        free(name);
        free(type);
        return false;
    }
    s->f[s->n++] = (OutField){name, type, off, order, (uint32_t)evidence};
    return true;
}
static void model_free(OutModel *m) {
    for (size_t i = 0; i < m->n; i++) {
        free(m->v[i].name);
        for (size_t j = 0; j < m->v[i].n; j++) {
            free(m->v[i].f[j].name);
            free(m->v[i].f[j].type);
        }
        free(m->v[i].f);
    }
    free(m->v);
    for (size_t i = 0; i < m->layouts_n; i++)
        free(m->layouts[i].name);
    free(m->layouts);
    map_free(&m->layout_by_name, true);
    map_free(&m->by_name, true);
    memset(m, 0, sizeof(*m));
}
static int field_cmp(const void *a, const void *b) {
    const OutField *x = a, *y = b;
    return x->off < y->off       ? -1
           : x->off > y->off     ? 1
           : x->order < y->order ? -1
           : x->order > y->order ? 1
                                 : 0;
}
static bool parse_array(const char *t, char **base, uint32_t *cnt) {
    const char *b = strrchr(t, '[');
    *base = NULL;
    *cnt = 0;
    if (!b) {
        *base = xstrdup(t);
        return *base != NULL;
    }
    if (b == t || b[1] < '0' || b[1] > '9')
        return false;
    errno = 0;
    char *e = NULL;
    unsigned long long n = strtoull(b + 1, &e, 10);
    if (errno == ERANGE || !e || *e != ']' || e[1] || !n || n > UINT32_MAX)
        return false;
    *base = xstrndup(t, (size_t)(b - t));
    if (!*base)
        return false;
    *cnt = (uint32_t)n;
    return true;
}
static bool checked_align(uint64_t value, uint32_t align, uint64_t *out) {
    if (!align)
        return false;
    uint64_t rem = value % align, add = rem ? align - rem : 0;
    if (value > UINT64_MAX - add)
        return false;
    *out = value + add;
    return true;
}
static bool layout_type(OutModel *m, const char *t, uint32_t *size, uint32_t *align, int depth);
static LayoutRec *layout_record(OutModel *m, const char *name) {
    uintptr_t idx;
    if (map_get(&m->layout_by_name, name, &idx))
        return &m->layouts[idx];
    if (!vec_grow((void **)&m->layouts, &m->layouts_cap, sizeof(LayoutRec), m->layouts_n + 1))
        return NULL;
    LayoutRec *r = &m->layouts[m->layouts_n];
    memset(r, 0, sizeof(*r));
    r->name = xstrdup(name);
    if (!r->name || !map_put(&m->layout_by_name, name, m->layouts_n, true)) {
        free(r->name);
        memset(r, 0, sizeof(*r));
        return NULL;
    }
    m->layouts_n++;
    return r;
}
static bool value_layout(OutModel *m, const char *name, uint32_t *size, uint32_t *align,
                         int depth) {
    if (depth > I2C_MAX_DEPTH) {
        return false;
    }
    LayoutRec *r = layout_record(m, name);
    if (!r) {
        m->layout_error = true;
        return false;
    }
    uintptr_t record_index;
    if (!map_get(&m->layout_by_name, name, &record_index)) {
        m->layout_error = true;
        return false;
    }
    if (r->state == LAYOUT_DONE) {
        *size = r->size;
        *align = r->align;
        return true;
    }
    if (r->state == LAYOUT_VISITING || r->state == LAYOUT_UNRESOLVED) {
        r->state = LAYOUT_UNRESOLVED;
        return false;
    }
    r->state = LAYOUT_VISITING;
    StructDef *definition = struct_find(m->st, name);
    MemberRefs flat = flatten(m->st, name);
    if (!flat.ok) {
        free(flat.v);
        m->layout_error = true;
        r->state = LAYOUT_UNRESOLVED;
        return false;
    }
    if (!definition) {
        free(flat.v);
        r->state = LAYOUT_UNRESOLVED;
        return false;
    }
    if (!flat.n) {
        free(flat.v);
        r->size = 1;
        r->align = 1;
        r->state = LAYOUT_DONE;
        *size = 1;
        *align = 1;
        return true;
    }
    StrMap om = {0};
    if (!build_offset_map(m->st, name, m->offs, &om)) {
        map_free(&om, true);
        free(flat.v);
        m->layout_error = true;
        r->state = LAYOUT_UNRESOLVED;
        return false;
    }
    bool all = m->offs->n > 0;
    for (size_t i = 0; i < flat.n && all; i++) {
        uint32_t q;
        if (!lookup_off(&om, flat.v[i]->name, &q))
            all = false;
    }
    uint64_t natural = 0, maximum = 0;
    uint32_t compound_align = 1;
    for (size_t i = 0; i < flat.n; i++) {
        char *nt = normalize_type(flat.v[i]->ctype);
        uint32_t member_size, member_align;
        bool member_ok = nt && layout_type(m, nt, &member_size, &member_align, depth + 1);
        r = &m->layouts[record_index];
        if (!member_ok) {
            free(nt);
            map_free(&om, true);
            free(flat.v);
            r->state = LAYOUT_UNRESOLVED;
            return false;
        }
        free(nt);
        if (member_align > compound_align)
            compound_align = member_align;
        uint64_t end;
        if (all) {
            uint32_t off;
            if (!lookup_off(&om, flat.v[i]->name, &off)) {
                m->layout_error = true;
                map_free(&om, true);
                free(flat.v);
                r->state = LAYOUT_UNRESOLVED;
                return false;
            }
            end = (uint64_t)off + member_size;
        } else if (definition->is_union)
            end = member_size;
        else {
            if (!checked_align(natural, member_align, &natural) ||
                natural > UINT64_MAX - member_size) {
                m->layout_error = true;
                map_free(&om, true);
                free(flat.v);
                r->state = LAYOUT_UNRESOLVED;
                return false;
            }
            natural += member_size;
            end = natural;
        }
        if (end > maximum)
            maximum = end;
    }
    if (!all && !definition->is_union) {
        maximum = natural;
    }
    if (!checked_align(maximum, compound_align, &maximum) || maximum > I2C_MAX_OFFSET) {
        m->layout_error = true;
        map_free(&om, true);
        free(flat.v);
        r->state = LAYOUT_UNRESOLVED;
        return false;
    }
    map_free(&om, true);
    free(flat.v);
    r->size = (uint32_t)(maximum ? maximum : 1);
    r->align = compound_align;
    r->state = LAYOUT_DONE;
    *size = r->size;
    *align = r->align;
    return true;
}
static bool layout_type(OutModel *m, const char *t, uint32_t *size, uint32_t *align, int depth) {
    if (depth > I2C_MAX_DEPTH) {
        return false;
    }
    char *base = NULL;
    uint32_t count = 0;
    if (!parse_array(t, &base, &count)) {
        m->layout_error = true;
        return false;
    }
    if (count) {
        uint32_t element_size, element_align;
        bool ok = layout_type(m, base, &element_size, &element_align, depth + 1);
        free(base);
        if (!ok)
            return false;
        uint64_t total = (uint64_t)element_size * count;
        if (total > I2C_MAX_OFFSET) {
            m->layout_error = true;
            return false;
        }
        *size = (uint32_t)total;
        *align = element_align;
        return true;
    }
    size_t n = strlen(base);
    if (strstr(base, "(*)") || (n && base[n - 1] == '*')) {
        *size = *align = (uint32_t)m->ptr;
        free(base);
        return true;
    }
    const char *b = !strncmp(base, "struct ", 7)  ? base + 7
                    : !strncmp(base, "union ", 6) ? base + 6
                                                  : base;
    bool ok = true;
    if (!strcmp(b, "bool") || !strcmp(b, "char") || !strcmp(b, "int8_t") || !strcmp(b, "uint8_t"))
        *size = *align = 1;
    else if (!strcmp(b, "int16_t") || !strcmp(b, "uint16_t")) {
        *size = *align = 2;
    } else if (!strcmp(b, "int32_t") || !strcmp(b, "uint32_t") || !strcmp(b, "float") ||
               !strcmp(b, "int") || !strcmp(b, "unsigned int")) {
        *size = *align = 4;
    } else if (!strcmp(b, "int64_t") || !strcmp(b, "uint64_t") || !strcmp(b, "double")) {
        *size = *align = 8;
    } else if (!strcmp(b, "intptr_t") || !strcmp(b, "uintptr_t")) {
        *size = *align = (uint32_t)m->ptr;
    } else if (struct_find(m->st, b))
        ok = value_layout(m, b, size, align, depth + 1);
    else
        *size = *align = (uint32_t)m->ptr;
    free(base);
    return ok;
}
static bool effective_layout(OutModel *m, const char *t, uint32_t *size, uint32_t *align) {
    if (layout_type(m, t, size, align, 0))
        return true;
    if (m->layout_error)
        return false;
    *size = *align = (uint32_t)m->ptr;
    return true;
}
static bool proven_type_size(OutModel *model, const char *type, uint32_t *size, bool *known,
                             int depth) {
    *known = false;
    if (depth > I2C_MAX_DEPTH)
        return false;
    char *base = NULL;
    uint32_t count = 0;
    if (!parse_array(type, &base, &count))
        return false;
    if (count) {
        uint32_t element_size;
        bool element_known;
        bool ok = proven_type_size(model, base, &element_size, &element_known, depth + 1);
        free(base);
        if (!ok || !element_known)
            return ok;
        uint64_t total = (uint64_t)element_size * count;
        if (total > I2C_MAX_OFFSET)
            return false;
        *size = (uint32_t)total;
        *known = true;
        return true;
    }
    size_t length = strlen(base);
    if (strstr(base, "(*)") || (length && base[length - 1] == '*')) {
        *size = (uint32_t)model->ptr;
        *known = true;
    } else {
        const char *name = !strncmp(base, "struct ", 7)  ? base + 7
                           : !strncmp(base, "union ", 6) ? base + 6
                                                         : base;
        if (!strcmp(name, "bool") || !strcmp(name, "char") || !strcmp(name, "int8_t") ||
            !strcmp(name, "uint8_t")) {
            *size = 1;
            *known = true;
        } else if (!strcmp(name, "int16_t") || !strcmp(name, "uint16_t")) {
            *size = 2;
            *known = true;
        } else if (!strcmp(name, "int32_t") || !strcmp(name, "uint32_t") ||
                   !strcmp(name, "float") || !strcmp(name, "int") ||
                   !strcmp(name, "unsigned int")) {
            *size = 4;
            *known = true;
        } else if (!strcmp(name, "int64_t") || !strcmp(name, "uint64_t") ||
                   !strcmp(name, "double")) {
            *size = 8;
            *known = true;
        } else if (!strcmp(name, "intptr_t") || !strcmp(name, "uintptr_t")) {
            *size = (uint32_t)model->ptr;
            *known = true;
        } else if (lookup_instance_size(name, model->offs, size)) {
            *known = true;
        }
    }
    free(base);
    return true;
}
static bool finalize_length(OutModel *m, OutStruct *s) {
    uint64_t z = s->length;
    for (size_t i = 0; i < s->n; i++) {
        uint32_t size = 0, align;
        bool size_known;
        if (!proven_type_size(m, s->f[i].type, &size, &size_known, 0) ||
            (!size_known && !effective_layout(m, s->f[i].type, &size, &align)))
            return false;
        uint64_t e = (uint64_t)s->f[i].off + size;
        if (e > I2C_MAX_OFFSET)
            return false;
        if (e > z)
            z = e;
    }
    s->length = (uint32_t)(z ? z : 1);
    return true;
}
static bool apply_instance_size(OutModel *model, OutStruct *structure, const char *fields_name) {
    uint32_t instance_size;
    if (!lookup_instance_size(fields_name, model->offs, &instance_size))
        return false;
    if (structure->length > instance_size)
        return false;
    for (size_t i = 0; i < structure->n; i++) {
        uint32_t field_size;
        bool size_known;
        if (structure->f[i].off >= instance_size ||
            !proven_type_size(model, structure->f[i].type, &field_size, &size_known, 0) ||
            (size_known && (uint64_t)structure->f[i].off + field_size > instance_size))
            return false;
    }
    structure->length = instance_size;
    structure->length_evidence = LAYOUT_EVIDENCE_SIDECAR_COPIED;
    return true;
}
static bool pointer_target_name(const char *type, char **target);
static bool collect_needed_type(StructTable *structures, StrMap *need, const char *type) {
    char *base = xstrdup(type);
    if (!base)
        return false;
    for (;;) {
        char *element = NULL;
        uint32_t count;
        if (!parse_array(base, &element, &count) || !element) {
            free(base);
            return false;
        }
        free(base);
        base = element;
        if (!count)
            break;
    }
    size_t length = strlen(base);
    if (strstr(base, "(*)") || (length && base[length - 1] == '*')) {
        char *target = NULL;
        if (!pointer_target_name(base, &target)) {
            free(base);
            return false;
        }
        bool ok = !target || !struct_find(structures, target) ||
                  field_storage_kind_for(structures, target) != FIELD_STORAGE_NONE ||
                  map_put(need, target, 1, false);
        free(target);
        free(base);
        return ok;
    }
    const char *name = !strncmp(base, "struct ", 7)  ? base + 7
                       : !strncmp(base, "union ", 6) ? base + 6
                                                     : base;
    bool ok = !struct_find(structures, name) || map_put(need, name, 1, false);
    free(base);
    return ok;
}
static bool pointer_target_name(const char *type, char **target) {
    *target = NULL;
    char *name = xstrdup(type);
    if (!name)
        return false;
    if (strstr(name, "(*)")) {
        free(name);
        return true;
    }
    size_t length = strlen(name);
    while (length && isspace((unsigned char)name[length - 1]))
        name[--length] = 0;
    if (!length || name[length - 1] != '*') {
        free(name);
        return true;
    }
    do {
        name[--length] = 0;
        while (length && isspace((unsigned char)name[length - 1]))
            name[--length] = 0;
    } while (length && name[length - 1] == '*');
    const char *qualifiers[] = {"const ", "volatile ", "restrict ", NULL};
    bool stripped = true;
    while (stripped) {
        stripped = false;
        for (size_t i = 0; qualifiers[i]; i++) {
            size_t qualifier_length = strlen(qualifiers[i]);
            if (!strncmp(name, qualifiers[i], qualifier_length)) {
                memmove(name, name + qualifier_length, strlen(name + qualifier_length) + 1);
                stripped = true;
                break;
            }
        }
    }
    char *base = !strncmp(name, "struct ", 7)  ? name + 7
                 : !strncmp(name, "union ", 6) ? name + 6
                                               : name;
    if (base != name)
        memmove(name, base, strlen(base) + 1);
    *target = name;
    return true;
}
static bool collect_static_fields_target(OutModel *model, StrMap *need, const char *owner,
                                         const char *field_name, const char *field_type) {
    size_t owner_length = strlen(owner);
    if (owner_length < 2 || strcmp(owner + owner_length - 2, "_c") ||
        strcmp(field_name, "static_fields"))
        return true;
    char *target = NULL, *expected = NULL;
    if (!pointer_target_name(field_type, &target))
        return false;
    bool ok = true;
    if (!target)
        goto done;
    if (str_printf(&expected, "%.*s_StaticFields", (int)(owner_length - 2), owner) < 0) {
        ok = false;
        goto done;
    }
    if (strcmp(target, expected) || !struct_find(model->st, target))
        goto done;
    if (model->offs->source != OFFSET_SOURCE_HEADER_ONLY) {
        StrMap offsets = {0};
        if (!build_offset_map(model->st, target, model->offs, &offsets)) {
            map_free(&offsets, true);
            ok = false;
            goto done;
        }
        bool has_runtime_fields = offsets.len != 0;
        map_free(&offsets, true);
        if (!has_runtime_fields) {
            char *type_name = strip_fields(target);
            OffClass *type = type_name ? off_class(model->offs, type_name, false) : NULL;
            if (type)
                for (size_t i = 0; i < type->static_fields.cap; i++)
                    if (type->static_fields.e[i].key &&
                        (type->static_fields.e[i].value & UINT32_C(0x80000000)))
                        record_missing(model, MISSING_UNSUPPORTED_LAYOUT);
            free(type_name);
            goto done;
        }
    }
    ok = map_put(need, target, 1, false);
done:
    free(expected);
    free(target);
    return ok;
}
static bool emit_value(OutModel *m, const char *name, StrMap *need) {
    if (out_struct(m, name, false))
        return true;
    MemberRefs flat = flatten(m->st, name);
    if (!flat.ok) {
        free(flat.v);
        return false;
    }
    OutStruct *s = out_struct(m, name, true);
    if (!s) {
        free(flat.v);
        return false;
    }
    if (!flat.n) {
        s->length = 1;
        if (!apply_instance_size(m, s, name))
            s->length_evidence = field_storage_kind_for(m->st, name) != FIELD_STORAGE_NONE
                                     ? LAYOUT_EVIDENCE_HEADER_INFERRED
                                     : LAYOUT_EVIDENCE_ABI_DEFINED;
        free(flat.v);
        return true;
    }
    StrMap om = {0}, ded = {0};
    if (!build_offset_map(m->st, name, m->offs, &om) || !map_init(&ded, flat.n + 1)) {
        map_free(&om, true);
        free(flat.v);
        return false;
    }
    StructDef *definition = struct_find(m->st, name);
    bool is_union = definition && definition->is_union;
    FieldStorageKind storage = field_storage_kind_for(m->st, name);
    bool managed_fields = storage != FIELD_STORAGE_NONE;
    bool sidecar_supplied = m->offs->source != OFFSET_SOURCE_HEADER_ONLY && managed_fields;
    LayoutEvidence natural_evidence =
        managed_fields ? LAYOUT_EVIDENCE_HEADER_INFERRED : LAYOUT_EVIDENCE_ABI_DEFINED;
    uint64_t natural = 0;
    for (size_t i = 0; i < flat.n; i++) {
        Member *mem = flat.v[i];
        char *nt = normalize_type(mem->ctype);
        if (!nt)
            goto oom;
        uint32_t off = 0;
        LayoutEvidence evidence;
        bool found = lookup_off(&om, mem->name, &off);
        if (found)
            evidence = LAYOUT_EVIDENCE_SIDECAR_COPIED;
        else if (sidecar_supplied) {
            record_missing(m, classify_missing_offset(m->st, m->offs, name, mem));
            free(nt);
            continue;
        } else if (is_union) {
            off = 0;
            evidence = natural_evidence;
        } else {
            uint32_t a, sz;
            if (!effective_layout(m, nt, &sz, &a) || !checked_align(natural, a, &natural) ||
                natural > I2C_MAX_OFFSET || natural > UINT64_MAX - sz) {
                free(nt);
                goto oom;
            }
            off = (uint32_t)natural;
            natural += sz;
            if (natural > I2C_MAX_OFFSET) {
                free(nt);
                goto oom;
            }
            evidence = natural_evidence;
        }
        uintptr_t idx, field_index;
        if (map_get(&ded, mem->name, &idx)) {
            OutField *f = &s->f[idx];
            free(f->type);
            f->type = nt;
            f->off = off;
            f->evidence = (uint32_t)evidence;
            field_index = idx;
        } else if (!map_put(&ded, mem->name, s->n, true) ||
                   !out_field_push(s, xstrdup(mem->name), nt, off, (uint32_t)i, evidence))
            goto oom;
        else
            field_index = s->n - 1;
        if (!collect_needed_type(m->st, need, s->f[field_index].type) ||
            !collect_static_fields_target(m, need, name, mem->name, s->f[field_index].type))
            goto oom;
    }
    if (s->n > 1)
        qsort(s->f, s->n, sizeof(OutField), field_cmp);
    if (storage != FIELD_STORAGE_INSTANCE || !apply_instance_size(m, s, name)) {
        uint32_t value_size, value_align;
        if (!sidecar_supplied && value_layout(m, name, &value_size, &value_align, 0))
            s->length = value_size;
        else if (m->layout_error || !finalize_length(m, s))
            goto oom;
        s->length_evidence = natural_evidence;
    }
    map_free(&ded, true);
    map_free(&om, true);
    free(flat.v);
    return true;
oom:
    map_free(&ded, true);
    map_free(&om, true);
    free(flat.v);
    return false;
}
static bool build_model(StructTable *st, Offsets *offs, int ptr, OutModel *m) {
    m->ptr = ptr;
    m->st = st;
    m->offs = offs;
    m->offset_source = offs->source;
    m->offset_schema_version = offs->schema_version;
    StrMap need = {0};
    if (!map_init(&m->by_name, st->n) || !map_init(&m->layout_by_name, st->n) ||
        !map_init(&need, 64))
        return false;
    for (size_t si = 0; si < st->n; si++) {
        StructDef *od = &st->v[si];
        size_t nl = strlen(od->name);
        if (nl < 2 || strcmp(od->name + nl - 2, "_o"))
            continue;
        char *fs = NULL;
        if (str_printf(&fs, "%.*s_Fields", (int)(nl - 2), od->name) < 0)
            goto oom;
        MemberRefs flat = flatten(st, fs);
        bool is_ref = od->n && strcmp(od->members[0].name, "klass") == 0;
        if (!flat.ok) {
            free(flat.v);
            free(fs);
            goto oom;
        }
        StrMap om = {0}, ded = {0};
        bool offsets_ok = build_offset_map(st, fs, offs, &om);
        OutStruct *s = out_struct(m, od->name, true);
        if (!offsets_ok || !s || !map_init(&ded, flat.n + 1)) {
            map_free(&om, true);
            free(flat.v);
            free(fs);
            goto oom;
        }
        uint32_t order = 0;
        if (is_ref) {
            char *stem = xstrndup(od->name, nl - 2), *class_name = NULL, *kt = NULL;
            if (!stem || str_printf(&class_name, "%s_c", stem) < 0 ||
                str_printf(&kt, "struct %s *", class_name) < 0 ||
                !out_field_push(s, xstrdup("klass"), kt, 0, order++, LAYOUT_EVIDENCE_ABI_DEFINED) ||
                !out_field_push(s, xstrdup("monitor"), xstrdup("void *"), (uint32_t)ptr, order++,
                                LAYOUT_EVIDENCE_ABI_DEFINED) ||
                (struct_find(st, class_name) && !map_put(&need, class_name, 1, false))) {
                free(class_name);
                free(stem);
                map_free(&ded, true);
                map_free(&om, true);
                free(flat.v);
                free(fs);
                goto oom;
            }
            s->length = (uint32_t)(ptr * 2);
            s->length_evidence = LAYOUT_EVIDENCE_ABI_DEFINED;
            free(class_name);
            free(stem);
        }
        uint64_t natural = is_ref ? (uint64_t)ptr * 2 : 0;
        for (size_t i = 0; i < flat.n; i++) {
            Member *mem = flat.v[i];
            char *nt = normalize_type(mem->ctype);
            if (!nt) {
                map_free(&ded, true);
                map_free(&om, true);
                free(flat.v);
                free(fs);
                goto oom;
            }
            uint32_t off;
            bool found = lookup_off(&om, mem->name, &off);
            if (found && is_ref && off < (uint32_t)(ptr * 2)) {
                record_missing(m, MISSING_OBJECT_HEADER);
                free(nt);
                continue;
            }
            if (!found && offs->source != OFFSET_SOURCE_HEADER_ONLY) {
                record_missing(m, classify_missing_offset(st, offs, fs, mem));
                free(nt);
                continue;
            }
            LayoutEvidence evidence =
                found ? LAYOUT_EVIDENCE_SIDECAR_COPIED : LAYOUT_EVIDENCE_HEADER_INFERRED;
            if (!found) {
                uint32_t a, sz;
                if (!effective_layout(m, nt, &sz, &a) || !checked_align(natural, a, &natural) ||
                    natural > I2C_MAX_OFFSET || natural > UINT64_MAX - sz) {
                    free(nt);
                    map_free(&ded, true);
                    map_free(&om, true);
                    free(flat.v);
                    free(fs);
                    goto oom;
                }
                off = (uint32_t)natural;
                natural += sz;
                if (natural > I2C_MAX_OFFSET) {
                    free(nt);
                    map_free(&ded, true);
                    map_free(&om, true);
                    free(flat.v);
                    free(fs);
                    goto oom;
                }
            }
            uintptr_t idx;
            if (map_get(&ded, mem->name, &idx)) {
                OutField *f = &s->f[idx];
                free(f->type);
                f->type = nt;
                f->off = off;
                f->evidence = (uint32_t)evidence;
            } else if (!map_put(&ded, mem->name, s->n, true) ||
                       !out_field_push(s, xstrdup(mem->name), nt, off, order++, evidence)) {
                map_free(&ded, true);
                map_free(&om, true);
                free(flat.v);
                free(fs);
                goto oom;
            }
            const char *field_type = s->f[map_get(&ded, mem->name, &idx) ? idx : s->n - 1].type;
            if (!collect_needed_type(st, &need, field_type)) {
                map_free(&ded, true);
                map_free(&om, true);
                free(flat.v);
                free(fs);
                goto oom;
            }
        }
        if (s->n > 1)
            qsort(s->f, s->n, sizeof(OutField), field_cmp);
        if (!apply_instance_size(m, s, fs)) {
            if (!finalize_length(m, s)) {
                map_free(&ded, true);
                map_free(&om, true);
                free(flat.v);
                free(fs);
                goto oom;
            }
            s->length_evidence =
                is_ref && s->n == 2 ? LAYOUT_EVIDENCE_ABI_DEFINED : LAYOUT_EVIDENCE_HEADER_INFERRED;
        }
        map_free(&ded, true);
        map_free(&om, true);
        free(flat.v);
        free(fs);
    }
    size_t cursor = 0;
    for (;;) {
        MapEnt *pending = NULL;
        for (size_t scanned = 0; scanned < need.cap; scanned++) {
            size_t index = (cursor + scanned) % need.cap;
            if (need.e[index].key && need.e[index].value == 1) {
                pending = &need.e[index];
                cursor = (index + 1) % need.cap;
                break;
            }
        }
        if (!pending)
            break;
        pending->value = 2;
        if (!emit_value(m, pending->key, &need))
            goto oom;
    }
    map_free(&need, true);
    return true;
oom:
    map_free(&need, true);
    return false;
}

static bool sidecar_layout_budget_ok(const OutModel *model) {
    uint64_t total = 0;
    for (size_t i = 0; i < model->n; i++) {
        const OutStruct *structure = &model->v[i];
        bool sidecar_influenced = structure->length_evidence == LAYOUT_EVIDENCE_SIDECAR_COPIED;
        for (size_t field = 0; field < structure->n && !sidecar_influenced; field++)
            sidecar_influenced = structure->f[field].evidence == LAYOUT_EVIDENCE_SIDECAR_COPIED;
        if (!sidecar_influenced)
            continue;
        if (structure->length > I2C_MAX_SIDECAR_OFFSET)
            return false;
        if ((uint64_t)structure->length > I2C_MAX_SIDECAR_LAYOUT_BYTES - total)
            return false;
        total += structure->length;
    }
    return true;
}

/* ---------------- binary writer ---------------- */
typedef struct {
    uint8_t *p;
    size_t n, cap;
} Buf;
static bool b_need(Buf *b, size_t x) {
    if (x > SIZE_MAX - b->n)
        return false;
    size_t need = b->n + x;
    if (need <= b->cap)
        return true;
    size_t c = b->cap ? b->cap : 4096;
    while (c < need) {
        if (c > SIZE_MAX / 2) {
            c = need;
            break;
        }
        c *= 2;
    }
    uint8_t *q = realloc(b->p, c);
    if (!q)
        return false;
    b->p = q;
    b->cap = c;
    return true;
}
static bool b_u32(Buf *b, uint32_t v) {
    if (!b_need(b, 4))
        return false;
    b->p[b->n++] = (uint8_t)v;
    b->p[b->n++] = (uint8_t)(v >> 8);
    b->p[b->n++] = (uint8_t)(v >> 16);
    b->p[b->n++] = (uint8_t)(v >> 24);
    return true;
}
static bool b_str(Buf *b, const char *s) {
    size_t n = strlen(s);
    if (n > UINT32_MAX || !b_u32(b, (uint32_t)n) || !b_need(b, n))
        return false;
    memcpy(b->p + b->n, s, n);
    b->n += n;
    return true;
}
static bool serialize(OutModel *m, Buf *b) {
    uint64_t classified = 0;
    for (size_t i = 0; i < MISSING_REASON_COUNT; i++)
        classified += m->missing_reasons[i];
    if (classified != m->missing)
        return false;
    if (m->n > UINT32_MAX || !b_u32(b, I2C_MAGIC) || !b_u32(b, I2C_VERSION) ||
        !b_u32(b, (uint32_t)m->ptr) || !b_u32(b, (uint32_t)m->n) || !b_u32(b, m->missing))
        return false;
    for (size_t i = 0; i < MISSING_REASON_COUNT; i++)
        if (!b_u32(b, m->missing_reasons[i]))
            return false;
    if (!b_u32(b, (uint32_t)m->offset_source) || !b_u32(b, m->offset_schema_version))
        return false;
    for (size_t i = 0; i < m->n; i++) {
        OutStruct *s = &m->v[i];
        if (s->n > UINT32_MAX || !b_str(b, s->name) || !b_u32(b, s->length) ||
            !b_u32(b, s->length_evidence) || !b_u32(b, (uint32_t)s->n))
            return false;
        for (size_t j = 0; j < s->n; j++) {
            OutField *f = &s->f[j];
            if (!b_u32(b, f->off) || !b_u32(b, f->evidence) || !b_str(b, f->name) ||
                !b_str(b, f->type))
                return false;
        }
    }
    return true;
}

I2CBlob i2c_parse_to_blob(const char *header, const char *offsets, int ptr) {
    I2CBlob r = {0};
    if (ptr != 4 && ptr != 8) {
        r.error = xstrdup("pointer size must be 4 or 8");
        return r;
    }
    StructTable st = {0};
    Offsets of = {0};
    OutModel m = {0};
    char *err = NULL;
    if (!parse_header(header, &st, &err)) {
        r.error = err;
        goto done;
    }
    if (!parse_offsets(offsets, &of, &err)) {
        r.error = err;
        goto done;
    }
    if (of.exact_json && of.schema_version >= 2 && !of.has_pointer_size) {
        r.error = xstrdup("type_offsets.json schema 2+ requires pointerSize");
        goto done;
    }
    if (of.has_pointer_size && of.pointer_size != (uint32_t)ptr) {
        str_printf(&r.error,
                   "type_offsets.json pointer size %u does not match target pointer size %d",
                   of.pointer_size, ptr);
        goto done;
    }
    if (!build_model(&st, &of, ptr, &m)) {
        r.error = xstrdup("model build failed");
        goto done;
    }
    if (!sidecar_layout_budget_ok(&m)) {
        r.error = xstrdup("type_offsets.json cumulative layout size exceeds limit");
        goto done;
    }
    Buf b = {0};
    if (!serialize(&m, &b)) {
        free(b.p);
        r.error = xstrdup("serialization OOM");
        goto done;
    }
    r.data = b.p;
    r.size = b.n;
done:
    model_free(&m);
    offsets_free(&of);
    structs_free(&st);
    return r;
}
void i2c_blob_free(I2CBlob *b) {
    if (!b)
        return;
    free(b->data);
    free(b->error);
    memset(b, 0, sizeof(*b));
}

#ifdef I2C_CLI
int main(int argc, char **argv) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: %s il2cpp.h [offsets.json|dump.cs|-] out.i2gf [ptrsize]\n",
                argv[0]);
        return 2;
    }
    const char *off = !strcmp(argv[2], "-") ? NULL : argv[2];
    const char *out = argc >= 4 ? argv[3] : "out.i2gf";
    int ptr = argc >= 5 ? atoi(argv[4]) : 8;
    I2CBlob b = i2c_parse_to_blob(argv[1], off, ptr);
    if (b.error) {
        fprintf(stderr, "%s\n", b.error);
        i2c_blob_free(&b);
        return 1;
    }
    FILE *f = fopen(out, "wb");
    if (!f || fwrite(b.data, 1, b.size, f) != b.size) {
        perror(out);
        if (f)
            fclose(f);
        i2c_blob_free(&b);
        return 1;
    }
    fclose(f);
    fprintf(stderr, "wrote %zu bytes\n", b.size);
    i2c_blob_free(&b);
    return 0;
}
#endif

#ifdef I2C_JNI
#include <jni.h>
JNIEXPORT jint JNICALL Java_turboheader_il2cpp_NativeParser_apiVersion0(JNIEnv *env, jclass cls);
JNIEXPORT jbyteArray JNICALL Java_turboheader_il2cpp_NativeParser_parse0(JNIEnv *env, jclass cls,
                                                                         jstring jh, jstring jo,
                                                                         jint ptr);

JNIEXPORT jint JNICALL Java_turboheader_il2cpp_NativeParser_apiVersion0(JNIEnv *env, jclass cls) {
    (void)env;
    (void)cls;
    return I2C_API_VERSION;
}

JNIEXPORT jbyteArray JNICALL Java_turboheader_il2cpp_NativeParser_parse0(JNIEnv *env, jclass cls,
                                                                         jstring jh, jstring jo,
                                                                         jint ptr) {
    (void)cls;
    if (!jh) {
        jclass ex = (*env)->FindClass(env, "java/lang/NullPointerException");
        (*env)->ThrowNew(env, ex, "header path is null");
        return NULL;
    }
    const char *h = (*env)->GetStringUTFChars(env, jh, NULL);
    if (!h)
        return NULL;
    const char *o = jo ? (*env)->GetStringUTFChars(env, jo, NULL) : NULL;
    if (jo && !o) {
        (*env)->ReleaseStringUTFChars(env, jh, h);
        return NULL;
    }
    I2CBlob b = i2c_parse_to_blob(h, o, (int)ptr);
    if (o)
        (*env)->ReleaseStringUTFChars(env, jo, o);
    (*env)->ReleaseStringUTFChars(env, jh, h);
    if (b.error) {
        jclass ex = (*env)->FindClass(env, "java/io/IOException");
        if (ex)
            (*env)->ThrowNew(env, ex, b.error);
        i2c_blob_free(&b);
        return NULL;
    }
    if (b.size > 0x7fffffffU) {
        jclass ex = (*env)->FindClass(env, "java/io/IOException");
        if (ex)
            (*env)->ThrowNew(env, ex, "parsed model exceeds Java array limit");
        i2c_blob_free(&b);
        return NULL;
    }
    jbyteArray a = (*env)->NewByteArray(env, (jsize)b.size);
    if (a)
        (*env)->SetByteArrayRegion(env, a, 0, (jsize)b.size, (const jbyte *)b.data);
    i2c_blob_free(&b);
    return a;
}
#endif
