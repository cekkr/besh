/*
 * besh_hu.c - the `.hu` sentence parser, grammar model and region recogniser.
 *
 * See besh_hu.h for what `.hu` is. This file is in four parts:
 *
 *   1. the lexer, which turns one line of a .hu script into tokens, discarding
 *      lowercase prose and matching multi-word terms longest-phrase-first;
 *   2. the sentence parser, which turns a line (plus any list items attached to
 *      it) into rules hung off fields;
 *   3. the recogniser, which walks a grammar over a region of input text and
 *      builds a tree;
 *   4. the `hu` builtin, which is the only way any of this is reachable.
 *
 * Everything is bounded. Grammars and trees are heap-allocated, one owning free
 * path each, because unreclaimed memory is a standing complaint against this
 * project and a new module should not add to it.
 */

#include "besh_hu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

/* --- limits ---------------------------------------------------------- */

#define HU_MAX_GRAMMARS   16
#define HU_MAX_FIELDS    128   /* fields in one grammar                   */
#define HU_MAX_RULES       8   /* rules on one field                      */
#define HU_MAX_CONSTS     64   /* user constants in one grammar           */
#define HU_MAX_TREES      64
#define HU_MAX_NODES    4096   /* ceiling on nodes in one tree            */
#define HU_NODES_INIT     64   /* a tree starts here and doubles          */
#define HU_MAX_DEPTH      64   /* recogniser recursion                    */
#define HU_MAX_TOKENS    128   /* tokens in one .hu sentence              */
#define HU_MAX_ITEMS      64   /* list items under one ':' header         */
#define HU_MAX_SPLITS   1024   /* pieces one region may split into        */

#define HU_NAME_LEN       64
#define HU_LIT_LEN        64
#define HU_ERR_LEN       256
#define HU_TERMINATOR_LOOKBACK 32  /* how far back ENDS WITH #const looks    */

/* ------------------------------------------------------------------ */
/* Terms                                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    HU_T_VERB,
    HU_T_COND,
    HU_T_QTY,
    HU_T_CONJ,
    HU_T_CMP
} HuTermClass;

typedef struct {
    const char* text;      /* as written in the script                   */
    const char* canonical; /* what it means                              */
    HuTermClass cls;
} HuTerm;

/* Multi-word phrases come first: the lexer scans this table in order and takes
 * the first match, so a longer phrase must be offered before its own prefix.
 * Entries marked INVENTED are not in the original design document, which
 * explicitly invites new terms; the rest are exactly as that document lists
 * them, aliases included. */
static const HuTerm g_terms[] = {
    /* multi-word */
    { "COMPOSED BY",   "HAVE",         HU_T_VERB },
    { "COMPOSED OF",   "HAVE",         HU_T_VERB },
    { "SEPARATED BY",  "SEPARATED BY", HU_T_VERB },  /* INVENTED */
    { "DELIMITED BY",  "SEPARATED BY", HU_T_VERB },  /* INVENTED */
    { "SPLIT BY",      "SEPARATED BY", HU_T_VERB },  /* INVENTED */
    { "ENDS WITH",     "ENDS WITH",    HU_T_VERB },  /* INVENTED */
    { "END WITH",      "ENDS WITH",    HU_T_VERB },  /* INVENTED */
    { "TERMINATED BY", "ENDS WITH",    HU_T_VERB },  /* INVENTED */
    { "STARTS WITH",   "STARTS WITH",  HU_T_VERB },  /* INVENTED */
    { "START WITH",    "STARTS WITH",  HU_T_VERB },  /* INVENTED */
    { "BEGINS WITH",   "STARTS WITH",  HU_T_VERB },  /* INVENTED */
    { "EXTENSION OF",  "EXTENDS",      HU_T_VERB },  /* INVENTED */
    { "WRAPPED IN",    "INSIDE",       HU_T_VERB },  /* INVENTED */
    { "ENCLOSED IN",   "INSIDE",       HU_T_VERB },  /* INVENTED */
    { "IS EQUAL TO",   "EQUALS",       HU_T_CMP  },
    { "LOOKS LIKE",    "MATCHES",      HU_T_VERB },  /* INVENTED */

    /* verbs */
    { "HAVE",      "HAVE",    HU_T_VERB },
    { "HAS",       "HAVE",    HU_T_VERB },
    { "CONTAIN",   "HAVE",    HU_T_VERB },
    { "CONTAINS",  "HAVE",    HU_T_VERB },
    { "IS",        "IS",      HU_T_VERB },
    { "ARE",       "IS",      HU_T_VERB },
    { "BE",        "IS",      HU_T_VERB },
    { "REPRESENT", "IS",      HU_T_VERB },
    { "REPRESENTS","IS",      HU_T_VERB },
    { "INSIDE",    "INSIDE",  HU_T_VERB },  /* INVENTED */
    { "BETWEEN",   "INSIDE",  HU_T_VERB },  /* INVENTED */
    { "MATCHES",   "MATCHES", HU_T_VERB },  /* INVENTED */
    { "MATCH",     "MATCHES", HU_T_VERB },  /* INVENTED */
    { "EXTENDS",   "EXTENDS", HU_T_VERB },  /* INVENTED */

    /* conditionals */
    { "CAN",   "CAN",  HU_T_COND },
    { "MUST",  "MUST", HU_T_COND },
    { "SHALL", "MUST", HU_T_COND },

    /* quantities */
    { "ALL",   "ALL",  HU_T_QTY },
    { "EVERY", "ALL",  HU_T_QTY },
    { "ONE",   "ONE",  HU_T_QTY },
    { "ZERO",  "ZERO", HU_T_QTY },
    { "NONE",  "ZERO", HU_T_QTY },

    /* conjunctions */
    { "AND",   "AND",  HU_T_CONJ },
    { "WHICH", "AND",  HU_T_CONJ },
    { "OR",    "OR",   HU_T_CONJ },
    { "IF",    "IF",   HU_T_CONJ },
    { "THEN",  "THEN", HU_T_CONJ },
    { "ELSE",  "ELSE", HU_T_CONJ },
    { "OF",    "OF",   HU_T_CONJ },

    /* comparisons */
    { "EQUALS", "EQUALS", HU_T_CMP },
    { "EQUAL",  "EQUALS", HU_T_CMP },
    { "MORE",   "MORE",   HU_T_CMP },
    { "LESS",   "LESS",   HU_T_CMP },
    { "THAN",   "THAN",   HU_T_CMP },
};
static const int g_term_count = (int)(sizeof(g_terms) / sizeof(g_terms[0]));

/* Words that are grammatical filler even when shouted. Everything lowercase is
 * filler already; these are the uppercase ones a description reaches for. */
static const char* const g_noise[] = {
    "A", "AN", "THE", "THAT", "THIS", "THOSE", "THESE", "TO", "IT", "ITS",
    "AS", "IN", "ON", "AT", "FOR", "FROM", "WITH", "BY", "ONLY", "ALSO",
    "JUST", "VERY", "SOME", "ANY", NULL
};

/* ------------------------------------------------------------------ */
/* Grammar model                                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    HU_RULE_TITLE,   /* $root IS "Name"                                  */
    HU_RULE_CHILD,   /* $x HAVE <qty> $y [SEPARATED BY 'sep']            */
    HU_RULE_ALT,     /* $x CAN BE $y [IF HAS 'lit']                      */
    HU_RULE_IS,      /* $x IS #const | 'lit'                             */
    HU_RULE_ENDS,    /* $x ENDS WITH 'lit' | #const                      */
    HU_RULE_STARTS,  /* $x STARTS WITH 'lit' | #const                    */
    HU_RULE_INSIDE,  /* $x IS INSIDE 'open', 'close'                     */
    HU_RULE_EXTENDS  /* $root EXTENDS "Base"                             */
} HuRuleKind;

typedef enum {
    HU_OPD_NONE,
    HU_OPD_FIELD,
    HU_OPD_CONST,
    HU_OPD_LITERAL,
    HU_OPD_NAME
} HuOperandKind;

typedef struct {
    HuRuleKind    kind;
    bool          must;          /* MUST rather than CAN                 */
    int           min, max;      /* max < 0 means unbounded              */
    int           order;         /* 0 unordered; n = numbered position   */
    HuOperandKind akind;
    char          a[HU_LIT_LEN];
    HuOperandKind bkind;
    char          b[HU_LIT_LEN]; /* INSIDE's closing delimiter           */
    char          sep[HU_LIT_LEN];
    char          guard[HU_LIT_LEN];
} HuRule;

typedef struct {
    char   name[HU_NAME_LEN];
    HuRule rules[HU_MAX_RULES];
    int    rule_count;
    char   action[MAX_VAR_NAME_LEN]; /* BSH function registered by `hu on` */
} HuField;

/* A constant is either one of the built-in matchers or a set of literal
 * alternatives written by the script. */
typedef struct {
    char name[HU_NAME_LEN];
    int  builtin;                /* HU_C_* ; HU_C_USER for a literal set */
    char alts[4][HU_LIT_LEN];
    int  alt_count;
} HuConst;

typedef struct {
    bool     used;
    char     name[HU_NAME_LEN];
    char     root[HU_NAME_LEN];
    HuField* fields;
    int      field_count;
    HuConst* consts;
    int      const_count;
} HuGrammar;

/* Built-in constant codes. */
enum {
    HU_C_USER = 0,
    HU_C_WORD, HU_C_IDENT, HU_C_NUMBER, HU_C_STRING, HU_C_SPACE,
    HU_C_NEWLINE, HU_C_TAB, HU_C_ANY, HU_C_END, HU_C_LETTER, HU_C_DIGIT,
    HU_C_SYMBOL, HU_C_QUOTE
};

typedef struct { const char* name; int code; } HuBuiltinConst;
static const HuBuiltinConst g_builtin_consts[] = {
    { "word",       HU_C_WORD    },
    { "identifier", HU_C_IDENT   },
    { "number",     HU_C_NUMBER  },
    { "string",     HU_C_STRING  },
    { "space",      HU_C_SPACE   },
    { "newLine",    HU_C_NEWLINE },
    { "newline",    HU_C_NEWLINE },
    { "tab",        HU_C_TAB     },
    { "any",        HU_C_ANY     },
    { "end",        HU_C_END     },
    { "letter",     HU_C_LETTER  },
    { "digit",      HU_C_DIGIT   },
    { "symbol",     HU_C_SYMBOL  },
    { "quote",      HU_C_QUOTE   },
};
static const int g_builtin_const_count =
    (int)(sizeof(g_builtin_consts) / sizeof(g_builtin_consts[0]));

/* ------------------------------------------------------------------ */
/* Trees                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char kind[HU_NAME_LEN];
    int  start, end;      /* offsets into the tree's own copy of the text */
    int  first_child;
    int  next_sibling;
    int  parent;
} HuNode;

typedef struct {
    bool     used;
    unsigned generation;  /* bumped on free, so a stale handle is caught   */
    char     grammar[HU_NAME_LEN];
    char*    text;
    int      text_len;
    HuNode*  nodes;
    int      node_count;
    int      node_cap;
} HuTree;

static HuGrammar g_grammars[HU_MAX_GRAMMARS];
static HuTree    g_trees[HU_MAX_TREES];
static bool      g_hu_ready = false;
static char      g_hu_error[HU_ERR_LEN];
static long      g_parses = 0;
static long      g_parse_failures = 0;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static void hu_copy(char* dst, size_t cap, const char* src, int len) {
    if (len < 0) len = (int)strlen(src);
    if ((size_t)len >= cap) len = (int)cap - 1;
    memcpy(dst, src, (size_t)len);
    dst[len] = '\0';
}

/* Byte-oriented, with one concession: any byte of a multi-byte UTF-8 sequence
 * counts as a word character, so an accented identifier in the described
 * language is not cut in half. Offsets and columns stay byte offsets. */
static bool hu_is_word_char(char c) {
    return isalnum((unsigned char)c) || c == '_' || (unsigned char)c >= 0x80;
}

static bool hu_all_upper(const char* s, int len) {
    bool saw_letter = false;
    for (int i = 0; i < len; ++i) {
        if (isalpha((unsigned char)s[i])) {
            if (islower((unsigned char)s[i])) return false;
            saw_letter = true;
        }
    }
    return saw_letter;
}

static bool hu_is_noise(const char* s, int len) {
    for (int i = 0; g_noise[i]; ++i) {
        if ((int)strlen(g_noise[i]) == len && strncmp(g_noise[i], s, (size_t)len) == 0) {
            return true;
        }
    }
    return false;
}

/* Skips blanks forward inside [pos,end). */
static int hu_skip_blank(const char* t, int pos, int end) {
    while (pos < end && isspace((unsigned char)t[pos])) pos++;
    return pos;
}

/* Narrows [*start,*end) to the non-blank text inside it. */
static void hu_trim(const char* t, int* start, int* end) {
    while (*start < *end && isspace((unsigned char)t[*start])) (*start)++;
    while (*end > *start && isspace((unsigned char)t[*end - 1])) (*end)--;
}

/* ------------------------------------------------------------------ */
/* The .hu lexer                                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    HU_TK_FIELD,
    HU_TK_CONST,
    HU_TK_LITERAL,  /* 'single quoted' - text in the described language   */
    HU_TK_NAME,     /* "double quoted" - a name                           */
    HU_TK_TERM,
    HU_TK_COMMA,
    HU_TK_COLON
} HuTokType;

typedef struct {
    HuTokType   type;
    char        text[HU_LIT_LEN];
    const char* canonical;  /* terms only */
    HuTermClass cls;        /* terms only */
} HuTok;

/* Removes a trailing comment. `///` starts one, and so does the document's
 * own alias for it, "You know". Quotes are respected so a literal containing
 * a slash survives. */
static void hu_strip_comment(char* line) {
    bool in_single = false, in_double = false;
    for (int i = 0; line[i]; ++i) {
        char c = line[i];
        if (c == '\'' && !in_double) { in_single = !in_single; continue; }
        if (c == '"' && !in_single) { in_double = !in_double; continue; }
        if (in_single || in_double) continue;
        if (c == '/' && line[i + 1] == '/' && line[i + 2] == '/') { line[i] = '\0'; return; }
        if ((c == 'Y' || c == 'y') && strncasecmp(line + i, "you know", 8) == 0 &&
            (i == 0 || !hu_is_word_char(line[i - 1]))) {
            line[i] = '\0';
            return;
        }
    }
}

/* Tries to read a term phrase at `pos`. Returns the number of source bytes
 * consumed, or 0. Words inside a phrase may be separated by any run of blanks. */
static int hu_match_term(const char* s, int pos, int len, const HuTerm** out) {
    for (int t = 0; t < g_term_count; ++t) {
        const char* phrase = g_terms[t].text;
        int p = pos, q = 0;
        bool ok = true;
        while (phrase[q]) {
            if (phrase[q] == ' ') {
                if (p >= len || !isspace((unsigned char)s[p])) { ok = false; break; }
                while (p < len && isspace((unsigned char)s[p])) p++;
                q++;
                continue;
            }
            if (p >= len || s[p] != phrase[q]) { ok = false; break; }
            p++; q++;
        }
        /* The phrase must end on a word boundary, or "ONE" would swallow the
         * first three letters of a longer shouted word. */
        if (ok && (p >= len || !hu_is_word_char(s[p]))) {
            *out = &g_terms[t];
            return p - pos;
        }
    }
    return 0;
}

/* Lexes one already-comment-stripped line. Returns the token count, or -1 on
 * an unterminated literal. */
static int hu_lex(const char* line, HuTok* toks, int max_toks) {
    int len = (int)strlen(line);
    int pos = 0, n = 0;

    while (pos < len && n < max_toks) {
        if (isspace((unsigned char)line[pos])) { pos++; continue; }

        if (line[pos] == ',') { toks[n].type = HU_TK_COMMA; toks[n].text[0] = '\0'; n++; pos++; continue; }
        if (line[pos] == ':') { toks[n].type = HU_TK_COLON; toks[n].text[0] = '\0'; n++; pos++; continue; }

        if (line[pos] == '$' || line[pos] == '#') {
            char sigil = line[pos];
            int start = ++pos;
            while (pos < len && hu_is_word_char(line[pos])) pos++;
            if (pos == start) continue;  /* a bare sigil is prose */
            toks[n].type = (sigil == '$') ? HU_TK_FIELD : HU_TK_CONST;
            hu_copy(toks[n].text, HU_LIT_LEN, line + start, pos - start);
            n++;
            continue;
        }

        if (line[pos] == '\'' || line[pos] == '"') {
            char quote = line[pos];
            int start = ++pos;
            while (pos < len && line[pos] != quote) {
                if (line[pos] == '\\' && pos + 1 < len) pos++;
                pos++;
            }
            if (pos >= len) return -1;  /* unterminated */
            toks[n].type = (quote == '\'') ? HU_TK_LITERAL : HU_TK_NAME;
            hu_copy(toks[n].text, HU_LIT_LEN, line + start, pos - start);
            n++;
            pos++;  /* closing quote */
            continue;
        }

        if (isalpha((unsigned char)line[pos])) {
            const HuTerm* term = NULL;
            int used = hu_match_term(line, pos, len, &term);
            if (used > 0) {
                toks[n].type = HU_TK_TERM;
                toks[n].canonical = term->canonical;
                toks[n].cls = term->cls;
                hu_copy(toks[n].text, HU_LIT_LEN, term->canonical, -1);
                n++;
                pos += used;
                continue;
            }
            /* Not a term: prose. Lowercase prose is silent by design; a shouted
             * word that is not a term and not known filler is almost always a
             * typo, and saying so beats ignoring it. */
            int start = pos;
            while (pos < len && hu_is_word_char(line[pos])) pos++;
            if (hu_all_upper(line + start, pos - start) && !hu_is_noise(line + start, pos - start)) {
                fprintf(stderr, "hu: ignoring unknown term '%.*s'\n", pos - start, line + start);
            }
            continue;
        }

        pos++;  /* punctuation that carries no meaning here */
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Grammar lookup and lifetime                                         */
/* ------------------------------------------------------------------ */

static HuGrammar* hu_grammar_find(const char* name) {
    for (int i = 0; i < HU_MAX_GRAMMARS; ++i) {
        if (g_grammars[i].used && strcmp(g_grammars[i].name, name) == 0) return &g_grammars[i];
    }
    return NULL;
}

static void hu_grammar_release(HuGrammar* g) {
    if (!g || !g->used) return;
    free(g->fields);
    free(g->consts);
    memset(g, 0, sizeof(*g));
}

static HuGrammar* hu_grammar_create(const char* name) {
    HuGrammar* g = hu_grammar_find(name);
    if (g) hu_grammar_release(g);
    if (!g) {
        for (int i = 0; i < HU_MAX_GRAMMARS; ++i) {
            if (!g_grammars[i].used) { g = &g_grammars[i]; break; }
        }
    }
    if (!g) return NULL;

    memset(g, 0, sizeof(*g));
    g->fields = (HuField*)calloc(HU_MAX_FIELDS, sizeof(HuField));
    g->consts = (HuConst*)calloc(HU_MAX_CONSTS, sizeof(HuConst));
    if (!g->fields || !g->consts) {
        free(g->fields);
        free(g->consts);
        memset(g, 0, sizeof(*g));
        return NULL;
    }
    g->used = true;
    hu_copy(g->name, HU_NAME_LEN, name, -1);
    return g;
}

static HuField* hu_field_find(HuGrammar* g, const char* name) {
    for (int i = 0; i < g->field_count; ++i) {
        if (strcmp(g->fields[i].name, name) == 0) return &g->fields[i];
    }
    return NULL;
}

static HuField* hu_field_get(HuGrammar* g, const char* name) {
    HuField* f = hu_field_find(g, name);
    if (f) return f;
    if (g->field_count >= HU_MAX_FIELDS) return NULL;
    f = &g->fields[g->field_count++];
    memset(f, 0, sizeof(*f));
    hu_copy(f->name, HU_NAME_LEN, name, -1);
    if (g->root[0] == '\0') hu_copy(g->root, HU_NAME_LEN, name, -1);
    return f;
}

static HuConst* hu_const_find(HuGrammar* g, const char* name) {
    for (int i = 0; i < g->const_count; ++i) {
        if (strcmp(g->consts[i].name, name) == 0) return &g->consts[i];
    }
    return NULL;
}

static int hu_builtin_const(const char* name) {
    for (int i = 0; i < g_builtin_const_count; ++i) {
        if (strcmp(g_builtin_consts[i].name, name) == 0) return g_builtin_consts[i].code;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Sentence parsing                                                    */
/* ------------------------------------------------------------------ */

/* One .hu statement being assembled: a header line and the list items that
 * complete it. */
typedef struct {
    char subject[HU_NAME_LEN];
    char verb[HU_LIT_LEN];
    bool must;
    int  min, max;
    bool open;            /* the header ended with ':' and awaits items    */
    bool ordered_items;   /* a numbered list was seen                      */
    char sep[HU_LIT_LEN]; /* SEPARATED BY carried from the header          */
} HuHeader;

static HuRule* hu_rule_add(HuField* f) {
    if (!f || f->rule_count >= HU_MAX_RULES) return NULL;
    HuRule* r = &f->rules[f->rule_count++];
    memset(r, 0, sizeof(*r));
    r->min = 1;
    r->max = 1;
    return r;
}

/* Applies one clause - a run of tokens with no clause-breaking comma - to the
 * grammar. `subject` is what the clause is about when it does not name its own.
 * Returns false on a clause the parser cannot make sense of. */
static bool hu_apply_clause(HuGrammar* g, const HuTok* toks, int n,
                            const char* default_subject,
                            HuHeader* header, int order,
                            char* err, size_t err_size) {
    char subject[HU_NAME_LEN];
    hu_copy(subject, HU_NAME_LEN, default_subject ? default_subject : "", -1);

    const char* verb = NULL;
    bool must = false;
    int  min = 1, max = 1;
    bool qty_seen = false;
    char guard[HU_LIT_LEN];
    guard[0] = '\0';
    HuRule* last = NULL;
    int i = 0;

    /* A clause may open with its own subject. */
    if (n > 0 && toks[0].type == HU_TK_FIELD) {
        hu_copy(subject, HU_NAME_LEN, toks[0].text, -1);
        i = 1;
    } else if (n > 0 && toks[0].type == HU_TK_CONST) {
        /* A constant definition: #name IS 'a' [OR 'b'] */
        if (g->const_count >= HU_MAX_CONSTS) {
            snprintf(err, err_size, "too many constants (max %d)", HU_MAX_CONSTS);
            return false;
        }
        HuConst* c = hu_const_find(g, toks[0].text);
        if (!c) {
            c = &g->consts[g->const_count++];
            memset(c, 0, sizeof(*c));
            hu_copy(c->name, HU_NAME_LEN, toks[0].text, -1);
        } else {
            c->alt_count = 0;
        }
        c->builtin = HU_C_USER;
        for (int k = 1; k < n; ++k) {
            if (toks[k].type == HU_TK_LITERAL && c->alt_count < 4) {
                hu_copy(c->alts[c->alt_count++], HU_LIT_LEN, toks[k].text, -1);
            } else if (toks[k].type == HU_TK_CONST) {
                int code = hu_builtin_const(toks[k].text);
                if (code > 0) c->builtin = code;
            }
        }
        return true;
    }

    if (subject[0] == '\0') return true;  /* prose with nothing to attach to */

    HuField* f = hu_field_get(g, subject);
    if (!f) {
        snprintf(err, err_size, "too many fields (max %d)", HU_MAX_FIELDS);
        return false;
    }

    for (; i < n; ++i) {
        const HuTok* t = &toks[i];

        if (t->type == HU_TK_TERM) {
            if (t->cls == HU_T_COND) {
                must = (strcmp(t->canonical, "MUST") == 0);
                continue;
            }
            if (t->cls == HU_T_QTY) {
                qty_seen = true;
                if (strcmp(t->canonical, "ONE") == 0)      { min = 1; max = 1; }
                else if (strcmp(t->canonical, "ZERO") == 0) { min = 0; max = 0; }
                else                                        { min = 0; max = -1; } /* ALL */
                continue;
            }
            if (t->cls == HU_T_CMP) {
                /* "... OR MORE" opens the quantity upward. */
                if (strcmp(t->canonical, "MORE") == 0 && qty_seen) max = -1;
                continue;
            }
            if (t->cls == HU_T_CONJ) {
                /* IF HAS 'lit' - a guard on the rule just emitted. */
                if (strcmp(t->canonical, "IF") == 0) {
                    for (int k = i + 1; k < n; ++k) {
                        if (toks[k].type == HU_TK_LITERAL) {
                            hu_copy(guard, HU_LIT_LEN, toks[k].text, -1);
                            if (last) hu_copy(last->guard, HU_LIT_LEN, toks[k].text, -1);
                            i = k;
                            break;
                        }
                    }
                }
                continue;
            }
            verb = t->canonical;
            continue;
        }

        /* An operand. What it means depends on the verb in force. */
        if (!verb) continue;

        if (strcmp(verb, "HAVE") == 0 && t->type == HU_TK_FIELD) {
            if (!hu_field_get(g, t->text)) {
                snprintf(err, err_size, "too many fields (max %d)", HU_MAX_FIELDS);
                return false;
            }
            f = hu_field_find(g, subject);
            last = hu_rule_add(f);
            if (!last) { snprintf(err, err_size, "field $%s has too many rules (max %d)", subject, HU_MAX_RULES); return false; }
            last->kind = HU_RULE_CHILD;
            last->must = must;
            last->min = min;
            last->max = max;
            last->order = order;
            last->akind = HU_OPD_FIELD;
            hu_copy(last->a, HU_LIT_LEN, t->text, -1);
            if (guard[0]) hu_copy(last->guard, HU_LIT_LEN, guard, -1);
            continue;
        }

        if (strcmp(verb, "IS") == 0) {
            if (t->type == HU_TK_NAME) {
                last = hu_rule_add(f);
                if (!last) { snprintf(err, err_size, "field $%s has too many rules", subject); return false; }
                last->kind = HU_RULE_TITLE;
                last->akind = HU_OPD_NAME;
                hu_copy(last->a, HU_LIT_LEN, t->text, -1);
                hu_copy(g->name, HU_NAME_LEN, t->text, -1);
                hu_copy(g->root, HU_NAME_LEN, subject, -1);
                continue;
            }
            if (t->type == HU_TK_FIELD) {
                /* "CAN BE $y" - an alternative. */
                if (!hu_field_get(g, t->text)) {
                    snprintf(err, err_size, "too many fields (max %d)", HU_MAX_FIELDS);
                    return false;
                }
                f = hu_field_find(g, subject);
                last = hu_rule_add(f);
                if (!last) { snprintf(err, err_size, "field $%s has too many rules", subject); return false; }
                last->kind = HU_RULE_ALT;
                last->must = must;
                last->order = order;
                last->akind = HU_OPD_FIELD;
                hu_copy(last->a, HU_LIT_LEN, t->text, -1);
                if (guard[0]) hu_copy(last->guard, HU_LIT_LEN, guard, -1);
                continue;
            }
            /* IS #const or IS 'lit' */
            last = hu_rule_add(f);
            if (!last) { snprintf(err, err_size, "field $%s has too many rules", subject); return false; }
            last->kind = HU_RULE_IS;
            last->must = must;
            last->akind = (t->type == HU_TK_CONST) ? HU_OPD_CONST : HU_OPD_LITERAL;
            hu_copy(last->a, HU_LIT_LEN, t->text, -1);
            continue;
        }

        if (strcmp(verb, "MATCHES") == 0) {
            last = hu_rule_add(f);
            if (!last) { snprintf(err, err_size, "field $%s has too many rules", subject); return false; }
            last->kind = HU_RULE_IS;
            last->akind = (t->type == HU_TK_CONST) ? HU_OPD_CONST : HU_OPD_LITERAL;
            hu_copy(last->a, HU_LIT_LEN, t->text, -1);
            continue;
        }

        if (strcmp(verb, "ENDS WITH") == 0 || strcmp(verb, "STARTS WITH") == 0) {
            last = hu_rule_add(f);
            if (!last) { snprintf(err, err_size, "field $%s has too many rules", subject); return false; }
            last->kind = (strcmp(verb, "ENDS WITH") == 0) ? HU_RULE_ENDS : HU_RULE_STARTS;
            last->akind = (t->type == HU_TK_CONST) ? HU_OPD_CONST : HU_OPD_LITERAL;
            hu_copy(last->a, HU_LIT_LEN, t->text, -1);
            continue;
        }

        if (strcmp(verb, "INSIDE") == 0) {
            last = hu_rule_add(f);
            if (!last) { snprintf(err, err_size, "field $%s has too many rules", subject); return false; }
            last->kind = HU_RULE_INSIDE;
            last->akind = HU_OPD_LITERAL;
            hu_copy(last->a, HU_LIT_LEN, t->text, -1);
            /* INSIDE takes two delimiters; the comma between them belongs to
             * the operand list, not to the clause. */
            int k = i + 1;
            if (k < n && toks[k].type == HU_TK_COMMA) k++;
            if (k < n && toks[k].type == HU_TK_LITERAL) {
                last->bkind = HU_OPD_LITERAL;
                hu_copy(last->b, HU_LIT_LEN, toks[k].text, -1);
                i = k;
            } else {
                last->bkind = HU_OPD_LITERAL;
                hu_copy(last->b, HU_LIT_LEN, last->a, -1);
            }
            continue;
        }

        if (strcmp(verb, "SEPARATED BY") == 0 && t->type != HU_TK_FIELD) {
            char text[HU_LIT_LEN];
            hu_copy(text, HU_LIT_LEN, t->text, -1);
            if (t->type == HU_TK_CONST) {
                int code = hu_builtin_const(text);
                if (code == HU_C_SPACE)        hu_copy(text, HU_LIT_LEN, " ", -1);
                else if (code == HU_C_NEWLINE) hu_copy(text, HU_LIT_LEN, "\n", -1);
                else if (code == HU_C_TAB)     hu_copy(text, HU_LIT_LEN, "\t", -1);
            }
            if (last && last->kind == HU_RULE_CHILD) {
                hu_copy(last->sep, HU_LIT_LEN, text, -1);
            } else if (header) {
                hu_copy(header->sep, HU_LIT_LEN, text, -1);
            }
            continue;
        }

        if (strcmp(verb, "EXTENDS") == 0 && t->type == HU_TK_NAME) {
            last = hu_rule_add(f);
            if (!last) { snprintf(err, err_size, "field $%s has too many rules", subject); return false; }
            last->kind = HU_RULE_EXTENDS;
            last->akind = HU_OPD_NAME;
            hu_copy(last->a, HU_LIT_LEN, t->text, -1);
            continue;
        }
    }

    /* A clause that named a subject and a verb but no object is a header
     * awaiting its list items. */
    if (header && verb && !last) {
        hu_copy(header->subject, HU_NAME_LEN, subject, -1);
        hu_copy(header->verb, HU_LIT_LEN, verb, -1);
        header->must = must;
        header->min = min;
        header->max = max;
        header->open = true;
    }
    return true;
}

/* Splits a token run into clauses at commas that are genuine clause breaks. A
 * comma sitting between INSIDE's two delimiters is not one. */
static bool hu_apply_sentence(HuGrammar* g, const HuTok* toks, int n,
                              const char* default_subject,
                              HuHeader* header, int order,
                              char* err, size_t err_size) {
    int start = 0;
    bool after_inside = false;

    for (int i = 0; i <= n; ++i) {
        bool is_break = (i == n);
        if (!is_break && toks[i].type == HU_TK_COMMA) {
            /* An operand comma: INSIDE 'a', 'b'. */
            if (after_inside && i + 1 < n && toks[i + 1].type == HU_TK_LITERAL) continue;
            is_break = true;
        }
        if (!is_break) {
            if (toks[i].type == HU_TK_TERM && strcmp(toks[i].canonical, "INSIDE") == 0) {
                after_inside = true;
            } else if (toks[i].type == HU_TK_FIELD || toks[i].type == HU_TK_CONST) {
                after_inside = false;
            }
            continue;
        }
        if (i > start) {
            if (!hu_apply_clause(g, toks + start, i - start, default_subject, header, order, err, err_size)) {
                return false;
            }
        }
        start = i + 1;
        after_inside = false;
        /* Only the first clause of an item may open a header. */
        header = NULL;
    }
    return true;
}

/* Reads a list marker. Returns 1 for a numbered item (with *number set), 2 for
 * a bulleted item, 0 for an ordinary line. `*offset` moves past the marker. */
static int hu_list_marker(const char* line, int* offset, int* number) {
    int i = 0;
    while (line[i] == ' ' || line[i] == '\t') i++;
    if (isdigit((unsigned char)line[i])) {
        int start = i;
        while (isdigit((unsigned char)line[i])) i++;
        if (line[i] == '.' || line[i] == ')') {
            *number = atoi(line + start);
            i++;
            while (line[i] == ' ' || line[i] == '\t') i++;
            *offset = i;
            return 1;
        }
        return 0;
    }
    if (line[i] == '-' || line[i] == '*') {
        i++;
        while (line[i] == ' ' || line[i] == '\t') i++;
        *offset = i;
        return 2;
    }
    return 0;
}

/* Parses a whole .hu source into `g`. */
static bool hu_parse_source(HuGrammar* g, const char* source, char* err, size_t err_size) {
    char line[MAX_LINE_LENGTH];
    HuHeader header;
    memset(&header, 0, sizeof(header));

    const char* p = source;
    int line_no = 0;

    while (*p) {
        const char* nl = strchr(p, '\n');
        int len = nl ? (int)(nl - p) : (int)strlen(p);
        if (len >= MAX_LINE_LENGTH) len = MAX_LINE_LENGTH - 1;
        memcpy(line, p, (size_t)len);
        line[len] = '\0';
        p = nl ? nl + 1 : p + strlen(p);
        line_no++;

        hu_strip_comment(line);

        int offset = 0, number = 0;
        int marker = hu_list_marker(line, &offset, &number);
        const char* body = line + (marker ? offset : 0);

        HuTok toks[HU_MAX_TOKENS];
        int n = hu_lex(body, toks, HU_MAX_TOKENS);
        if (n < 0) {
            snprintf(err, err_size, "line %d: unterminated quoted text", line_no);
            return false;
        }
        if (n == 0) {
            if (marker == 0) memset(&header, 0, sizeof(header));  /* a blank line closes a list */
            continue;
        }

        bool ends_open = (toks[n - 1].type == HU_TK_COLON);
        if (ends_open) n--;

        if (marker != 0 && header.open) {
            /* A list item completes the header sentence. The item's own
             * subject is the header's missing object; anything after the first
             * comma describes that subject, not the header's. */
            int item_order = (marker == 1) ? (number > 0 ? number : 1) : 0;
            if (marker == 1) header.ordered_items = true;

            /* First, the completion: <header subject> <header verb> <item subject>. */
            const char* item_subject = NULL;
            for (int i = 0; i < n; ++i) {
                if (toks[i].type == HU_TK_FIELD) { item_subject = toks[i].text; break; }
            }
            if (item_subject) {
                HuTok synth[4];
                int sn = 0;
                memset(synth, 0, sizeof(synth));
                synth[sn].type = HU_TK_FIELD;
                hu_copy(synth[sn].text, HU_LIT_LEN, header.subject, -1);
                sn++;
                synth[sn].type = HU_TK_TERM;
                synth[sn].canonical = header.verb;
                synth[sn].cls = HU_T_VERB;
                hu_copy(synth[sn].text, HU_LIT_LEN, header.verb, -1);
                sn++;
                synth[sn].type = HU_TK_FIELD;
                hu_copy(synth[sn].text, HU_LIT_LEN, item_subject, -1);
                sn++;

                char item_subject_copy[HU_NAME_LEN];
                hu_copy(item_subject_copy, HU_NAME_LEN, item_subject, -1);

                if (!hu_apply_clause(g, synth, sn, header.subject, NULL, item_order, err, err_size)) {
                    return false;
                }
                /* Carry the header's quantity and separator onto the rule just
                 * made, and let the item's own trailing clauses describe it. */
                HuField* hf = hu_field_find(g, header.subject);
                if (hf && hf->rule_count > 0) {
                    HuRule* r = &hf->rules[hf->rule_count - 1];
                    if (r->kind == HU_RULE_CHILD) {
                        r->min = header.min;
                        r->max = header.max;
                        if (header.sep[0] && r->sep[0] == '\0') {
                            hu_copy(r->sep, HU_LIT_LEN, header.sep, -1);
                        }
                    }
                    r->must = header.must;
                }
                if (!hu_apply_sentence(g, toks, n, item_subject_copy, NULL, 0, err, err_size)) {
                    return false;
                }
            }
            continue;
        }

        /* An ordinary sentence. */
        memset(&header, 0, sizeof(header));
        HuHeader* h = ends_open ? &header : NULL;
        if (!hu_apply_sentence(g, toks, n, NULL, h, 0, err, err_size)) return false;
        if (!ends_open) memset(&header, 0, sizeof(header));
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Constant matching                                                   */
/* ------------------------------------------------------------------ */

/* Matches `name` at `pos` inside [pos,end). Returns the offset just past the
 * match, or -1. */
static int hu_const_match(HuGrammar* g, const char* name, const char* t, int pos, int end) {
    int code = hu_builtin_const(name);
    HuConst* user = hu_const_find(g, name);
    if (user) {
        if (user->alt_count > 0) {
            int best = -1;
            for (int i = 0; i < user->alt_count; ++i) {
                int l = (int)strlen(user->alts[i]);
                if (l > 0 && pos + l <= end && strncmp(t + pos, user->alts[i], (size_t)l) == 0) {
                    if (pos + l > best) best = pos + l;
                }
            }
            if (best >= 0) return best;
            if (user->builtin == HU_C_USER) return -1;
        }
        if (user->builtin != HU_C_USER) code = user->builtin;
    }
    if (code < 0) return -1;

    int i = pos;
    switch (code) {
        case HU_C_WORD:
            while (i < end && hu_is_word_char(t[i])) i++;
            return (i > pos) ? i : -1;
        case HU_C_IDENT:
            if (i < end && (isalpha((unsigned char)t[i]) || t[i] == '_')) {
                i++;
                while (i < end && hu_is_word_char(t[i])) i++;
                return i;
            }
            return -1;
        case HU_C_NUMBER:
            if (i < end && (t[i] == '-' || t[i] == '+')) i++;
            while (i < end && isdigit((unsigned char)t[i])) i++;
            if (i < end && t[i] == '.') {
                i++;
                while (i < end && isdigit((unsigned char)t[i])) i++;
            }
            return (i > pos && isdigit((unsigned char)t[i - 1])) ? i : -1;
        case HU_C_STRING:
            if (i < end && (t[i] == '\'' || t[i] == '"')) {
                char q = t[i++];
                while (i < end && t[i] != q) {
                    if (t[i] == '\\' && i + 1 < end) i++;
                    i++;
                }
                return (i < end) ? i + 1 : -1;
            }
            return -1;
        case HU_C_SPACE:
            while (i < end && (t[i] == ' ' || t[i] == '\t')) i++;
            return (i > pos) ? i : -1;
        case HU_C_NEWLINE:
            if (i < end && t[i] == '\r') i++;
            if (i < end && t[i] == '\n') return i + 1;
            return -1;
        case HU_C_TAB:
            return (i < end && t[i] == '\t') ? i + 1 : -1;
        case HU_C_ANY:
            return end;
        case HU_C_END:
            return (i == end) ? i : -1;
        case HU_C_LETTER:
            return (i < end && isalpha((unsigned char)t[i])) ? i + 1 : -1;
        case HU_C_DIGIT:
            return (i < end && isdigit((unsigned char)t[i])) ? i + 1 : -1;
        case HU_C_QUOTE:
            return (i < end && (t[i] == '\'' || t[i] == '"')) ? i + 1 : -1;
        case HU_C_SYMBOL:
            return (i < end && ispunct((unsigned char)t[i])) ? i + 1 : -1;
        default:
            return -1;
    }
}

/* ------------------------------------------------------------------ */
/* Region utilities                                                    */
/* ------------------------------------------------------------------ */

/* True when `pos` is not inside a quoted run or a bracketed group. The caller
 * walks the region itself; these two helpers keep quote and nesting state. */
typedef struct { char quote; int depth; } HuScan;

static void hu_scan_step(HuScan* s, char c) {
    if (s->quote) {
        if (c == s->quote) s->quote = 0;
        return;
    }
    if (c == '\'' || c == '"') { s->quote = c; return; }
    if (c == '(' || c == '[' || c == '{') s->depth++;
    else if (c == ')' || c == ']' || c == '}') { if (s->depth > 0) s->depth--; }
}

static bool hu_scan_top(const HuScan* s) { return s->quote == 0 && s->depth == 0; }

/* Matches `lit` at `pos`. A literal whose own edge is a word character is only
 * accepted on a word boundary: without this, a guard of 'if' fires inside
 * "notify" and a separator of 'in' splits "int", quietly and forever. */
static bool hu_literal_at(const char* t, int pos, int end, const char* lit) {
    int l = (int)strlen(lit);
    if (l == 0 || pos < 0 || pos + l > end) return false;
    if (strncmp(t + pos, lit, (size_t)l) != 0) return false;
    if (hu_is_word_char(lit[0]) && pos > 0 && hu_is_word_char(t[pos - 1])) return false;
    if (hu_is_word_char(lit[l - 1]) && pos + l < end && hu_is_word_char(t[pos + l])) return false;
    return true;
}

/* Finds the first top-level occurrence of `lit` in [from,to), skipping quoted
 * runs and bracketed groups. Returns its offset, or -1. */
static int hu_find_top(const char* t, int from, int to, const char* lit) {
    HuScan s = { 0, 0 };
    for (int i = from; i < to; ++i) {
        if (hu_scan_top(&s) && hu_literal_at(t, i, to, lit)) return i;
        hu_scan_step(&s, t[i]);
    }
    return -1;
}

/* Finds `close` matching the `open` that starts at `pos`, honouring nesting of
 * that same pair and skipping quoted runs. Returns the offset of `close`, or -1. */
static int hu_find_close(const char* t, int pos, int end, const char* open, const char* close) {
    int ol = (int)strlen(open), cl = (int)strlen(close);
    if (ol == 0 || cl == 0) return -1;
    int depth = 0;
    char quote = 0;
    for (int i = pos; i < end; ++i) {
        char c = t[i];
        if (quote) {
            if (c == '\\') { i++; continue; }
            if (c == quote) quote = 0;
            continue;
        }
        if (c == '\'' || c == '"') { quote = c; continue; }
        if (i + cl <= end && strncmp(t + i, close, (size_t)cl) == 0) {
            depth--;
            if (depth == 0) return i;
            continue;
        }
        if (i + ol <= end && strncmp(t + i, open, (size_t)ol) == 0) {
            depth++;
            continue;
        }
    }
    return -1;
}

/* Splits [start,end) at top-level occurrences of `sep`. */
static int hu_split(const char* t, int start, int end, const char* sep,
                    int* out_start, int* out_end, int max) {
    int sl = (int)strlen(sep);
    if (sl == 0) return 0;
    HuScan s = { 0, 0 };
    int piece = start, n = 0;
    for (int i = start; i < end; ++i) {
        if (hu_scan_top(&s) && hu_literal_at(t, i, end, sep)) {
            if (n >= max) return n;
            out_start[n] = piece;
            out_end[n] = i;
            n++;
            i += sl - 1;
            piece = i + 1;
            continue;
        }
        hu_scan_step(&s, t[i]);
    }
    if (n < max) {
        out_start[n] = piece;
        out_end[n] = end;
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* The recogniser                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    HuGrammar* g;
    HuTree*    tree;
    const char* t;
    int        depth;
    int        fail_pos;
    char       fail_msg[HU_ERR_LEN];
} HuCtx;

/* One field's rules, sorted into the shapes the recogniser asks about. */
typedef struct {
    HuRule* inside;
    HuRule* ends;
    HuRule* starts;
    HuRule* is_rule;
    HuRule* ordered[HU_MAX_RULES];
    int     ordered_count;
    HuRule* children[HU_MAX_RULES];
    int     child_count;
    HuRule* alts[HU_MAX_RULES];
    int     alt_count;
} HuPlan;

static void hu_plan(HuField* f, HuPlan* p) {
    memset(p, 0, sizeof(*p));
    if (!f) return;
    for (int i = 0; i < f->rule_count; ++i) {
        HuRule* r = &f->rules[i];
        switch (r->kind) {
            case HU_RULE_INSIDE: if (!p->inside) p->inside = r; break;
            case HU_RULE_ENDS:   if (!p->ends) p->ends = r; break;
            case HU_RULE_STARTS: if (!p->starts) p->starts = r; break;
            case HU_RULE_IS:     if (!p->is_rule) p->is_rule = r; break;
            case HU_RULE_ALT:
                if (p->alt_count < HU_MAX_RULES) p->alts[p->alt_count++] = r;
                break;
            case HU_RULE_CHILD:
                if (r->order > 0) {
                    if (p->ordered_count < HU_MAX_RULES) p->ordered[p->ordered_count++] = r;
                } else {
                    if (p->child_count < HU_MAX_RULES) p->children[p->child_count++] = r;
                }
                break;
            default: break;
        }
    }
    /* Numbered items must be matched in the order they were written. */
    for (int i = 1; i < p->ordered_count; ++i) {
        HuRule* key = p->ordered[i];
        int j = i - 1;
        while (j >= 0 && p->ordered[j]->order > key->order) {
            p->ordered[j + 1] = p->ordered[j];
            j--;
        }
        p->ordered[j + 1] = key;
    }
}

static void hu_fail(HuCtx* ctx, int pos, const char* field, const char* what) {
    if (pos < ctx->fail_pos) return;  /* keep the deepest expectation */
    ctx->fail_pos = pos;
    snprintf(ctx->fail_msg, sizeof(ctx->fail_msg), "field $%s expected %s", field, what);
}

static int hu_node_new(HuCtx* ctx, const char* kind, int start, int end, int parent) {
    HuTree* tr = ctx->tree;
    /* Grow on demand: most parses want a handful of nodes, and reserving the
     * ceiling for each one would cost far more than any tree ever uses. Nodes
     * are addressed by index, never by held pointer, so moving them is safe -
     * both pointers below are taken after this point. */
    if (tr->node_count >= tr->node_cap) {
        if (tr->node_cap >= HU_MAX_NODES) return -1;
        int cap = tr->node_cap ? tr->node_cap * 2 : HU_NODES_INIT;
        if (cap > HU_MAX_NODES) cap = HU_MAX_NODES;
        HuNode* grown = (HuNode*)realloc(tr->nodes, (size_t)cap * sizeof(HuNode));
        if (!grown) return -1;
        memset(grown + tr->node_cap, 0, (size_t)(cap - tr->node_cap) * sizeof(HuNode));
        tr->nodes = grown;
        tr->node_cap = cap;
    }
    int idx = tr->node_count++;
    HuNode* n = &tr->nodes[idx];
    memset(n, 0, sizeof(*n));
    hu_copy(n->kind, HU_NAME_LEN, kind, -1);
    n->start = start;
    n->end = end;
    n->first_child = -1;
    n->next_sibling = -1;
    n->parent = parent;
    if (parent >= 0) {
        HuNode* p = &tr->nodes[parent];
        if (p->first_child < 0) {
            p->first_child = idx;
        } else {
            int c = p->first_child;
            while (tr->nodes[c].next_sibling >= 0) c = tr->nodes[c].next_sibling;
            tr->nodes[c].next_sibling = idx;
        }
    }
    return idx;
}

/* Drops every node added after `mark`, so a failed attempt leaves no trace. */
static void hu_node_rollback(HuCtx* ctx, int mark, int parent) {
    HuTree* tr = ctx->tree;
    if (mark >= tr->node_count) return;
    tr->node_count = mark;
    if (parent >= 0) {
        HuNode* p = &tr->nodes[parent];
        if (p->first_child >= mark) {
            p->first_child = -1;
        } else if (p->first_child >= 0) {
            int c = p->first_child;
            while (tr->nodes[c].next_sibling >= 0) {
                if (tr->nodes[c].next_sibling >= mark) { tr->nodes[c].next_sibling = -1; break; }
                c = tr->nodes[c].next_sibling;
            }
        }
    }
}

static int hu_match(HuCtx* ctx, HuField* f, int start, int end, int parent);

/* Works out where one ordered child ends inside [start,end). Returns the end
 * offset, or -1 when the grammar does not say. */
static int hu_child_extent(HuCtx* ctx, HuField* child, int start, int end, bool last) {
    HuPlan p;
    hu_plan(child, &p);
    int pos = hu_skip_blank(ctx->t, start, end);

    if (p.inside) {
        int ol = (int)strlen(p.inside->a);
        int at = hu_find_top(ctx->t, pos, end, p.inside->a);
        if (at < 0) return -1;
        (void)ol;
        int close = hu_find_close(ctx->t, at, end, p.inside->a, p.inside->b);
        if (close < 0) return -1;
        return close + (int)strlen(p.inside->b);
    }
    if (p.ends) {
        int ts, te;
        if (p.ends->akind == HU_OPD_CONST) {
            for (int i = pos; i <= end; ++i) {
                int m = hu_const_match(ctx->g, p.ends->a, ctx->t, i, end);
                if (m > i) return m;
            }
            return last ? end : -1;
        }
        te = (int)strlen(p.ends->a);
        ts = hu_find_top(ctx->t, pos, end, p.ends->a);
        if (ts >= 0) return ts + te;
        return last ? end : -1;
    }
    if (p.is_rule) {
        if (p.is_rule->akind == HU_OPD_CONST) {
            int m = hu_const_match(ctx->g, p.is_rule->a, ctx->t, pos, end);
            return m;
        }
        if (hu_literal_at(ctx->t, pos, end, p.is_rule->a)) return pos + (int)strlen(p.is_rule->a);
        return -1;
    }
    return last ? end : -1;
}

/* Matches `f` over [start,end), attaching a node under `parent`. Returns the
 * node index, or -1. */
static int hu_match_inner(HuCtx* ctx, HuField* f, int start, int end, int parent) {
    HuPlan p;
    hu_plan(f, &p);
    hu_trim(ctx->t, &start, &end);

    /* STARTS WITH trims an opener off the front. */
    if (p.starts) {
        int pos = hu_skip_blank(ctx->t, start, end);
        if (p.starts->akind == HU_OPD_CONST) {
            int m = hu_const_match(ctx->g, p.starts->a, ctx->t, pos, end);
            if (m < 0) { hu_fail(ctx, pos, f->name, p.starts->a); return -1; }
            start = m;
        } else {
            if (!hu_literal_at(ctx->t, pos, end, p.starts->a)) {
                hu_fail(ctx, pos, f->name, p.starts->a);
                return -1;
            }
            start = pos + (int)strlen(p.starts->a);
        }
        hu_trim(ctx->t, &start, &end);
    }

    /* ENDS WITH trims its terminator off the back of this single instance -
     * whether the terminator was written as a literal or as a constant. The two
     * spellings have to behave the same, or `ENDS WITH #assign` would keep the
     * '=' that `ENDS WITH '='` drops. */
    if (p.ends) {
        if (p.ends->akind == HU_OPD_LITERAL) {
            int l = (int)strlen(p.ends->a);
            if (end - l >= start && hu_literal_at(ctx->t, end - l, end, p.ends->a)) {
                end -= l;
                hu_trim(ctx->t, &start, &end);
            }
        } else {
            /* The shortest trailing run that is the constant, so only the
             * terminator is removed. A terminator is punctuation or whitespace
             * in practice, so a short lookback is enough. */
            int floor_pos = end - HU_TERMINATOR_LOOKBACK;
            if (floor_pos < start) floor_pos = start;
            for (int k = end - 1; k >= floor_pos; --k) {
                if (hu_const_match(ctx->g, p.ends->a, ctx->t, k, end) == end) {
                    end = k;
                    hu_trim(ctx->t, &start, &end);
                    break;
                }
            }
        }
    }

    /* INSIDE carves out the delimited interior; the node owns the interior. */
    if (p.inside) {
        int pos = hu_skip_blank(ctx->t, start, end);
        int ol = (int)strlen(p.inside->a);
        if (!hu_literal_at(ctx->t, pos, end, p.inside->a)) {
            hu_fail(ctx, pos, f->name, p.inside->a);
            return -1;
        }
        int close = hu_find_close(ctx->t, pos, end, p.inside->a, p.inside->b);
        if (close < 0) {
            char what[HU_LIT_LEN * 2 + 24];
            snprintf(what, sizeof(what), "'%s' to close '%s'", p.inside->b, p.inside->a);
            hu_fail(ctx, end, f->name, what);
            return -1;
        }
        start = pos + ol;
        end = close;
        hu_trim(ctx->t, &start, &end);
    }

    int node = hu_node_new(ctx, f->name, start, end, parent);
    if (node < 0) { hu_fail(ctx, start, f->name, "fewer nodes (tree budget exhausted)"); return -1; }

    /* Alternatives: the first whose guard admits it and which matches wins. */
    if (p.alt_count > 0) {
        for (int i = 0; i < p.alt_count; ++i) {
            HuRule* r = p.alts[i];
            /* The guard prunes; it does not decide. A guard that fires still
             * has to match, and one that does not fire only skips a try. */
            if (r->guard[0] && hu_find_top(ctx->t, start, end, r->guard) < 0) continue;
            HuField* alt = hu_field_find(ctx->g, r->a);
            if (!alt) continue;
            int mark = ctx->tree->node_count;
            if (hu_match(ctx, alt, start, end, node) >= 0) return node;
            hu_node_rollback(ctx, mark, node);
        }
        hu_fail(ctx, start, f->name, "one of its alternatives to match");
        return -1;
    }

    /* Numbered children, in sequence. */
    if (p.ordered_count > 0) {
        int pos = start;
        for (int i = 0; i < p.ordered_count; ++i) {
            HuRule* r = p.ordered[i];
            HuField* child = hu_field_find(ctx->g, r->a);
            if (!child) continue;
            pos = hu_skip_blank(ctx->t, pos, end);
            bool last = (i == p.ordered_count - 1);
            int extent = hu_child_extent(ctx, child, pos, end, last);
            if (extent < 0) {
                if (r->must || r->min > 0) {
                    char what[HU_NAME_LEN + 8];
                    snprintf(what, sizeof(what), "$%s", child->name);
                    hu_fail(ctx, pos, f->name, what);
                    return -1;
                }
                continue;
            }
            if (r->sep[0] || r->max < 0 || r->max > 1) {
                /* A numbered slot that itself repeats. */
                int ss[HU_MAX_SPLITS], se[HU_MAX_SPLITS];
                int count = hu_split(ctx->t, pos, extent, r->sep[0] ? r->sep : ",", ss, se, HU_MAX_SPLITS);
                for (int k = 0; k < count; ++k) {
                    int a = ss[k], b = se[k];
                    hu_trim(ctx->t, &a, &b);
                    if (a >= b) continue;
                    if (hu_match(ctx, child, a, b, node) < 0) return -1;
                }
            } else if (hu_match(ctx, child, pos, extent, node) < 0) {
                return -1;
            }
            pos = extent;
        }
        /* Quietly dropping input would make every tree untrustworthy, so a
         * sequence that does not reach the end of its region fails instead. */
        pos = hu_skip_blank(ctx->t, pos, end);
        if (pos < end) {
            hu_fail(ctx, pos, f->name, "no further input after its last part");
            return -1;
        }
        return node;
    }

    /* Unordered children. */
    if (p.child_count > 0) {
        for (int i = 0; i < p.child_count; ++i) {
            HuRule* r = p.children[i];
            HuField* child = hu_field_find(ctx->g, r->a);
            if (!child) continue;

            bool repeats = (r->max < 0 || r->max > 1);
            if (!repeats) {
                if (hu_match(ctx, child, start, end, node) < 0 && (r->must || r->min > 0)) return -1;
                continue;
            }

            HuPlan cp;
            hu_plan(child, &cp);
            int ss[HU_MAX_SPLITS], se[HU_MAX_SPLITS];
            int count = 0;

            if (r->sep[0]) {
                count = hu_split(ctx->t, start, end, r->sep, ss, se, HU_MAX_SPLITS);
            } else if (cp.ends) {
                /* No separator, but each instance says how it ends. */
                int pos = start;
                while (pos < end && count < HU_MAX_SPLITS) {
                    int stop = -1;
                    if (cp.ends->akind == HU_OPD_CONST) {
                        HuScan sc = { 0, 0 };
                        for (int k = pos; k <= end; ++k) {
                            if (hu_scan_top(&sc)) {
                                int m = hu_const_match(ctx->g, cp.ends->a, ctx->t, k, end);
                                if (m > k) { stop = m; break; }
                            }
                            if (k < end) hu_scan_step(&sc, ctx->t[k]);
                        }
                    } else {
                        int at = hu_find_top(ctx->t, pos, end, cp.ends->a);
                        if (at >= 0) stop = at + (int)strlen(cp.ends->a);
                    }
                    /* Running out of terminators is not a failure: the end of
                     * the region terminates the last instance. */
                    if (stop < 0) { ss[count] = pos; se[count] = end; count++; break; }
                    ss[count] = pos;
                    se[count] = stop;
                    count++;
                    if (stop <= pos) break;  /* a zero-width match must not loop */
                    pos = stop;
                }
            } else {
                ss[0] = start; se[0] = end; count = 1;
            }

            int matched = 0;
            for (int k = 0; k < count; ++k) {
                int a = ss[k], b = se[k];
                hu_trim(ctx->t, &a, &b);
                if (a >= b) continue;
                if (hu_match(ctx, child, a, b, node) < 0) return -1;
                matched++;
            }
            if (matched < r->min) {
                char what[HU_NAME_LEN + 24];
                snprintf(what, sizeof(what), "at least one $%s", child->name);
                hu_fail(ctx, start, f->name, what);
                return -1;
            }
        }
        return node;
    }

    /* A leaf. If the field says what it is, hold it to that. */
    if (p.is_rule) {
        if (p.is_rule->akind == HU_OPD_CONST) {
            int m = hu_const_match(ctx->g, p.is_rule->a, ctx->t, start, end);
            /* The whole region has to be the constant. Accepting a prefix would
             * drop the rest of the text without saying so, and a leaf is the
             * one place where that would never be noticed. */
            if (m < 0 || m != end) {
                char what[HU_NAME_LEN + 8];
                snprintf(what, sizeof(what), "#%s", p.is_rule->a);
                hu_fail(ctx, (m > start) ? m : start, f->name, what);
                return -1;
            }
        } else {
            int l = (int)strlen(p.is_rule->a);
            if (end - start != l || strncmp(ctx->t + start, p.is_rule->a, (size_t)l) != 0) {
                char what[HU_LIT_LEN + 8];
                snprintf(what, sizeof(what), "'%s'", p.is_rule->a);
                hu_fail(ctx, start, f->name, what);
                return -1;
            }
        }
    }
    return node;
}

static int hu_match(HuCtx* ctx, HuField* f, int start, int end, int parent) {
    if (!f) return -1;
    if (ctx->depth >= HU_MAX_DEPTH) {
        hu_fail(ctx, start, f->name, "less nesting (recursion limit reached)");
        return -1;
    }
    ctx->depth++;
    int r = hu_match_inner(ctx, f, start, end, parent);
    ctx->depth--;
    return r;
}

/* ------------------------------------------------------------------ */
/* Tree handles                                                        */
/* ------------------------------------------------------------------ */

static void hu_tree_release(HuTree* tr) {
    if (!tr || !tr->used) return;
    free(tr->text);
    free(tr->nodes);
    tr->text = NULL;
    tr->nodes = NULL;
    tr->used = false;
    tr->node_count = 0;
    tr->node_cap = 0;
    tr->generation++;  /* every handle onto this slot is now stale */
}

static HuTree* hu_tree_create(const char* text, const char* grammar, int* slot_out) {
    for (int i = 0; i < HU_MAX_TREES; ++i) {
        if (g_trees[i].used) continue;
        HuTree* tr = &g_trees[i];
        int len = (int)strlen(text);
        tr->text = (char*)malloc((size_t)len + 1);
        tr->nodes = (HuNode*)calloc(HU_NODES_INIT, sizeof(HuNode));
        if (!tr->text || !tr->nodes) {
            free(tr->text);
            free(tr->nodes);
            tr->text = NULL;
            tr->nodes = NULL;
            return NULL;
        }
        memcpy(tr->text, text, (size_t)len + 1);
        tr->text_len = len;
        tr->node_cap = HU_NODES_INIT;
        tr->node_count = 0;
        tr->used = true;
        if (tr->generation == 0) tr->generation = 1;
        hu_copy(tr->grammar, HU_NAME_LEN, grammar, -1);
        *slot_out = i;
        return tr;
    }
    return NULL;
}

/* A handle is "hu#<slot>.<generation>[/<node>]". The generation is what makes a
 * handle held across `hu free` fail loudly instead of reading freed nodes. */
static void hu_handle_make(char* out, size_t cap, int slot, unsigned gen, int node) {
    if (node <= 0) snprintf(out, cap, "hu#%d.%u", slot, gen);
    else           snprintf(out, cap, "hu#%d.%u/%d", slot, gen, node);
}

static bool hu_handle_parse(const char* h, HuTree** tree_out, int* slot_out,
                            int* node_out, char* err, size_t err_size) {
    if (!h || strncmp(h, "hu#", 3) != 0) {
        snprintf(err, err_size, "'%s' is not a .hu handle", h ? h : "");
        return false;
    }
    const char* p = h + 3;
    char* endp = NULL;
    long slot = strtol(p, &endp, 10);
    if (!endp || *endp != '.' || slot < 0 || slot >= HU_MAX_TREES) {
        snprintf(err, err_size, "malformed handle '%s'", h);
        return false;
    }
    unsigned long gen = strtoul(endp + 1, &endp, 10);
    int node = 0;
    if (endp && *endp == '/') node = (int)strtol(endp + 1, &endp, 10);
    if (endp && *endp != '\0') {
        snprintf(err, err_size, "malformed handle '%s'", h);
        return false;
    }

    HuTree* tr = &g_trees[slot];
    if (!tr->used || tr->generation != (unsigned)gen) {
        snprintf(err, err_size, "handle '%s' refers to a tree that has been freed", h);
        return false;
    }
    if (node < 0 || node >= tr->node_count) {
        snprintf(err, err_size, "handle '%s' has no such node", h);
        return false;
    }
    if (tree_out) *tree_out = tr;
    if (slot_out) *slot_out = (int)slot;
    if (node_out) *node_out = node;
    return true;
}

/* ------------------------------------------------------------------ */
/* Rendering                                                           */
/* ------------------------------------------------------------------ */

static void hu_append(char* out, size_t cap, size_t* used, const char* text) {
    size_t l = strlen(text);
    if (*used + l >= cap) l = (cap > *used + 1) ? cap - *used - 1 : 0;
    memcpy(out + *used, text, l);
    *used += l;
    out[*used] = '\0';
}

static void hu_append_escaped(char* out, size_t cap, size_t* used,
                              const char* text, int start, int end) {
    for (int i = start; i < end && *used + 8 < cap; ++i) {
        switch (text[i]) {
            case '<': hu_append(out, cap, used, "&lt;"); break;
            case '>': hu_append(out, cap, used, "&gt;"); break;
            case '&': hu_append(out, cap, used, "&amp;"); break;
            default: {
                char c[2] = { text[i], '\0' };
                hu_append(out, cap, used, c);
                break;
            }
        }
    }
}

static void hu_xml(HuTree* tr, int idx, int indent, char* out, size_t cap, size_t* used) {
    HuNode* n = &tr->nodes[idx];
    for (int i = 0; i < indent; ++i) hu_append(out, cap, used, "  ");
    hu_append(out, cap, used, "<");
    hu_append(out, cap, used, n->kind);
    hu_append(out, cap, used, ">");

    if (n->first_child < 0) {
        hu_append_escaped(out, cap, used, tr->text, n->start, n->end);
    } else {
        hu_append(out, cap, used, "\n");
        for (int c = n->first_child; c >= 0; c = tr->nodes[c].next_sibling) {
            hu_xml(tr, c, indent + 1, out, cap, used);
        }
        for (int i = 0; i < indent; ++i) hu_append(out, cap, used, "  ");
    }
    hu_append(out, cap, used, "</");
    hu_append(out, cap, used, n->kind);
    hu_append(out, cap, used, ">\n");
}

static void hu_dump(HuTree* tr, int idx, int indent) {
    HuNode* n = &tr->nodes[idx];
    for (int i = 0; i < indent; ++i) printf("  ");
    printf("$%s", n->kind);
    if (n->first_child < 0) {
        printf(" = \"%.*s\"", n->end - n->start, tr->text + n->start);
    }
    printf("\n");
    for (int c = n->first_child; c >= 0; c = tr->nodes[c].next_sibling) {
        hu_dump(tr, c, indent + 1);
    }
}

/* Resolves a slash-separated path of field names from `idx`. */
static int hu_node_path(HuTree* tr, int idx, const char* path) {
    char buf[HU_NAME_LEN * 8];
    hu_copy(buf, sizeof(buf), path, -1);
    char* save = NULL;
    char* part = strtok_r(buf, "/", &save);
    int cur = idx;
    while (part) {
        int found = -1;
        for (int c = tr->nodes[cur].first_child; c >= 0; c = tr->nodes[c].next_sibling) {
            if (strcmp(tr->nodes[c].kind, part) == 0) { found = c; break; }
        }
        if (found < 0) return -1;
        cur = found;
        part = strtok_r(NULL, "/", &save);
    }
    return cur;
}

/* ------------------------------------------------------------------ */
/* Actions                                                             */
/* ------------------------------------------------------------------ */

static void hu_walk(HuGrammar* g, HuTree* tr, int slot, int idx) {
    HuNode* n = &tr->nodes[idx];
    HuField* f = hu_field_find(g, n->kind);
    if (f && f->action[0]) {
        /* The action is resolved the way any command name is, but a missing
         * one is worth saying plainly rather than letting it fall through to a
         * PATH lookup and a confusing "command not found". */
        UserFunction* fn = function_list;
        while (fn && strcmp(fn->name, f->action) != 0) fn = fn->next;
        if (fn) {
            char handle[64];
            static char text[INPUT_BUFFER_SIZE];
            static char discard[INPUT_BUFFER_SIZE];
            hu_handle_make(handle, sizeof(handle), slot, tr->generation, idx);
            int len = n->end - n->start;
            if (len >= INPUT_BUFFER_SIZE) len = INPUT_BUFFER_SIZE - 1;
            memcpy(text, tr->text + n->start, (size_t)len);
            text[len] = '\0';
            const char* argv[2] = { handle, text };
            besh_dispatch_command_values(f->action, argv, 2, discard, sizeof(discard));
        } else {
            fprintf(stderr, "hu walk: no function named '%s' for field $%s\n", f->action, n->kind);
        }
    }
    for (int c = n->first_child; c >= 0; c = tr->nodes[c].next_sibling) {
        hu_walk(g, tr, slot, c);
    }
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

void besh_hu_init(void) {
    if (g_hu_ready) return;
    memset(g_grammars, 0, sizeof(g_grammars));
    memset(g_trees, 0, sizeof(g_trees));
    g_hu_error[0] = '\0';
    g_hu_ready = true;
}

void besh_hu_shutdown(void) {
    if (!g_hu_ready) return;
    for (int i = 0; i < HU_MAX_GRAMMARS; ++i) hu_grammar_release(&g_grammars[i]);
    for (int i = 0; i < HU_MAX_TREES; ++i) hu_tree_release(&g_trees[i]);
    g_hu_ready = false;
}

/* ------------------------------------------------------------------ */
/* The `hu` builtin                                                    */
/* ------------------------------------------------------------------ */

/* Reads a whole file. The caller frees the result. */
static char* hu_read_file(const char* path, char* err, size_t err_size) {
    /* fopen succeeds on a directory on some systems and then reads nothing,
     * which would look like an empty grammar rather than a mistake. */
    struct stat st;
    if (stat(path, &st) != 0) { snprintf(err, err_size, "cannot open '%s'", path); return NULL; }
    if (!S_ISREG(st.st_mode)) { snprintf(err, err_size, "'%s' is not a regular file", path); return NULL; }

    FILE* fp = fopen(path, "rb");
    if (!fp) { snprintf(err, err_size, "cannot open '%s'", path); return NULL; }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); snprintf(err, err_size, "cannot size '%s'", path); return NULL; }
    long size = ftell(fp);
    if (size < 0) { fclose(fp); snprintf(err, err_size, "cannot size '%s'", path); return NULL; }
    rewind(fp);
    char* buf = (char*)malloc((size_t)size + 1);
    if (!buf) { fclose(fp); snprintf(err, err_size, "out of memory reading '%s'", path); return NULL; }
    size_t got = fread(buf, 1, (size_t)size, fp);
    buf[got] = '\0';
    fclose(fp);
    return buf;
}

/* Every subcommand, its fixed argument count, and whether it yields a value.
 * A value-producing subcommand writes to the trailing result variable when one
 * is given and prints the value when one is not. */
typedef struct {
    const char* name;
    int         fixed;
    bool        produces;
    /* Index of the argument that is .hu source rather than shell data. A
     * quoted literal in that position is taken verbatim, because `$field` in a
     * grammar means a field and expanding it away would leave nothing behind.
     * A variable token there is still expanded, so building a grammar in a
     * variable and passing it works as usual. -1 when there is no such
     * argument. */
    int         raw_arg;
} HuSubcommand;

static const HuSubcommand g_subs[] = {
    { "status",    0, false, -1 },
    { "terms",     0, false, -1 },
    { "list",      0, true,  -1 },
    { "error",     0, true,  -1 },
    { "load",      1, true,  -1 },
    { "unload",    1, false, -1 },
    { "fields",    1, true,  -1 },
    { "free",      1, false, -1 },
    { "tree",      1, false, -1 },
    { "kind",      1, true,  -1 },
    { "text",      1, true,  -1 },
    { "count",     1, true,  -1 },
    { "xml",       1, true,  -1 },
    { "walk",      1, false, -1 },
    { "define",    2, true,   1 },
    { "rule",      2, false,  1 },
    { "extend",    2, false, -1 },
    { "rules",     2, false, -1 },
    { "parse",     2, true,  -1 },
    { "parsefile", 2, true,  -1 },
    { "child",     2, true,  -1 },
    { "node",      2, true,  -1 },
    { "bind",      2, false, -1 },
    { "on",        3, false, -1 },
};
static const int g_sub_count = (int)(sizeof(g_subs) / sizeof(g_subs[0]));

static const HuSubcommand* hu_sub_find(const char* name) {
    for (int i = 0; i < g_sub_count; ++i) {
        if (strcmp(g_subs[i].name, name) == 0) return &g_subs[i];
    }
    return NULL;
}

bool besh_hu_produces_value(const char* sub) {
    const HuSubcommand* s = hu_sub_find(sub);
    return s ? s->produces : false;
}

/* Runs one parse and publishes the tree. */
static bool hu_do_parse(HuGrammar* g, const char* text, char* out, size_t out_size,
                        char* err, size_t err_size) {
    int slot = -1;
    HuTree* tr = hu_tree_create(text, g->name, &slot);
    if (!tr) { snprintf(err, err_size, "no free parse tree (max %d)", HU_MAX_TREES); return false; }

    HuField* root = hu_field_find(g, g->root);
    if (!root) {
        hu_tree_release(tr);
        snprintf(err, err_size, "grammar '%s' has no root field", g->name);
        return false;
    }

    HuCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.g = g;
    ctx.tree = tr;
    ctx.t = tr->text;
    ctx.fail_pos = -1;

    g_parses++;
    int node = hu_match(&ctx, root, 0, tr->text_len, -1);
    if (node < 0) {
        g_parse_failures++;
        /* Turn the deepest expectation into a line and column. */
        int line = 1, col = 1;
        for (int i = 0; i < ctx.fail_pos && i < tr->text_len; ++i) {
            if (tr->text[i] == '\n') { line++; col = 1; } else { col++; }
        }
        snprintf(g_hu_error, sizeof(g_hu_error), "line %d, col %d: %s",
                 line, col, ctx.fail_msg[0] ? ctx.fail_msg : "no rule matched");
        hu_tree_release(tr);
        snprintf(err, err_size, "%s", g_hu_error);
        return false;
    }
    g_hu_error[0] = '\0';
    hu_handle_make(out, out_size, slot, tr->generation, 0);
    return true;
}

bool besh_hu_command(const char* sub, char argv[][BESH_HU_ARG_SIZE], int argc,
                     char* out, size_t out_size,
                     char* err, size_t err_size) {
    besh_hu_init();
    out[0] = '\0';
    err[0] = '\0';

    const HuSubcommand* spec = hu_sub_find(sub);
    if (!spec) { snprintf(err, err_size, "unknown subcommand '%s'", sub); return false; }
    if (argc < spec->fixed) {
        snprintf(err, err_size, "hu %s needs %d argument(s)", sub, spec->fixed);
        return false;
    }

    /* --- introspection ------------------------------------------------ */

    if (strcmp(sub, "status") == 0) {
        int grammars = 0, trees = 0;
        for (int i = 0; i < HU_MAX_GRAMMARS; ++i) if (g_grammars[i].used) grammars++;
        for (int i = 0; i < HU_MAX_TREES; ++i) if (g_trees[i].used) trees++;
        printf("hu: grammars=%d/%d trees=%d/%d parses=%ld failures=%ld\n",
               grammars, HU_MAX_GRAMMARS, trees, HU_MAX_TREES, g_parses, g_parse_failures);
        return true;
    }

    if (strcmp(sub, "terms") == 0) {
        const char* const class_name[] = { "verb", "conditional", "quantity", "conjunction", "comparison" };
        for (int i = 0; i < g_term_count; ++i) {
            printf("%-14s %-14s %s\n", g_terms[i].text, g_terms[i].canonical, class_name[g_terms[i].cls]);
        }
        printf("constants:");
        for (int i = 0; i < g_builtin_const_count; ++i) printf(" #%s", g_builtin_consts[i].name);
        printf("\n");
        return true;
    }

    if (strcmp(sub, "list") == 0) {
        size_t used = 0;
        for (int i = 0; i < HU_MAX_GRAMMARS; ++i) {
            if (!g_grammars[i].used) continue;
            if (used) hu_append(out, out_size, &used, " ");
            hu_append(out, out_size, &used, g_grammars[i].name);
        }
        return true;
    }

    if (strcmp(sub, "error") == 0) {
        snprintf(out, out_size, "%s", g_hu_error);
        return true;
    }

    /* --- grammar lifecycle -------------------------------------------- */

    if (strcmp(sub, "load") == 0 || strcmp(sub, "define") == 0) {
        bool from_file = (strcmp(sub, "load") == 0);
        char* source = NULL;
        const char* name = NULL;

        if (from_file) {
            source = hu_read_file(argv[0], err, err_size);
            if (!source) return false;
            name = argv[0];
        } else {
            name = argv[0];
            source = strdup(argv[1]);
            if (!source) { snprintf(err, err_size, "out of memory"); return false; }
        }

        HuGrammar* g = hu_grammar_create(name);
        if (!g) { free(source); snprintf(err, err_size, "no free grammar slot (max %d)", HU_MAX_GRAMMARS); return false; }

        char perr[HU_ERR_LEN];
        perr[0] = '\0';
        bool ok = hu_parse_source(g, source, perr, sizeof(perr));
        free(source);
        if (!ok) {
            hu_grammar_release(g);
            snprintf(err, err_size, "%s: %s", name, perr);
            return false;
        }
        /* `$root IS "Name"` renames the grammar; that name is what every other
         * subcommand takes. */
        snprintf(out, out_size, "%s", g->name);
        return true;
    }

    if (strcmp(sub, "unload") == 0) {
        HuGrammar* g = hu_grammar_find(argv[0]);
        if (!g) { snprintf(err, err_size, "no grammar named '%s'", argv[0]); return false; }
        hu_grammar_release(g);
        return true;
    }

    if (strcmp(sub, "rule") == 0 || strcmp(sub, "extend") == 0) {
        HuGrammar* g = hu_grammar_find(argv[0]);
        if (!g) { snprintf(err, err_size, "no grammar named '%s'", argv[0]); return false; }

        char* source = NULL;
        if (strcmp(sub, "extend") == 0) {
            source = hu_read_file(argv[1], err, err_size);
            if (!source) return false;
        } else {
            source = strdup(argv[1]);
            if (!source) { snprintf(err, err_size, "out of memory"); return false; }
        }

        char perr[HU_ERR_LEN];
        perr[0] = '\0';
        /* An extension keeps the grammar's own name even if it restates a
         * title, so callers that already hold the name keep working. */
        char keep[HU_NAME_LEN];
        hu_copy(keep, HU_NAME_LEN, g->name, -1);
        bool ok = hu_parse_source(g, source, perr, sizeof(perr));
        hu_copy(g->name, HU_NAME_LEN, keep, -1);
        free(source);
        if (!ok) { snprintf(err, err_size, "%s", perr); return false; }
        return true;
    }

    if (strcmp(sub, "fields") == 0) {
        HuGrammar* g = hu_grammar_find(argv[0]);
        if (!g) { snprintf(err, err_size, "no grammar named '%s'", argv[0]); return false; }
        size_t used = 0;
        for (int i = 0; i < g->field_count; ++i) {
            if (used) hu_append(out, out_size, &used, " ");
            hu_append(out, out_size, &used, g->fields[i].name);
        }
        return true;
    }

    if (strcmp(sub, "rules") == 0) {
        HuGrammar* g = hu_grammar_find(argv[0]);
        if (!g) { snprintf(err, err_size, "no grammar named '%s'", argv[0]); return false; }
        HuField* f = hu_field_find(g, argv[1]);
        if (!f) { snprintf(err, err_size, "grammar '%s' has no field $%s", argv[0], argv[1]); return false; }

        static const char* const kind_name[] = {
            "TITLE", "HAVE", "CAN BE", "IS", "ENDS WITH", "STARTS WITH", "INSIDE", "EXTENDS"
        };
        printf("$%s%s\n", f->name, (strcmp(f->name, g->root) == 0) ? "  (root)" : "");
        for (int i = 0; i < f->rule_count; ++i) {
            HuRule* r = &f->rules[i];
            printf("  %-12s", kind_name[r->kind]);
            if (r->akind == HU_OPD_FIELD)        printf(" $%s", r->a);
            else if (r->akind == HU_OPD_CONST)   printf(" #%s", r->a);
            else if (r->akind == HU_OPD_LITERAL) printf(" '%s'", r->a);
            else if (r->akind == HU_OPD_NAME)    printf(" \"%s\"", r->a);
            if (r->bkind == HU_OPD_LITERAL)      printf(" '%s'", r->b);
            if (r->order)   printf(" order=%d", r->order);
            if (r->max < 0) printf(" quantity=%d..*", r->min);
            else if (r->min != 1 || r->max != 1) printf(" quantity=%d..%d", r->min, r->max);
            if (r->must)    printf(" MUST");
            if (r->sep[0])  printf(" separated-by='%s'", r->sep);
            if (r->guard[0]) printf(" if-has='%s'", r->guard);
            printf("\n");
        }
        if (f->action[0]) printf("  action       %s\n", f->action);
        return true;
    }

    if (strcmp(sub, "on") == 0) {
        HuGrammar* g = hu_grammar_find(argv[0]);
        if (!g) { snprintf(err, err_size, "no grammar named '%s'", argv[0]); return false; }
        HuField* f = hu_field_find(g, argv[1]);
        if (!f) { snprintf(err, err_size, "grammar '%s' has no field $%s", argv[0], argv[1]); return false; }
        hu_copy(f->action, MAX_VAR_NAME_LEN, argv[2], -1);
        return true;
    }

    /* --- recognition --------------------------------------------------- */

    if (strcmp(sub, "parse") == 0 || strcmp(sub, "parsefile") == 0) {
        HuGrammar* g = hu_grammar_find(argv[0]);
        if (!g) { snprintf(err, err_size, "no grammar named '%s'", argv[0]); return false; }
        if (strcmp(sub, "parse") == 0) return hu_do_parse(g, argv[1], out, out_size, err, err_size);

        char* source = hu_read_file(argv[1], err, err_size);
        if (!source) return false;
        bool ok = hu_do_parse(g, source, out, out_size, err, err_size);
        free(source);
        return ok;
    }

    if (strcmp(sub, "free") == 0) {
        HuTree* tr = NULL;
        if (!hu_handle_parse(argv[0], &tr, NULL, NULL, err, err_size)) return false;
        hu_tree_release(tr);
        return true;
    }

    /* --- tree navigation ----------------------------------------------- */

    if (strcmp(sub, "kind") == 0 || strcmp(sub, "text") == 0 ||
        strcmp(sub, "count") == 0 || strcmp(sub, "tree") == 0 ||
        strcmp(sub, "xml") == 0 || strcmp(sub, "walk") == 0) {
        HuTree* tr = NULL;
        int slot = 0, idx = 0;
        if (!hu_handle_parse(argv[0], &tr, &slot, &idx, err, err_size)) return false;
        HuNode* n = &tr->nodes[idx];

        if (strcmp(sub, "kind") == 0) {
            snprintf(out, out_size, "%s", n->kind);
            return true;
        }
        if (strcmp(sub, "text") == 0) {
            int len = n->end - n->start;
            if (len < 0) len = 0;
            if ((size_t)len >= out_size) len = (int)out_size - 1;
            memcpy(out, tr->text + n->start, (size_t)len);
            out[len] = '\0';
            return true;
        }
        if (strcmp(sub, "count") == 0) {
            int count = 0;
            for (int c = n->first_child; c >= 0; c = tr->nodes[c].next_sibling) count++;
            snprintf(out, out_size, "%d", count);
            return true;
        }
        if (strcmp(sub, "tree") == 0) {
            hu_dump(tr, idx, 0);
            return true;
        }
        if (strcmp(sub, "xml") == 0) {
            size_t used = 0;
            hu_xml(tr, idx, 0, out, out_size, &used);
            return true;
        }
        /* walk */
        HuGrammar* g = hu_grammar_find(tr->grammar);
        if (!g) { snprintf(err, err_size, "grammar '%s' is no longer loaded", tr->grammar); return false; }
        hu_walk(g, tr, slot, idx);
        return true;
    }

    if (strcmp(sub, "child") == 0 || strcmp(sub, "node") == 0 || strcmp(sub, "bind") == 0) {
        HuTree* tr = NULL;
        int slot = 0, idx = 0;
        if (!hu_handle_parse(argv[0], &tr, &slot, &idx, err, err_size)) return false;

        if (strcmp(sub, "child") == 0) {
            int want = atoi(argv[1]);
            int i = 0;
            for (int c = tr->nodes[idx].first_child; c >= 0; c = tr->nodes[c].next_sibling, ++i) {
                if (i == want) { hu_handle_make(out, out_size, slot, tr->generation, c); return true; }
            }
            snprintf(err, err_size, "node has no child %d", want);
            return false;
        }

        if (strcmp(sub, "node") == 0) {
            int found = hu_node_path(tr, idx, argv[1]);
            if (found < 0) { snprintf(err, err_size, "no node at path '%s'", argv[1]); return false; }
            hu_handle_make(out, out_size, slot, tr->generation, found);
            return true;
        }

        /* bind: publish one node's immediate children as shell variables. */
        {
            const char* prefix = argv[1];
            char var[MAX_VAR_NAME_LEN];
            char value[INPUT_BUFFER_SIZE];
            HuNode* n = &tr->nodes[idx];

            snprintf(var, sizeof(var), "%s_KIND", prefix);
            set_variable_scoped(var, n->kind, false);

            int len = n->end - n->start;
            if (len < 0) len = 0;
            if (len >= INPUT_BUFFER_SIZE) len = INPUT_BUFFER_SIZE - 1;
            memcpy(value, tr->text + n->start, (size_t)len);
            value[len] = '\0';
            snprintf(var, sizeof(var), "%s_TEXT", prefix);
            set_variable_scoped(var, value, false);

            int count = 0;
            for (int c = n->first_child; c >= 0; c = tr->nodes[c].next_sibling) {
                char handle[64], index[16];
                hu_handle_make(handle, sizeof(handle), slot, tr->generation, c);
                snprintf(index, sizeof(index), "%d", count);
                set_array_element_scoped(prefix, index, handle);

                /* The first child of each field name is also reachable by name. */
                snprintf(var, sizeof(var), "%s_%s", prefix, tr->nodes[c].kind);
                if (!get_variable_scoped(var)) set_variable_scoped(var, handle, false);
                count++;
            }
            snprintf(var, sizeof(var), "%s_COUNT", prefix);
            snprintf(value, sizeof(value), "%d", count);
            set_variable_scoped(var, value, false);
            return true;
        }
    }

    snprintf(err, err_size, "unknown subcommand '%s'", sub);
    return false;
}

/* Expands one token the way the interpreter's command handlers do. Quoted
 * arguments keep their quotes in the token, so unescaping has to happen before
 * expansion or a quoted grammar name is looked up with its quotes attached. */
static void hu_expand_token(const Token* t, char* out, size_t out_size, bool literal) {
    char raw[INPUT_BUFFER_SIZE];
    snprintf(raw, sizeof(raw), "%.*s", t->len, t->text);
    if (t->type == TOKEN_STRING) {
        char unescaped[INPUT_BUFFER_SIZE];
        unescape_string(raw, unescaped, sizeof(unescaped));
        if (literal) snprintf(out, out_size, "%s", unescaped);
        else         expand_variables_in_string_advanced(unescaped, out, out_size);
    } else {
        expand_variables_in_string_advanced(raw, out, out_size);
    }
}

void handle_hu_statement(Token* tokens, int num_tokens) {
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    if (num_tokens < 2) {
        fprintf(stderr, "Syntax: hu <subcommand> [args...] [result_var]\n");
        return;
    }
    besh_hu_init();

    /* Static: process_line recurses, and a per-frame copy of this buffer would
     * exhaust the stack within a few nested calls. */
    static char expanded[MAX_CALL_ARGS][INPUT_BUFFER_SIZE];

    /* The subcommand decides how its own arguments are read, so it is expanded
     * on its own before the rest. */
    hu_expand_token(&tokens[1], expanded[0], INPUT_BUFFER_SIZE, false);

    char sub[MAX_VAR_NAME_LEN];
    snprintf(sub, sizeof(sub), "%s", expanded[0]);

    const HuSubcommand* spec = hu_sub_find(sub);
    if (!spec) {
        fprintf(stderr, "hu: unknown subcommand '%s'\n", sub);
        set_variable_scoped("LAST_HU_STATUS", "1", false);
        return;
    }

    int count = 1;
    for (int i = 2; i < num_tokens && count < MAX_CALL_ARGS; ++i) {
        if (tokens[i].type == TOKEN_COMMENT) break;
        bool literal = (spec->raw_arg >= 0 && (count - 1) == spec->raw_arg);
        hu_expand_token(&tokens[i], expanded[count], INPUT_BUFFER_SIZE, literal);
        count++;
    }

    /* A value-producing subcommand takes its result variable last, but only
     * when one was actually supplied; without it the value is printed. */
    int arg_count = count - 1;
    char result_var[MAX_VAR_NAME_LEN];
    result_var[0] = '\0';
    if (spec->produces && arg_count > spec->fixed) {
        snprintf(result_var, sizeof(result_var), "%s", expanded[count - 1]);
        trim_whitespace(result_var);
        arg_count--;
    }

    static char result[INPUT_BUFFER_SIZE];
    char err[HU_ERR_LEN];
    if (!besh_hu_command(sub, &expanded[1], arg_count, result, sizeof(result), err, sizeof(err))) {
        fprintf(stderr, "hu: %s\n", err);
        set_variable_scoped("LAST_HU_STATUS", "1", false);
        if (result_var[0]) set_variable_scoped(result_var, "", false);
        return;
    }
    set_variable_scoped("LAST_HU_STATUS", "0", false);
    if (result_var[0]) {
        set_variable_scoped(result_var, result, false);
    } else if (spec->produces && result[0]) {
        printf("%s\n", result);
    }
}
