/*
 * Tree-sitter splice mutator for AFL++.
 *
 * Language-agnostic, AST-aware fuzzing mutations inspired by tree-splicer:
 * https://github.com/langston-barrett/tree-splicer.
 *
 * Uses tree-sitter to parse inputs, then performs type-safe
 * mutations: subtree deletion, cross-input splicing, sibling swapping,
 * recursive shrinking, literal replacement, and subtree duplication.
 *
 * The grammar .so is loaded at runtime via dlopen (TS_GRAMMAR env var),
 * so this mutator works with ANY tree-sitter grammar without recompilation.
 */

#include "afl-fuzz.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tree_sitter/api.h>

/* ------------------------------------------------------------------ */
/* Configuration defaults                                              */
/* ------------------------------------------------------------------ */

#define DEFAULT_BANK_CAP       8192
#define DEFAULT_BANK_MAX_SUB   256
#define DEFAULT_NODE_CAP       4096
#define DEFAULT_ARENA_CAP      (DEFAULT_BANK_CAP * DEFAULT_BANK_MAX_SUB)
#define DEFAULT_HAVOC_PROB     50
#define MAX_RETRIES            4
#define MUT_COUNT              10
#define TS_STACK_HARD_CAP      8

/* ------------------------------------------------------------------ */
/* Mutation strategy IDs                                               */
/* ------------------------------------------------------------------ */

enum {
  MUT_SUBTREE_DELETE       = 0,
  MUT_SUBTREE_REPLACE_BANK = 1,
  MUT_SUBTREE_REPLACE_ADD  = 2,
  MUT_SIBLING_SWAP         = 3,
  MUT_RECURSIVE_SHRINK     = 4,
  MUT_LITERAL_REPLACE      = 5,
  MUT_SUBTREE_DUPLICATE    = 6,
  MUT_BANK_INSERT          = 7,
  MUT_RANGE_SPLICE         = 8,
  MUT_CHAOS                = 9,
};

static const uint32_t default_weights[MUT_COUNT] = {
    20, /* SUBTREE_DELETE       */
    20, /* SUBTREE_REPLACE_BANK */
    20, /* SUBTREE_REPLACE_ADD  */
    15, /* SIBLING_SWAP         */
    10, /* RECURSIVE_SHRINK     */
     5, /* LITERAL_REPLACE      */
     3, /* SUBTREE_DUPLICATE    */
     7, /* BANK_INSERT          */
     4, /* RANGE_SPLICE         */
     2, /* CHAOS                */
};

static const char *mut_names[MUT_COUNT] = {
    "ts-del", "ts-bank", "ts-add", "ts-swap",
    "ts-shrink", "ts-lit", "ts-dup", "ts-ins",
    "ts-range", "ts-chaos",
};

/* ------------------------------------------------------------------ */
/* Numeric literal tables (used by ts-lit)                             */
/* ------------------------------------------------------------------ */

/* Boundary values that shake loose off-by-one, unsigned wraps, and
   signed/unsigned confusion in target code. */
static const int64_t TS_LIT_SMALL[] = {
    -1, 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100,
    127, 128, 255, 256, 511, 512, 1000, 1024, 4096,
    32767, 32768, 65535, 65536, 1000000,
    2147483647LL, -2147483648LL, 4294967295LL,
};
#define TS_LIT_SMALL_N (sizeof(TS_LIT_SMALL) / sizeof(TS_LIT_SMALL[0]))

/* Values too wide for int64; emitted verbatim. */
static const char *TS_LIT_BIG[] = {
    "9223372036854775807",
    "9223372036854775808",
    "18446744073709551615",
    "18446744073709551616",
    "0xffffffffffffffff",
    "0x10000000000000000",
    "170141183460469231731687303715884105727",
    "340282366920938463463374607431768211455",
    "340282366920938463463374607431768211456",
    "115792089237316195423570985008687907853269984665640564039457584007913129639935",
};
#define TS_LIT_BIG_N (sizeof(TS_LIT_BIG) / sizeof(TS_LIT_BIG[0]))

/* Deltas to apply to the current value. */
static const int32_t TS_LIT_DELTAS[] = {
    1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 65536,
};
#define TS_LIT_DELTAS_N (sizeof(TS_LIT_DELTAS) / sizeof(TS_LIT_DELTAS[0]))

/* ------------------------------------------------------------------ */
/* Data structures                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
  uint32_t start_byte;
  uint32_t end_byte;
  TSSymbol symbol;
  uint32_t parent_idx;    /* UINT32_MAX for root */
  uint32_t named_children;
} NodeInfo;

typedef struct {
  TSSymbol symbol;
  uint32_t text_offset;
  uint32_t text_len;
} SubtreeEntry;

typedef struct {
  uint32_t start;
  uint32_t count;
} BankIndex;

/* Pre-computed sibling pair for O(1) swap */
typedef struct {
  uint32_t a;
  uint32_t b;
} SibPair;

/* A run of direct children of one parent that all share a symbol.
   Children in [start, start+count) inside sib_group_members are kept
   in source order so a contiguous slice maps to a contiguous byte range. */
typedef struct {
  uint32_t parent_idx;
  TSSymbol symbol;
  uint32_t start;
  uint32_t count;
} SibGroup;

typedef struct {
  /* tree-sitter core */
  TSParser        *parser;
  const TSLanguage *lang;
  void            *grammar_handle;

  /* output buffer */
  uint8_t *out_buf;
  size_t   out_cap;

  /* tree cache (main input) */
  uint64_t cached_hash;
  size_t   cached_len;
  TSTree  *cached_tree;

  /* add_buf cache */
  uint64_t add_hash;
  size_t   add_len;
  TSTree  *add_tree;
  NodeInfo *add_nodes;
  uint32_t  add_node_count;
  uint32_t  add_node_cap;

  /* flat node table */
  NodeInfo *nodes;
  uint32_t  node_count;
  uint32_t  node_cap;

  /* pre-computed indices (built during collect_nodes) */
  uint32_t *leaf_idx;     /* indices of leaf nodes */
  uint32_t  leaf_count;
  uint32_t  leaf_cap;
  SibPair  *sib_pairs;    /* swappable sibling pairs */
  uint32_t  sib_count;
  uint32_t  sib_cap;

  /* sibling groups of >=2 same-symbol direct children */
  SibGroup *sib_groups;
  uint32_t  sib_group_count;
  uint32_t  sib_group_cap;
  uint32_t *sib_group_members;
  uint32_t  sib_group_members_count;
  uint32_t  sib_group_members_cap;

  /* scratch buffer for concatenating bank donors during range splice */
  uint8_t  *range_scratch;
  uint32_t  range_scratch_cap;

  /* subtree bank */
  SubtreeEntry *bank;
  uint32_t      bank_count;
  uint32_t      bank_cap;
  char         *bank_arena;
  size_t        arena_used;
  size_t        arena_cap;
  uint32_t      bank_max_subtree;

  /* per-symbol index */
  BankIndex *sym_index;
  uint32_t   sym_index_size;
  int        sym_index_dirty;

  /* mutation config */
  uint32_t weights[MUT_COUNT];
  uint32_t weight_sum;
  uint8_t  havoc_prob;

  /* RNG (xorshift64) */
  uint64_t rng;

  /* description */
  char desc_buf[64];
  int  last_mutation;

  /* chaos modifier — set by dispatcher when MUT_CHAOS fires, cleared
     immediately after the underlying strategy runs. When set, the
     bank/add/range strategies skip their TSSymbol filter. */
  uint8_t chaos_active;

  /* multi-round stacking (TS_STACK_MAX) */
  uint32_t stack_max;             /* clamped to [1, TS_STACK_HARD_CAP] */
  uint8_t *stack_scratch;         /* intermediate buffer, allocated iff stack_max>1 */
  size_t   stack_scratch_cap;
  uint32_t last_stack_depth;      /* effective depth of most recent fuzz call */

} TSMutState;

/* ------------------------------------------------------------------ */
/* Fast hash (FNV-1a 64-bit) for cache invalidation                    */
/* ------------------------------------------------------------------ */

static inline uint64_t fnv1a(const uint8_t *data, size_t len) {
  uint64_t h = 0xcbf29ce484222325ULL;
  /* process 8 bytes at a time */
  while (len >= 8) {
    uint64_t v;
    memcpy(&v, data, 8);
    h = (h ^ v) * 0x100000001b3ULL;
    data += 8;
    len -= 8;
  }
  while (len--) h = (h ^ *data++) * 0x100000001b3ULL;
  return h;
}

/* ------------------------------------------------------------------ */
/* RNG                                                                 */
/* ------------------------------------------------------------------ */

static inline uint64_t rng_next(TSMutState *st) {
  uint64_t x = st->rng;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return (st->rng = x);
}

static inline uint32_t rng_below(TSMutState *st, uint32_t max) {
  if (!max) return 0;
  return (uint32_t)(rng_next(st) % max);
}

/* ------------------------------------------------------------------ */
/* Buffer helpers                                                      */
/* ------------------------------------------------------------------ */

static void ensure_out(TSMutState *st, size_t need) {
  if (st->out_cap >= need) return;
  size_t nc = st->out_cap ? st->out_cap : 4096;
  while (nc < need) nc <<= 1;
  uint8_t *p = realloc(st->out_buf, nc);
  if (!p) return;
  st->out_buf = p;
  st->out_cap = nc;
}

/* Build output: head from buf[0..head_len] + repl[0..repl_len] + tail from buf[tail_off..buf_len].
   Returns new length, or 0 on failure. */
static size_t splice_output(TSMutState *st, const uint8_t *buf, size_t buf_len,
                            uint32_t head_len, const uint8_t *repl,
                            size_t repl_len, uint32_t tail_off,
                            size_t max_size) {
  size_t tail_len = buf_len - tail_off;
  size_t new_len = head_len + repl_len + tail_len;
  if (new_len == 0 || new_len > max_size) return 0;
  ensure_out(st, new_len);
  if (st->out_cap < new_len) return 0;
  if (head_len) memcpy(st->out_buf, buf, head_len);
  if (repl_len) memcpy(st->out_buf + head_len, repl, repl_len);
  if (tail_len) memcpy(st->out_buf + head_len + repl_len, buf + tail_off, tail_len);
  return new_len;
}

/* ------------------------------------------------------------------ */
/* Node collection via TSTreeCursor                                    */
/* ------------------------------------------------------------------ */

/* Grow a dynamic array. Returns 0 on success, -1 on alloc failure. */
#define GROW_ARRAY(ptr, count, cap, type, init_cap) do { \
  if ((count) >= (cap)) {                                \
    uint32_t _nc = (cap) ? (cap) * 2 : (init_cap);      \
    type *_p = realloc((ptr), _nc * sizeof(type));       \
    if (!_p) return;                                     \
    (ptr) = _p; (cap) = _nc;                             \
  }                                                      \
} while (0)

static void collect_nodes(TSMutState *st, TSTree *tree) {
  st->node_count = 0;
  st->leaf_count = 0;
  st->sib_count = 0;
  st->sib_group_count = 0;
  st->sib_group_members_count = 0;
  TSNode root = ts_tree_root_node(tree);
  if (ts_node_is_null(root)) return;

  TSTreeCursor cursor = ts_tree_cursor_new(root);

  /* parent tracking: maps depth -> index in nodes[] */
  uint32_t parent_stack[256];
  uint32_t depth = 0;
  parent_stack[0] = UINT32_MAX;

  for (;;) {
    TSNode node = ts_tree_cursor_current_node(&cursor);

    if (ts_node_is_named(node) && !ts_node_has_error(node)) {
      GROW_ARRAY(st->nodes, st->node_count, st->node_cap, NodeInfo,
                 DEFAULT_NODE_CAP);

      uint32_t idx = st->node_count;
      uint32_t pidx = (depth < 256) ? parent_stack[depth] : UINT32_MAX;
      st->nodes[idx].start_byte = ts_node_start_byte(node);
      st->nodes[idx].end_byte = ts_node_end_byte(node);
      st->nodes[idx].symbol = ts_node_symbol(node);
      st->nodes[idx].parent_idx = pidx;
      st->nodes[idx].named_children = 0;
      st->node_count++;

      /* bump parent's child count */
      if (pidx != UINT32_MAX && pidx < st->node_count)
        st->nodes[pidx].named_children++;

      /* set as parent for next depth level */
      if (depth + 1 < 256) parent_stack[depth + 1] = idx;
    }

    if (ts_tree_cursor_goto_first_child(&cursor)) {
      depth++;
      continue;
    }
    if (ts_tree_cursor_goto_next_sibling(&cursor)) continue;

    while (ts_tree_cursor_goto_parent(&cursor)) {
      if (depth > 0) depth--;
      if (ts_tree_cursor_goto_next_sibling(&cursor)) goto next_iter;
    }
    break;
    next_iter:;
  }
  ts_tree_cursor_delete(&cursor);

  /* Post-pass: build leaf index and sibling pairs */
  for (uint32_t i = 0; i < st->node_count; i++) {
    NodeInfo *n = &st->nodes[i];

    /* Leaves */
    if (n->named_children == 0 && n->end_byte > n->start_byte) {
      GROW_ARRAY(st->leaf_idx, st->leaf_count, st->leaf_cap, uint32_t, 256);
      st->leaf_idx[st->leaf_count++] = i;
    }

    /* Sibling pairs: for each node, check the next few nodes with same parent+symbol */
    if (n->parent_idx != UINT32_MAX) {
      for (uint32_t j = i + 1; j < st->node_count && j < i + 32; j++) {
        NodeInfo *m = &st->nodes[j];
        if (m->parent_idx == n->parent_idx && m->symbol == n->symbol &&
            n->end_byte <= m->start_byte) {
          GROW_ARRAY(st->sib_pairs, st->sib_count, st->sib_cap, SibPair, 128);
          st->sib_pairs[st->sib_count].a = i;
          st->sib_pairs[st->sib_count].b = j;
          st->sib_count++;
          break; /* one pair per node is enough */
        }
      }
    }
  }

  /* Second post-pass: for each parent with >=2 named children, emit one
     SibGroup per run of same-symbol children, preserving source order. */
  #define SIB_MEMBERS_HARD_CAP 65536u
  for (uint32_t p = 0; p < st->node_count; p++) {
    if (st->nodes[p].named_children < 2) continue;
    if (st->sib_group_members_count >= SIB_MEMBERS_HARD_CAP) break;

    /* Collect direct children of p in source order (DFS order already is). */
    uint32_t kids_start = st->sib_group_members_count;
    uint32_t kids_count = 0;
    for (uint32_t c = p + 1; c < st->node_count; c++) {
      if (st->nodes[c].start_byte >= st->nodes[p].end_byte) break;
      if (st->nodes[c].parent_idx != p) continue;
      GROW_ARRAY(st->sib_group_members, st->sib_group_members_count,
                 st->sib_group_members_cap, uint32_t, 256);
      st->sib_group_members[st->sib_group_members_count++] = c;
      kids_count++;
    }
    if (kids_count < 2) {
      st->sib_group_members_count = kids_start;
      continue;
    }

    /* Stable insertion sort by symbol; same-symbol children keep their
       relative (source) order, so contiguous runs are contiguous in bytes. */
    uint32_t *kids = &st->sib_group_members[kids_start];
    for (uint32_t a = 1; a < kids_count; a++) {
      uint32_t v = kids[a];
      TSSymbol sv = st->nodes[v].symbol;
      uint32_t b = a;
      while (b > 0 && st->nodes[kids[b - 1]].symbol > sv) {
        kids[b] = kids[b - 1];
        b--;
      }
      kids[b] = v;
    }

    /* Emit a group for each run of length >=2. */
    uint32_t run_start = 0;
    for (uint32_t k = 1; k <= kids_count; k++) {
      int boundary = (k == kids_count) ||
          (st->nodes[kids[k]].symbol != st->nodes[kids[run_start]].symbol);
      if (boundary) {
        uint32_t run_len = k - run_start;
        if (run_len >= 2) {
          GROW_ARRAY(st->sib_groups, st->sib_group_count,
                     st->sib_group_cap, SibGroup, 64);
          SibGroup *g = &st->sib_groups[st->sib_group_count++];
          g->parent_idx = p;
          g->symbol = st->nodes[kids[run_start]].symbol;
          g->start = kids_start + run_start;
          g->count = run_len;
        }
        run_start = k;
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Parse with caching                                                  */
/* ------------------------------------------------------------------ */

static TSTree *parse_cached(TSMutState *st, const uint8_t *buf, size_t len) {
  uint64_t h = fnv1a(buf, len);

  if (st->cached_tree && st->cached_len == len && st->cached_hash == h) {
    return st->cached_tree;
  }

  if (st->cached_tree) ts_tree_delete(st->cached_tree);

  st->cached_tree = ts_parser_parse_string(st->parser, NULL,
                                           (const char *)buf, (uint32_t)len);
  if (!st->cached_tree) {
    st->cached_len = 0;
    st->node_count = 0;
    return NULL;
  }

  st->cached_hash = h;
  st->cached_len = len;
  collect_nodes(st, st->cached_tree);
  return st->cached_tree;
}

/* Parse add_buf with caching (AFL++ often passes the same add_buf repeatedly) */
static void parse_add_cached(TSMutState *st, const uint8_t *add_buf,
                             size_t add_len) {
  uint64_t h = fnv1a(add_buf, add_len);
  if (st->add_tree && st->add_len == add_len && st->add_hash == h) return;

  if (st->add_tree) ts_tree_delete(st->add_tree);
  st->add_tree = ts_parser_parse_string(st->parser, NULL,
                                        (const char *)add_buf,
                                        (uint32_t)add_len);
  st->add_hash = h;
  st->add_len = add_len;
  st->add_node_count = 0;

  if (!st->add_tree) return;

  /* collect add_buf nodes */
  TSNode root = ts_tree_root_node(st->add_tree);
  TSTreeCursor cur = ts_tree_cursor_new(root);
  for (;;) {
    TSNode nd = ts_tree_cursor_current_node(&cur);
    if (ts_node_is_named(nd) && !ts_node_has_error(nd)) {
      if (st->add_node_count >= st->add_node_cap) {
        uint32_t nc = st->add_node_cap ? st->add_node_cap * 2 : 512;
        NodeInfo *p = realloc(st->add_nodes, nc * sizeof(NodeInfo));
        if (!p) break;
        st->add_nodes = p;
        st->add_node_cap = nc;
      }
      uint32_t i = st->add_node_count;
      st->add_nodes[i].start_byte = ts_node_start_byte(nd);
      st->add_nodes[i].end_byte = ts_node_end_byte(nd);
      st->add_nodes[i].symbol = ts_node_symbol(nd);
      st->add_nodes[i].parent_idx = UINT32_MAX;
      st->add_nodes[i].named_children = 0;
      st->add_node_count++;
    }
    if (ts_tree_cursor_goto_first_child(&cur)) continue;
    if (ts_tree_cursor_goto_next_sibling(&cur)) continue;
    while (ts_tree_cursor_goto_parent(&cur)) {
      if (ts_tree_cursor_goto_next_sibling(&cur)) goto add_next;
    }
    break;
    add_next:;
  }
  ts_tree_cursor_delete(&cur);
}

/* ------------------------------------------------------------------ */
/* Subtree bank                                                        */
/* ------------------------------------------------------------------ */

static int bank_entry_cmp(const void *a, const void *b) {
  const SubtreeEntry *ea = (const SubtreeEntry *)a;
  const SubtreeEntry *eb = (const SubtreeEntry *)b;
  if (ea->symbol < eb->symbol) return -1;
  if (ea->symbol > eb->symbol) return 1;
  return 0;
}

static void bank_rebuild_index(TSMutState *st) {
  if (!st->sym_index_dirty || !st->bank_count) return;

  qsort(st->bank, st->bank_count, sizeof(SubtreeEntry), bank_entry_cmp);

  memset(st->sym_index, 0, st->sym_index_size * sizeof(BankIndex));

  for (uint32_t i = 0; i < st->bank_count; i++) {
    TSSymbol s = st->bank[i].symbol;
    if (s < st->sym_index_size) {
      if (st->sym_index[s].count == 0)
        st->sym_index[s].start = i;
      st->sym_index[s].count++;
    }
  }

  st->sym_index_dirty = 0;
}

static void bank_add_subtree(TSMutState *st, TSSymbol sym,
                             const char *text, uint32_t text_len) {
  if (text_len == 0 || text_len > st->bank_max_subtree) return;

  /* grow bank array */
  if (st->bank_count >= st->bank_cap) {
    /* ring buffer: overwrite from start */
    st->bank_count = 0;
    st->arena_used = 0;
  }

  /* grow arena */
  size_t need = st->arena_used + text_len;
  if (need > st->arena_cap) {
    if (st->arena_cap >= (size_t)st->bank_cap * st->bank_max_subtree) {
      /* arena full, wrap */
      st->bank_count = 0;
      st->arena_used = 0;
    } else {
      size_t nc = st->arena_cap ? st->arena_cap * 2 : DEFAULT_ARENA_CAP;
      while (nc < need) nc <<= 1;
      char *p = realloc(st->bank_arena, nc);
      if (!p) return;
      st->bank_arena = p;
      st->arena_cap = nc;
    }
  }

  uint32_t idx = st->bank_count;
  st->bank[idx].symbol = sym;
  st->bank[idx].text_offset = (uint32_t)st->arena_used;
  st->bank[idx].text_len = text_len;
  memcpy(st->bank_arena + st->arena_used, text, text_len);
  st->arena_used += text_len;
  st->bank_count++;
  st->sym_index_dirty = 1;
}

/* ------------------------------------------------------------------ */
/* Mutation implementations                                            */
/* ------------------------------------------------------------------ */

/* 0: Delete a named subtree */
static size_t mut_subtree_delete(TSMutState *st, const uint8_t *buf,
                                 size_t len, size_t max_size) {
  if (!st->node_count) return 0;

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    uint32_t i = rng_below(st, st->node_count);
    NodeInfo *n = &st->nodes[i];

    /* skip root node and zero-length nodes */
    if (n->parent_idx == UINT32_MAX) continue;
    if (n->start_byte >= n->end_byte) continue;

    size_t new_len = len - (n->end_byte - n->start_byte);
    if (new_len == 0 || new_len > max_size) continue;

    return splice_output(st, buf, len, n->start_byte, NULL, 0,
                         n->end_byte, max_size);
  }
  return 0;
}

/* 1: Replace a subtree with a type-compatible one from the bank */
static size_t mut_subtree_replace_bank(TSMutState *st, const uint8_t *buf,
                                       size_t len, size_t max_size) {
  if (!st->node_count || !st->bank_count) return 0;
  if (!st->chaos_active) bank_rebuild_index(st);

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    uint32_t i = rng_below(st, st->node_count);
    NodeInfo *n = &st->nodes[i];

    SubtreeEntry *e;
    if (st->chaos_active) {
      /* pick any bank entry regardless of symbol — deliberately breaks
         type-safety to stress parse-error recovery paths */
      e = &st->bank[rng_below(st, st->bank_count)];
    } else {
      TSSymbol sym = n->symbol;
      if (sym >= st->sym_index_size) continue;
      BankIndex *bi = &st->sym_index[sym];
      if (bi->count == 0) continue;
      e = &st->bank[bi->start + rng_below(st, bi->count)];
    }

    const uint8_t *repl = (const uint8_t *)(st->bank_arena + e->text_offset);
    return splice_output(st, buf, len, n->start_byte, repl, e->text_len,
                         n->end_byte, max_size);
  }
  return 0;
}

/* 2: Replace a subtree with a type-compatible one from add_buf (cached) */
static size_t mut_subtree_replace_add(TSMutState *st, const uint8_t *buf,
                                      size_t len, const uint8_t *add_buf,
                                      size_t add_len, size_t max_size) {
  if (!st->node_count || !add_buf || add_len == 0) return 0;

  parse_add_cached(st, add_buf, add_len);
  if (!st->add_node_count) return 0;

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    uint32_t ti = rng_below(st, st->node_count);
    NodeInfo *target = &st->nodes[ti];

    if (st->chaos_active) {
      /* pick any add_buf node regardless of symbol */
      uint32_t ai = rng_below(st, st->add_node_count);
      uint32_t astart = st->add_nodes[ai].start_byte;
      uint32_t aend = st->add_nodes[ai].end_byte;
      if (aend > astart && aend <= add_len) {
        return splice_output(st, buf, len, target->start_byte,
                             add_buf + astart, aend - astart,
                             target->end_byte, max_size);
      }
      continue;
    }

    TSSymbol sym = target->symbol;
    uint32_t start = rng_below(st, st->add_node_count);
    for (uint32_t j = 0; j < st->add_node_count; j++) {
      uint32_t ai = (start + j) % st->add_node_count;
      if (st->add_nodes[ai].symbol == sym) {
        uint32_t astart = st->add_nodes[ai].start_byte;
        uint32_t aend = st->add_nodes[ai].end_byte;
        if (aend > astart && aend <= add_len) {
          return splice_output(st, buf, len, target->start_byte,
                               add_buf + astart, aend - astart,
                               target->end_byte, max_size);
        }
      }
    }
  }
  return 0;
}

/* 3: Swap two named siblings of the same symbol (pre-computed pairs) */
static size_t mut_sibling_swap(TSMutState *st, const uint8_t *buf,
                               size_t len, size_t max_size) {
  if (!st->sib_count) return 0;

  SibPair *p = &st->sib_pairs[rng_below(st, st->sib_count)];
  NodeInfo *a = &st->nodes[p->a];
  NodeInfo *b = &st->nodes[p->b];

  uint32_t a_len = a->end_byte - a->start_byte;
  uint32_t b_len = b->end_byte - b->start_byte;
  size_t new_len = len - a_len - b_len + b_len + a_len;
  if (new_len > max_size) return 0;

  ensure_out(st, new_len);
  if (st->out_cap < new_len) return 0;

  uint8_t *o = st->out_buf;
  size_t pos = 0;

  memcpy(o + pos, buf, a->start_byte);
  pos += a->start_byte;
  memcpy(o + pos, buf + b->start_byte, b_len);
  pos += b_len;
  memcpy(o + pos, buf + a->end_byte, b->start_byte - a->end_byte);
  pos += b->start_byte - a->end_byte;
  memcpy(o + pos, buf + a->start_byte, a_len);
  pos += a_len;
  memcpy(o + pos, buf + b->end_byte, len - b->end_byte);
  pos += len - b->end_byte;

  return pos;
}

/* 4: Replace a node with a descendant of the same type (always shrinks) */
static size_t mut_recursive_shrink(TSMutState *st, const uint8_t *buf,
                                   size_t len, size_t max_size) {
  if (st->node_count < 2) return 0;

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    uint32_t i = rng_below(st, st->node_count);
    NodeInfo *outer = &st->nodes[i];
    if (outer->named_children == 0) continue;

    /* find a descendant with same symbol but strictly contained */
    uint32_t best = UINT32_MAX;
    for (uint32_t j = i + 1; j < st->node_count; j++) {
      NodeInfo *inner = &st->nodes[j];
      if (inner->start_byte >= outer->end_byte) break;  /* past our subtree in DFS */
      if (inner->end_byte > outer->end_byte) continue;  /* not a descendant */
      if (inner->symbol == outer->symbol &&
          (inner->end_byte - inner->start_byte) <
          (outer->end_byte - outer->start_byte)) {
        best = j;
        break;
      }
    }
    if (best == UINT32_MAX) continue;

    NodeInfo *inner = &st->nodes[best];
    return splice_output(st, buf, len, outer->start_byte,
                         buf + inner->start_byte,
                         inner->end_byte - inner->start_byte,
                         outer->end_byte, max_size);
  }
  return 0;
}

/* Parse a numeric leaf. Returns 1 on success (value in *out), 0 otherwise.
   Handles plain decimal and 0x/0X hex; ignores malformed tails by treating
   them as failures. `text` is not null-terminated. */
static int ts_lit_parse_current(const char *text, uint32_t nlen,
                                int64_t *out) {
  char tmp[32];
  if (nlen == 0 || nlen >= sizeof(tmp)) return 0;
  memcpy(tmp, text, nlen);
  tmp[nlen] = '\0';

  const char *p = tmp;
  int base = 10;
  if (nlen > 2 && tmp[0] == '0' && (tmp[1] == 'x' || tmp[1] == 'X')) {
    base = 16;
    p = tmp + 2;
  }
  errno = 0;
  char *end = NULL;
  long long v = strtoll(p, &end, base);
  if (errno == ERANGE || end == p) return 0;
  *out = (int64_t)v;
  return 1;
}

/* Format an int64 into `out` as either decimal or hex (25% hex). Returns
   bytes written (not including NUL). */
static size_t ts_lit_emit_int(TSMutState *st, int64_t v,
                              char *out, size_t out_cap) {
  if (rng_below(st, 4) == 0) {
    uint64_t u = (uint64_t)v;
    return (size_t)snprintf(out, out_cap, "0x%llx", (unsigned long long)u);
  }
  return (size_t)snprintf(out, out_cap, "%lld", (long long)v);
}

/* 5: Replace a leaf node with a random literal (language-agnostic heuristic) */
static size_t mut_literal_replace(TSMutState *st, const uint8_t *buf,
                                  size_t len, size_t max_size) {
  if (!st->leaf_count) return 0;

  NodeInfo *n = &st->nodes[st->leaf_idx[rng_below(st, st->leaf_count)]];
  uint32_t nlen = n->end_byte - n->start_byte;
  const char *text = (const char *)(buf + n->start_byte);

  char repl[128];
  size_t repl_len = 0;

  if (nlen > 0 && (text[0] >= '0' && text[0] <= '9')) {
    /* numeric: mix of boundary values, deltas, random, and wide literals */
    int64_t cur = 0;
    int have_cur = ts_lit_parse_current(text, nlen, &cur);

    uint32_t pick = rng_below(st, 100);
    /* If we couldn't parse the current value, the delta path can't fire.
       Reroute its mass into the random-bounded range so weights stay even. */
    if (!have_cur && pick >= 40 && pick < 70) {
      pick = 70 + rng_below(st, 20);
    }

    if (pick < 40) {
      int64_t v = TS_LIT_SMALL[rng_below(st, TS_LIT_SMALL_N)];
      repl_len = ts_lit_emit_int(st, v, repl, sizeof(repl));

    } else if (pick < 70) {
      int32_t d = TS_LIT_DELTAS[rng_below(st, TS_LIT_DELTAS_N)];
      /* Unsigned math avoids signed-overflow UB; cast back for printing. */
      uint64_t uc = (uint64_t)cur;
      uint64_t uv;
      switch (rng_below(st, 6)) {
        case 0:  uv = uc + (uint64_t)(uint32_t)d; break;
        case 1:  uv = uc - (uint64_t)(uint32_t)d; break;
        case 2:  uv = uc << 1; break;
        case 3:  uv = uc >> 1; break;
        case 4:  uv = uc ^ 0xFFull; break;
        default: uv = uc ^ 0xFFFFFFFFull; break;
      }
      repl_len = ts_lit_emit_int(st, (int64_t)uv, repl, sizeof(repl));

    } else if (pick < 90) {
      /* preserved original random-bounded path */
      if (rng_below(st, 4) == 0) {
        unsigned v = 1u + rng_below(st, 0xFFFF);
        repl_len = (size_t)snprintf(repl, sizeof(repl), "0x%X", v);
      } else {
        unsigned v = rng_below(st, 100000u);
        repl_len = (size_t)snprintf(repl, sizeof(repl), "%u", v);
      }

    } else {
      /* wide literal, emitted verbatim */
      const char *s = TS_LIT_BIG[rng_below(st, TS_LIT_BIG_N)];
      size_t slen = strlen(s);
      if (slen >= sizeof(repl)) slen = sizeof(repl) - 1;
      memcpy(repl, s, slen);
      repl_len = slen;
    }
  } else if (nlen > 0 && (text[0] == '"' || text[0] == '\'')) {
    /* string: empty/minimal, format specifiers, control bytes,
       embedded quote/backslash, numeric specials, BOM-ish */
    static const char *samples[] = {
      /* empty / minimal */
      "\"\"", "\"A\"", "\"foo\"",
      /* format specifiers — lexer / printf-style surprises */
      "\"%s\"", "\"%d\"", "\"%n\"", "\"%p\"", "\"%#x\"", "\"aaaa%d%n\"",
      /* embedded control / escape bytes */
      "\"\\n\"", "\"\\r\\n\"", "\"\\0\"", "\"\\x00\"",
      "\"\\x0a\"", "\"\\x0d\"", "\"\\xff\"",
      /* embedded backslash / quote */
      "\"\\\\\"", "\"\\\"\"",
      /* Unicode escapes, including NUL and BOM */
      "\"\\u0000\"", "\"\\ufeff\"",
      /* numeric specials if the target ever parses strings as numbers */
      "\"NaN\"", "\"+inf\"", "\"-inf\"",
    };
    const size_t nsamples = sizeof(samples) / sizeof(samples[0]);
    const char *s = samples[rng_below(st, nsamples)];
    repl_len = strlen(s);
    if (repl_len >= sizeof(repl)) repl_len = sizeof(repl) - 1;
    memcpy(repl, s, repl_len);
  } else if (nlen >= 4 && memcmp(text, "true", 4) == 0) {
    memcpy(repl, "false", 5); repl_len = 5;
  } else if (nlen >= 5 && memcmp(text, "false", 5) == 0) {
    memcpy(repl, "true", 4); repl_len = 4;
  } else if (nlen >= 4 && memcmp(text, "null", 4) == 0) {
    memcpy(repl, "0", 1); repl_len = 1;
  } else {
    /* identifier -- pick random short name */
    static const char *ids[] = {"x", "y", "_", "tmp", "val", "a", "b"};
    const char *s = ids[rng_below(st, 7)];
    repl_len = strlen(s);
    memcpy(repl, s, repl_len);
  }

  if (repl_len == 0) return 0;
  repl[repl_len] = '\0';

  return splice_output(st, buf, len, n->start_byte, (const uint8_t *)repl,
                       repl_len, n->end_byte, max_size);
}

/* 6: Duplicate a child node (insert copy adjacent) */
static size_t mut_subtree_duplicate(TSMutState *st, const uint8_t *buf,
                                    size_t len, size_t max_size) {
  if (st->node_count < 2) return 0;

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    uint32_t i = rng_below(st, st->node_count);
    NodeInfo *n = &st->nodes[i];
    if (n->parent_idx == UINT32_MAX) continue;

    uint32_t nlen = n->end_byte - n->start_byte;
    if (nlen == 0 || len + nlen > max_size) continue;

    /* insert copy right after the node */
    ensure_out(st, len + nlen);
    if (st->out_cap < len + nlen) return 0;

    memcpy(st->out_buf, buf, n->end_byte);
    memcpy(st->out_buf + n->end_byte, buf + n->start_byte, nlen);
    memcpy(st->out_buf + n->end_byte + nlen, buf + n->end_byte,
           len - n->end_byte);
    return len + nlen;
  }
  return 0;
}

/* 7: Insert a type-compatible bank subtree adjacent to a node (grows input) */
static size_t mut_bank_insert(TSMutState *st, const uint8_t *buf,
                              size_t len, size_t max_size) {
  if (!st->node_count || !st->bank_count) return 0;
  bank_rebuild_index(st);

  /* hard cap: don't more than double the input in one mutation */
  size_t growth_limit = len * 2;
  if (growth_limit > max_size) growth_limit = max_size;

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    uint32_t i = rng_below(st, st->node_count);
    NodeInfo *n = &st->nodes[i];
    if (n->parent_idx == UINT32_MAX) continue;
    TSSymbol sym = n->symbol;

    if (sym >= st->sym_index_size) continue;
    BankIndex *bi = &st->sym_index[sym];
    if (bi->count == 0) continue;

    SubtreeEntry *e = &st->bank[bi->start + rng_below(st, bi->count)];

    size_t new_len = len + e->text_len;
    if (new_len > growth_limit) continue;

    const uint8_t *ins = (const uint8_t *)(st->bank_arena + e->text_offset);
    ensure_out(st, new_len);
    if (st->out_cap < new_len) return 0;

    memcpy(st->out_buf, buf, n->end_byte);
    memcpy(st->out_buf + n->end_byte, ins, e->text_len);
    memcpy(st->out_buf + n->end_byte + e->text_len,
           buf + n->end_byte, len - n->end_byte);
    return new_len;
  }
  return 0;
}

/* 8: Range splice. Pick a sibling group (>=2 same-symbol children under one
      parent), pick a contiguous destination slice of that group, then replace
      those bytes with either a slice of same-symbol nodes drawn from add_buf
      or a concatenation of 1..3 same-symbol bank entries. */
static size_t mut_range_splice(TSMutState *st, const uint8_t *buf, size_t len,
                               const uint8_t *add_buf, size_t add_len,
                               size_t max_size) {
  if (!st->sib_group_count) return 0;
  if (!st->range_scratch || !st->range_scratch_cap) return 0;

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    SibGroup *g = &st->sib_groups[rng_below(st, st->sib_group_count)];
    uint32_t *members = &st->sib_group_members[g->start];

    /* Destination slice [di, dj) inside the group. */
    uint32_t di = rng_below(st, g->count);
    uint32_t dj = di + 1 + rng_below(st, g->count - di);
    NodeInfo *first = &st->nodes[members[di]];
    NodeInfo *last  = &st->nodes[members[dj - 1]];
    uint32_t dst_start = first->start_byte;
    uint32_t dst_end   = last->end_byte;
    if (dst_end <= dst_start) continue;

    const uint8_t *src_ptr = NULL;
    uint32_t src_len = 0;

    /* Prefer add_buf when available and coin-flip favorable. */
    int use_add = add_buf && add_len && (rng_below(st, 2) == 0);
    if (use_add) {
      parse_add_cached(st, add_buf, add_len);
      if (!st->add_node_count) use_add = 0;
    }

    if (use_add) {
      uint32_t found = UINT32_MAX;
      if (st->chaos_active) {
        /* any node, any symbol */
        found = rng_below(st, st->add_node_count);
      } else {
        TSSymbol want = g->symbol;
        uint32_t pick = rng_below(st, st->add_node_count);
        for (uint32_t k = 0; k < st->add_node_count; k++) {
          uint32_t idx = (pick + k) % st->add_node_count;
          if (st->add_nodes[idx].symbol == want) { found = idx; break; }
        }
      }
      if (found != UINT32_MAX) {
        uint32_t s_start = st->add_nodes[found].start_byte;
        uint32_t s_end   = st->add_nodes[found].end_byte;
        if (!st->chaos_active) {
          uint32_t want_runs = 1 + rng_below(st, 3);
          uint32_t runs = 1;
          TSSymbol want = g->symbol;
          for (uint32_t k = found + 1;
               k < st->add_node_count && runs < want_runs; k++) {
            if (st->add_nodes[k].symbol != want) continue;
            if (st->add_nodes[k].start_byte < s_end) continue; /* nested */
            s_end = st->add_nodes[k].end_byte;
            runs++;
          }
        }
        if (s_end <= add_len && s_end > s_start) {
          src_ptr = add_buf + s_start;
          src_len = s_end - s_start;
        }
      }
    }

    if (!src_ptr) {
      /* Fall back to the bank: stitch 1..3 entries into scratch. Chaos
         mode draws any entries; normal mode matches g->symbol. */
      if (!st->bank_count) continue;

      BankIndex *bi = NULL;
      if (!st->chaos_active) {
        bank_rebuild_index(st);
        if (g->symbol >= st->sym_index_size) continue;
        bi = &st->sym_index[g->symbol];
        if (bi->count == 0) continue;
      }

      uint32_t n_take = 1 + rng_below(st, 3);
      uint32_t acc = 0;
      for (uint32_t k = 0; k < n_take; k++) {
        SubtreeEntry *e;
        if (st->chaos_active) {
          e = &st->bank[rng_below(st, st->bank_count)];
        } else {
          e = &st->bank[bi->start + rng_below(st, bi->count)];
        }
        uint32_t need = e->text_len + (k > 0 ? 1 : 0);
        if (acc + need > st->range_scratch_cap) break;
        if (k > 0) st->range_scratch[acc++] = ' ';
        memcpy(st->range_scratch + acc,
               st->bank_arena + e->text_offset, e->text_len);
        acc += e->text_len;
      }
      if (!acc) continue;
      src_ptr = st->range_scratch;
      src_len = acc;
    }

    return splice_output(st, buf, len, dst_start, src_ptr, src_len,
                         dst_end, max_size);
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Weighted strategy selection                                         */
/* ------------------------------------------------------------------ */

static int select_strategy(TSMutState *st) {
  uint32_t r = rng_below(st, st->weight_sum);
  uint32_t cumulative = 0;
  for (int i = 0; i < MUT_COUNT; i++) {
    cumulative += st->weights[i];
    if (r < cumulative) return i;
  }
  return MUT_COUNT - 1;
}

/* Run one mutation. Returns new length, 0 on failure. */
static size_t apply_mutation(TSMutState *st, const uint8_t *buf, size_t len,
                             const uint8_t *add_buf, size_t add_len,
                             size_t max_size) {
  /* Chaos delegation targets: the three bank/add/range strategies. */
  static const int chaos_targets[3] = {
    MUT_SUBTREE_REPLACE_BANK,
    MUT_SUBTREE_REPLACE_ADD,
    MUT_RANGE_SPLICE,
  };

  for (int retry = 0; retry < MAX_RETRIES; retry++) {
    int strat = select_strategy(st);
    int chaos = 0;
    if (strat == MUT_CHAOS) {
      chaos = 1;
      strat = chaos_targets[rng_below(st, 3)];
    }
    st->chaos_active = (uint8_t)chaos;

    size_t result = 0;
    switch (strat) {
      case MUT_SUBTREE_DELETE:
        result = mut_subtree_delete(st, buf, len, max_size);
        break;
      case MUT_SUBTREE_REPLACE_BANK:
        result = mut_subtree_replace_bank(st, buf, len, max_size);
        break;
      case MUT_SUBTREE_REPLACE_ADD:
        result = mut_subtree_replace_add(st, buf, len, add_buf, add_len,
                                         max_size);
        break;
      case MUT_SIBLING_SWAP:
        result = mut_sibling_swap(st, buf, len, max_size);
        break;
      case MUT_RECURSIVE_SHRINK:
        result = mut_recursive_shrink(st, buf, len, max_size);
        break;
      case MUT_LITERAL_REPLACE:
        result = mut_literal_replace(st, buf, len, max_size);
        break;
      case MUT_SUBTREE_DUPLICATE:
        result = mut_subtree_duplicate(st, buf, len, max_size);
        break;
      case MUT_BANK_INSERT:
        result = mut_bank_insert(st, buf, len, max_size);
        break;
      case MUT_RANGE_SPLICE:
        result = mut_range_splice(st, buf, len, add_buf, add_len, max_size);
        break;
    }
    st->chaos_active = 0;

    if (result) {
      st->last_mutation = chaos ? MUT_CHAOS : strat;
      return result;
    }
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Config parsing helpers                                              */
/* ------------------------------------------------------------------ */

static void parse_weights(TSMutState *st, const char *str) {
  if (!str) return;
  uint32_t w[MUT_COUNT];
  int n = sscanf(str, "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
                 &w[0], &w[1], &w[2], &w[3], &w[4], &w[5], &w[6], &w[7],
                 &w[8], &w[9]);
  if (n == MUT_COUNT) {
    memcpy(st->weights, w, sizeof(w));
    st->weight_sum = 0;
    for (int i = 0; i < MUT_COUNT; i++) st->weight_sum += st->weights[i];
  }
}

/* Derive function name from .so path: libtree-sitter-foo.so -> tree_sitter_foo */
static void derive_func_name(const char *path, char *out, size_t out_size) {
  const char *base = strrchr(path, '/');
  base = base ? base + 1 : path;

  /* strip lib prefix */
  if (strncmp(base, "lib", 3) == 0) base += 3;

  size_t len = strlen(base);
  /* strip .so suffix */
  const char *dot = strstr(base, ".so");
  if (dot) len = (size_t)(dot - base);

  if (len >= out_size) len = out_size - 1;
  for (size_t i = 0; i < len; i++) {
    out[i] = (base[i] == '-') ? '_' : base[i];
  }
  out[len] = '\0';
}

/* ------------------------------------------------------------------ */
/* AFL++ API                                                           */
/* ------------------------------------------------------------------ */

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  TSMutState *st = calloc(1, sizeof(TSMutState));
  if (!st) FATAL("ts mutator: calloc failed");

  st->rng = seed ? (uint64_t)seed : 1;
  st->last_mutation = -1;

  /* -- load grammar via dlopen -- */
  const char *grammar_path = getenv("TS_GRAMMAR");
  if (!grammar_path || !grammar_path[0]) {
    FATAL("ts mutator: TS_GRAMMAR not set. "
          "Set it to the path of a tree-sitter grammar .so "
          "(e.g., /usr/lib/libtree-sitter-javascript.so)");
  }

  st->grammar_handle = dlopen(grammar_path, RTLD_NOW);
  if (!st->grammar_handle) {
    FATAL("ts mutator: dlopen(%s) failed: %s", grammar_path, dlerror());
  }

  /* resolve language function */
  char func_name[256];
  const char *func_env = getenv("TS_LANG_FUNC");
  if (func_env && func_env[0]) {
    snprintf(func_name, sizeof(func_name), "%s", func_env);
  } else {
    derive_func_name(grammar_path, func_name, sizeof(func_name));
  }

  typedef const TSLanguage *(*lang_fn_t)(void);
  lang_fn_t lang_fn = (lang_fn_t)dlsym(st->grammar_handle, func_name);
  if (!lang_fn) {
    FATAL("ts mutator: dlsym(%s) failed: %s. "
          "Set TS_LANG_FUNC to the correct symbol name.",
          func_name, dlerror());
  }

  st->lang = lang_fn();
  st->parser = ts_parser_new();
  if (!ts_parser_set_language(st->parser, st->lang)) {
    FATAL("ts mutator: ABI version mismatch. Grammar version %u, "
          "library supports %u-%u.",
          ts_language_abi_version(st->lang),
          TREE_SITTER_MIN_COMPATIBLE_LANGUAGE_VERSION,
          TREE_SITTER_LANGUAGE_VERSION);
  }

  /* -- init bank -- */
  const char *bank_size_str = getenv("TS_BANK_SIZE");
  st->bank_cap = bank_size_str ? (uint32_t)atoi(bank_size_str) : DEFAULT_BANK_CAP;
  if (st->bank_cap == 0) st->bank_cap = DEFAULT_BANK_CAP;
  st->bank = calloc(st->bank_cap, sizeof(SubtreeEntry));

  const char *max_sub_str = getenv("TS_BANK_MAX_SUBTREE");
  st->bank_max_subtree = max_sub_str ? (uint32_t)atoi(max_sub_str)
                                     : DEFAULT_BANK_MAX_SUB;
  if (st->bank_max_subtree == 0) st->bank_max_subtree = DEFAULT_BANK_MAX_SUB;

  st->sym_index_size = ts_language_symbol_count(st->lang);
  st->sym_index = calloc(st->sym_index_size, sizeof(BankIndex));

  /* Range-splice scratch: enough to stitch ~3 max-size bank entries + seps. */
  st->range_scratch_cap = st->bank_max_subtree * 4;
  st->range_scratch = malloc(st->range_scratch_cap);
  if (!st->range_scratch) st->range_scratch_cap = 0;

  /* -- init weights -- */
  memcpy(st->weights, default_weights, sizeof(default_weights));
  st->weight_sum = 0;
  for (int i = 0; i < MUT_COUNT; i++) st->weight_sum += st->weights[i];
  parse_weights(st, getenv("TS_WEIGHTS"));

  const char *hp = getenv("TS_HAVOC_PROB");
  st->havoc_prob = hp ? (uint8_t)atoi(hp) : DEFAULT_HAVOC_PROB;

  /* -- init stacking -- */
  st->stack_max = 1;
  st->last_stack_depth = 1;
  const char *sm = getenv("TS_STACK_MAX");
  if (sm && sm[0]) {
    long v = strtol(sm, NULL, 10);
    if (v < 1) v = 1;
    if (v > TS_STACK_HARD_CAP) {
      WARNF("ts mutator: TS_STACK_MAX=%ld clamped to %d",
            v, TS_STACK_HARD_CAP);
      v = TS_STACK_HARD_CAP;
    }
    st->stack_max = (uint32_t)v;
  }
  if (st->stack_max > 1) {
    st->stack_scratch_cap = 65536;
    st->stack_scratch = malloc(st->stack_scratch_cap);
    if (!st->stack_scratch) {
      st->stack_scratch_cap = 0;
      st->stack_max = 1;
    }
  }

  OKF("ts mutator: loaded grammar %s (func=%s, symbols=%u, bank_cap=%u)",
      grammar_path, func_name, st->sym_index_size, st->bank_cap);

  (void)afl;
  return st;
}

uint32_t afl_custom_fuzz_count(void *data, const uint8_t *buf,
                               size_t buf_size) {
  TSMutState *st = (TSMutState *)data;

  /* pre-parse and cache */
  TSTree *tree = parse_cached(st, buf, buf_size);
  if (!tree || !st->node_count) return 1;

  uint32_t count = st->node_count * 2;
  if (count > 128) count = 128;
  if (count < 4) count = 4;
  return count;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {
  TSMutState *st = (TSMutState *)data;
  st->last_stack_depth = 1;

  TSTree *tree = parse_cached(st, buf, buf_size);
  if (!tree || !st->node_count) {
    *out_buf = buf;
    return buf_size;
  }

  /* Fast path: exactly the original single-mutation behavior. */
  if (st->stack_max <= 1) {
    size_t result = apply_mutation(st, buf, buf_size, add_buf, add_buf_size,
                                   max_size);
    if (result) { *out_buf = st->out_buf; return result; }
    *out_buf = buf;
    return buf_size;
  }

  /* Stacked path: uniform random depth in [1, stack_max]. */
  uint32_t target = 1 + rng_below(st, st->stack_max);

  size_t cur_len = apply_mutation(st, buf, buf_size, add_buf, add_buf_size,
                                  max_size);
  if (!cur_len) { *out_buf = buf; return buf_size; }
  uint32_t done = 1;

  for (uint32_t step = 1; step < target; step++) {
    if (cur_len > st->stack_scratch_cap) {
      size_t nc = st->stack_scratch_cap ? st->stack_scratch_cap : 65536;
      while (nc < cur_len) nc <<= 1;
      uint8_t *np = realloc(st->stack_scratch, nc);
      if (!np) break;
      st->stack_scratch = np;
      st->stack_scratch_cap = nc;
    }
    memcpy(st->stack_scratch, st->out_buf, cur_len);

    TSTree *t2 = parse_cached(st, st->stack_scratch, cur_len);
    if (!t2 || !st->node_count) break;

    size_t next_len = apply_mutation(st, st->stack_scratch, cur_len,
                                     add_buf, add_buf_size, max_size);
    if (!next_len) break;
    cur_len = next_len;
    done++;
  }

  st->last_stack_depth = done;
  *out_buf = st->out_buf;
  return cur_len;
}

size_t afl_custom_havoc_mutation(void *data, uint8_t *buf, size_t buf_size,
                                 uint8_t **out_buf, size_t max_size) {
  TSMutState *st = (TSMutState *)data;

  TSTree *tree = parse_cached(st, buf, buf_size);
  if (!tree || !st->node_count) {
    *out_buf = buf;
    return buf_size;
  }

  /* havoc mode: skip add_buf-based splicing. Chaos in havoc can only
     target bank + range (no add_buf available). Stacking is intentionally
     disabled here — AFL's per-execution havoc loop already stacks mutations
     externally, and doubling it here would just amplify noise. */
  static const int chaos_havoc_targets[2] = {
    MUT_SUBTREE_REPLACE_BANK,
    MUT_RANGE_SPLICE,
  };

  size_t result = 0;
  int chaos = 0;
  for (int retry = 0; retry < MAX_RETRIES && !result; retry++) {
    int strat = select_strategy(st);
    if (strat == MUT_SUBTREE_REPLACE_ADD) continue;
    chaos = 0;
    if (strat == MUT_CHAOS) {
      chaos = 1;
      strat = chaos_havoc_targets[rng_below(st, 2)];
    }
    st->chaos_active = (uint8_t)chaos;

    switch (strat) {
      case MUT_SUBTREE_DELETE:
        result = mut_subtree_delete(st, buf, buf_size, max_size);
        break;
      case MUT_SUBTREE_REPLACE_BANK:
        result = mut_subtree_replace_bank(st, buf, buf_size, max_size);
        break;
      case MUT_SIBLING_SWAP:
        result = mut_sibling_swap(st, buf, buf_size, max_size);
        break;
      case MUT_RECURSIVE_SHRINK:
        result = mut_recursive_shrink(st, buf, buf_size, max_size);
        break;
      case MUT_LITERAL_REPLACE:
        result = mut_literal_replace(st, buf, buf_size, max_size);
        break;
      case MUT_SUBTREE_DUPLICATE:
        result = mut_subtree_duplicate(st, buf, buf_size, max_size);
        break;
      case MUT_BANK_INSERT:
        result = mut_bank_insert(st, buf, buf_size, max_size);
        break;
      case MUT_RANGE_SPLICE:
        result = mut_range_splice(st, buf, buf_size, NULL, 0, max_size);
        break;
    }
    st->chaos_active = 0;
  }

  if (result) {
    st->last_mutation = chaos ? MUT_CHAOS : -1;
    *out_buf = st->out_buf;
    return result;
  }

  *out_buf = buf;
  return buf_size;
}

uint8_t afl_custom_havoc_mutation_probability(void *data) {
  TSMutState *st = (TSMutState *)data;
  return st->havoc_prob;
}

uint8_t afl_custom_queue_get(void *data, const uint8_t *filename) {
  /* We fuzz everything. Pre-parsing happens in fuzz_count. */
  (void)data;
  (void)filename;
  return 1;
}

uint8_t afl_custom_queue_new_entry(void *data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {
  TSMutState *st = (TSMutState *)data;
  (void)filename_orig_queue;

  /* read the new file */
  int fd = open((const char *)filename_new_queue, O_RDONLY);
  if (fd < 0) return 0;

  struct stat sb;
  if (fstat(fd, &sb) < 0 || sb.st_size <= 0 || sb.st_size > (1 << 20)) {
    close(fd);
    return 0;
  }

  char *file_buf = malloc((size_t)sb.st_size);
  if (!file_buf) { close(fd); return 0; }

  ssize_t rd = read(fd, file_buf, (size_t)sb.st_size);
  close(fd);
  if (rd <= 0) { free(file_buf); return 0; }

  /* parse it */
  TSTree *tree = ts_parser_parse_string(st->parser, NULL, file_buf,
                                        (uint32_t)rd);
  if (!tree) { free(file_buf); return 0; }

  /* DFS and bank named subtrees */
  TSNode root = ts_tree_root_node(tree);
  TSTreeCursor cur = ts_tree_cursor_new(root);

  for (;;) {
    TSNode nd = ts_tree_cursor_current_node(&cur);
    if (ts_node_is_named(nd) && !ts_node_has_error(nd)) {
      uint32_t sb_val = ts_node_start_byte(nd);
      uint32_t eb = ts_node_end_byte(nd);
      uint32_t nlen = eb - sb_val;
      if (nlen > 0 && nlen <= st->bank_max_subtree && eb <= (uint32_t)rd) {
        bank_add_subtree(st, ts_node_symbol(nd), file_buf + sb_val, nlen);
      }
    }
    if (ts_tree_cursor_goto_first_child(&cur)) continue;
    if (ts_tree_cursor_goto_next_sibling(&cur)) continue;
    while (ts_tree_cursor_goto_parent(&cur)) {
      if (ts_tree_cursor_goto_next_sibling(&cur)) goto bank_next;
    }
    break;
    bank_next:;
  }

  ts_tree_cursor_delete(&cur);
  ts_tree_delete(tree);
  free(file_buf);

  return 0;  /* 0 = we did NOT modify the file */
}

const char *afl_custom_describe(void *data, size_t max_description_len) {
  TSMutState *st = (TSMutState *)data;
  if (st->last_stack_depth > 1) {
    snprintf(st->desc_buf, sizeof(st->desc_buf), "ts-stack%u",
             st->last_stack_depth);
  } else if (st->last_mutation >= 0 && st->last_mutation < MUT_COUNT) {
    snprintf(st->desc_buf, sizeof(st->desc_buf), "%s",
             mut_names[st->last_mutation]);
  } else {
    snprintf(st->desc_buf, sizeof(st->desc_buf), "ts-nop");
  }
  (void)max_description_len;
  return st->desc_buf;
}

void afl_custom_deinit(void *data) {
  TSMutState *st = (TSMutState *)data;

  OKF("ts mutator stats: bank=%u subtrees", st->bank_count);

  if (st->cached_tree) ts_tree_delete(st->cached_tree);
  if (st->add_tree) ts_tree_delete(st->add_tree);
  if (st->parser) ts_parser_delete(st->parser);
  if (st->grammar_handle) dlclose(st->grammar_handle);

  free(st->out_buf);
  free(st->nodes);
  free(st->add_nodes);
  free(st->leaf_idx);
  free(st->sib_pairs);
  free(st->sib_groups);
  free(st->sib_group_members);
  free(st->range_scratch);
  free(st->stack_scratch);
  free(st->bank);
  free(st->bank_arena);
  free(st->sym_index);
  free(st);
}
