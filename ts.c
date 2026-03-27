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
#define MUT_COUNT              8

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
};

static const char *mut_names[MUT_COUNT] = {
    "ts-del", "ts-bank", "ts-add", "ts-swap",
    "ts-shrink", "ts-lit", "ts-dup", "ts-ins",
};

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
  bank_rebuild_index(st);

  for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    uint32_t i = rng_below(st, st->node_count);
    NodeInfo *n = &st->nodes[i];
    TSSymbol sym = n->symbol;

    if (sym >= st->sym_index_size) continue;
    BankIndex *bi = &st->sym_index[sym];
    if (bi->count == 0) continue;

    SubtreeEntry *e = &st->bank[bi->start + rng_below(st, bi->count)];
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
    TSSymbol sym = target->symbol;

    /* find matching node in cached add_buf nodes */
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
    /* numeric */
    if (rng_below(st, 4) == 0) {
      unsigned v = 1u + rng_below(st, 0xFFFF);
      repl_len = (size_t)snprintf(repl, sizeof(repl), "0x%X", v);
    } else {
      unsigned v = rng_below(st, 100000u);
      repl_len = (size_t)snprintf(repl, sizeof(repl), "%u", v);
    }
  } else if (nlen > 0 && (text[0] == '"' || text[0] == '\'')) {
    /* string */
    static const char *samples[] = {"\"\"", "\"A\"", "\"foo\"", "\"%d\"", "\"\\n\""};
    const char *s = samples[rng_below(st, 5)];
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
  for (int retry = 0; retry < MAX_RETRIES; retry++) {
    int strat = select_strategy(st);
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
    }

    if (result) {
      st->last_mutation = strat;
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
  int n = sscanf(str, "%u,%u,%u,%u,%u,%u,%u,%u",
                 &w[0], &w[1], &w[2], &w[3], &w[4], &w[5], &w[6], &w[7]);
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
          ts_language_version(st->lang),
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

  /* -- init weights -- */
  memcpy(st->weights, default_weights, sizeof(default_weights));
  st->weight_sum = 0;
  for (int i = 0; i < MUT_COUNT; i++) st->weight_sum += st->weights[i];
  parse_weights(st, getenv("TS_WEIGHTS"));

  const char *hp = getenv("TS_HAVOC_PROB");
  st->havoc_prob = hp ? (uint8_t)atoi(hp) : DEFAULT_HAVOC_PROB;

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

  TSTree *tree = parse_cached(st, buf, buf_size);
  if (!tree || !st->node_count) {
    *out_buf = buf;
    return buf_size;
  }

  size_t result = apply_mutation(st, buf, buf_size, add_buf, add_buf_size,
                                 max_size);
  if (result) {
    *out_buf = st->out_buf;
    return result;
  }

  /* fallback: identity */
  *out_buf = buf;
  return buf_size;
}

size_t afl_custom_havoc_mutation(void *data, uint8_t *buf, size_t buf_size,
                                 uint8_t **out_buf, size_t max_size) {
  TSMutState *st = (TSMutState *)data;

  TSTree *tree = parse_cached(st, buf, buf_size);
  if (!tree || !st->node_count) {
    *out_buf = buf;
    return buf_size;
  }

  /* havoc mode: skip add_buf-based splicing */
  size_t result = 0;
  for (int retry = 0; retry < MAX_RETRIES && !result; retry++) {
    int strat = select_strategy(st);
    /* skip MUT_SUBTREE_REPLACE_ADD in havoc (no add_buf available) */
    if (strat == MUT_SUBTREE_REPLACE_ADD) continue;

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
    }
  }

  if (result) {
    st->last_mutation = -1; /* set by individual mutation */
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
  if (st->last_mutation >= 0 && st->last_mutation < MUT_COUNT) {
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
  free(st->bank);
  free(st->bank_arena);
  free(st->sym_index);
  free(st);
}
