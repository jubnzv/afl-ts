# AFL++ tree-sitter splice mutator

AST-aware custom mutator for [AFL++](https://github.com/AFLplusplus/AFLplusplus/).

Uses [tree-sitter](https://tree-sitter.github.io/) to parse inputs and perform AST-level mutations inspired by [tree-splicer](https://github.com/langston-barrett/tree-splicer).

Works with any tree-sitter grammar - loaded at runtime via `dlopen`, no recompilation needed.

## Requirements

Requires tree-sitter **v0.25+** (ABI version 15). Older versions are not supported.

## Build

The mutator builds in-source-tree. Clone AFL++ sources:
```
git clone https://github.com/AFLplusplus/AFLplusplus/
```

Then clone and build this custom mutator:

```
cd AFLplusplus/custom_mutators
git clone https://github.com/jubnzv/afl-tree-sitter-splice ts
cd ts
make
```

If `pkg-config` finds tree-sitter automatically, that's all you need. Otherwise, point `TSPREFIX` to your tree-sitter install prefix:

```
make TSPREFIX=/path/to/tree-sitter-install
```

To build tree-sitter v0.25+ from source:

```
git clone https://github.com/tree-sitter/tree-sitter
cd tree-sitter && git checkout v0.25.6
make && make install PREFIX=/path/to/tree-sitter-install
```

If tree-sitter is installed to a non-standard location, set `LD_LIBRARY_PATH` at runtime:

```
export LD_LIBRARY_PATH=/path/to/tree-sitter-install/lib
```

## Usage

```
TS_GRAMMAR=/path/to/your-libtree-sitter.so \
AFL_CUSTOM_MUTATOR_LIBRARY=./libts.so \
afl-fuzz -i corpus -o out -- ./target @@
```

## Mutation strategies

| Strategy | Weight | What it does |
|---|---|---|
| `ts-del` | 20 | Delete a named AST subtree |
| `ts-bank` | 20 | Replace subtree with type-compatible one from corpus bank (`TSSymbol` match) |
| `ts-add` | 20 | Replace subtree with type-compatible one from AFL++'s `add_buf` |
| `ts-swap` | 15 | Swap two sibling nodes of the same type |
| `ts-shrink` | 10 | Replace node with a same-type descendant (always reduces size) |
| `ts-lit` | 5 | Replace leaf with random literal |
| `ts-dup` | 3 | Duplicate a subtree adjacent to itself |
| `ts-ins` | 7 | Insert a type-compatible bank subtree after a node (grows input, capped at 2x) |
| `ts-range` | 4 | Replace a contiguous run of same-symbol siblings with a same-symbol run from `add_buf` or 1..3 concatenated bank entries |
| `ts-chaos` | 2 | Bypass the type-safety filter on `ts-bank` / `ts-add` / `ts-range`: splice a random bank (or `add_buf`) node into the destination regardless of `TSSymbol`. Produces deliberately ungrammatical inputs to increase coverage. |

The subtree bank is populated via `afl_custom_queue_new_entry` as the corpus grows.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `TS_GRAMMAR` | **(required)** | Path to grammar `.so` |
| `TS_LANG_FUNC` | derived from filename | `tree_sitter_*()` symbol name |
| `TS_WEIGHTS` | `20,20,20,15,10,5,3,7,4,2` | Comma-separated strategy weights |
| `TS_BANK_SIZE` | `8192` | Max subtree bank entries |
| `TS_BANK_MAX_SUBTREE` | `256` | Max bytes per banked subtree |
| `TS_HAVOC_PROB` | `50` | Havoc mutation probability (%) |
