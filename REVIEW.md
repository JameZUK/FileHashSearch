# Code Review: FileHashSearch

## Overview

FileHashSearch is a single-file Python CLI utility (~186 LOC) that finds files by SHA-256 hash matching across directories and performs batch operations (move, delete, list) on matches. It uses only standard library modules and includes a JSON-based hash cache for performance.

The tool is functional for its intended purpose, but there are several bugs, missing project infrastructure, and code quality items worth addressing.

---

## Bugs

### 1. Division by zero on empty directories (`hashsearch.py:66,102`)

`get_files_with_hashes` and `find_matching_files` both compute `file_count / total_time` unconditionally in their summary output. If a directory is empty or processing completes in effectively zero time, this will raise a `ZeroDivisionError` and crash the script. The verbose per-file logging already guards against this (`if elapsed_time > 0`), but the final summary lines do not.

### 2. `os.path.getmtime()` called outside try block (`hashsearch.py:46,79`)

`file_mtime = os.path.getmtime(filepath)` is called *before* the `try` block. If a file is deleted between `os.walk()` yielding its name and the `getmtime` call (a race condition), the script will crash with an unhandled `FileNotFoundError` instead of logging the error and continuing.

### 3. Source hash collisions silently drop files (`hashsearch.py:56`)

`file_hashes[file_hash] = filepath` maps hash to path, meaning if the source directory contains duplicate files (same content, different paths), only the last one scanned is retained. This silently discards duplicates with no warning. Whether this is intentional is unclear, but it can mislead the user about match counts.

### 4. `not_found_count` calculation is misleading (`hashsearch.py:174`)

```python
not_found_count = source_count - len(matching_files)
```

`source_count` is the number of files in the search folder. `matching_files` is the list of files *in the target folder* that matched. These are fundamentally different sets. This subtraction doesn't represent "files not found" in any meaningful way. For example, one source hash could match 100 target files, making `not_found_count` negative. The intended metric should be: how many source hashes had zero matches in the target.

### 5. `shutil.move` name collisions in destination (`hashsearch.py:116`)

When moving matched files to a destination directory, if multiple files share the same filename, `shutil.move` will overwrite or raise errors depending on the OS. There is no conflict resolution (e.g., renaming, skipping).

---

## Security & Safety Concerns

### 6. No confirmation for destructive actions

The `--action delete` flag permanently removes files without any confirmation prompt. A single typo in directory paths could result in unintended data loss. Consider adding a `--dry-run` mode or requiring `--confirm` for destructive operations.

### 7. Cache file permissions

`hash_cache.json` is written with default permissions and exposes the full directory structure of scanned paths. This may be a concern in shared environments.

---

## Code Quality

### 8. Duplicated hashing/caching logic

`get_files_with_hashes()` (lines 37-68) and `find_matching_files()` (lines 70-104) contain nearly identical directory traversal, caching, and hashing logic. This violates DRY and means any bug fix must be applied in two places. The shared logic should be extracted into a helper function.

### 9. Cache file uses relative path (`hashsearch.py:8`)

```python
CACHE_FILE = "hash_cache.json"
```

The cache location depends on the *current working directory*, not the script location. Running the script from different directories creates scattered cache files, and the cache from a previous run may not be found.

### 10. Floating-point mtime comparison (`hashsearch.py:35`)

```python
return current_mtime == cached_entry.get('mtime')
```

Comparing floating-point timestamps with `==` can be fragile across filesystems and JSON serialization round-trips. Some filesystems have lower mtime precision, and floating-point representation issues could cause valid caches to be invalidated unnecessarily.

---

## Missing Project Infrastructure

- **No `.gitignore`** — `hash_cache.json` and Python bytecode (`__pycache__/`, `*.pyc`) could be accidentally committed.
- **No tests** — Zero test coverage. The core hashing, caching, and matching logic would benefit from unit tests.
- **No `requirements.txt` / `pyproject.toml`** — While there are no external deps, having a minimal project config documents the Python version requirement.
- **README formatting** — The README has broken markdown formatting (missing code fences around bash examples).

---

## Summary

| Category | Issue | Severity |
|----------|-------|----------|
| Bug | Division by zero on empty dirs | High |
| Bug | `getmtime` outside try block (race condition) | Medium |
| Bug | Source duplicates silently dropped | Medium |
| Bug | `not_found_count` calculation incorrect | Medium |
| Bug | Move action name collisions | Low |
| Safety | No confirmation for delete action | Medium |
| Quality | Duplicated hashing/caching logic | Low |
| Quality | Relative cache file path | Low |
| Quality | Float mtime equality comparison | Low |
| Infra | No `.gitignore`, tests, or project config | Low |

## What's Done Well

- Clean, readable function decomposition with clear single-responsibility functions
- Streaming hash computation (4KB blocks) handles large files efficiently
- Cache validation with mtime is a good performance optimization
- Proper use of `argparse` with validation (destination required for move)
- Error handling around file operations allows partial failures without crashing
- Performance metrics reporting is a useful operational feature
