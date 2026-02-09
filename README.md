# FileHashSearch

Find files in a search directory and locate matching files in a target directory by SHA-256 hash, then perform batch operations on them.

## Key Features

- **File Hash Caching**: Saves file hashes and modification times to a persistent cache. Unchanged files reuse their cached hash.
- **Cache Validation**: Compares file modification times before reusing a cached hash. Changed files are automatically rehashed.
- **Duplicate Detection**: Warns when multiple source files share identical content.
- **Safe Operations**: Destructive actions require confirmation; `--dry-run` previews changes without modifying files.

## Usage

### Listing matching files (verbose mode)

```bash
python hashsearch.py /path/to/search_folder /path/to/target_folder --action list --verbose
```

### Moving matching files

```bash
python hashsearch.py /path/to/search_folder /path/to/target_folder --action move --destination /path/to/destination_folder --verbose
```

### Deleting matching files (preview with dry-run)

```bash
python hashsearch.py /path/to/search_folder /path/to/target_folder --action delete --dry-run
```

### Deleting matching files (skip confirmation)

```bash
python hashsearch.py /path/to/search_folder /path/to/target_folder --action delete --yes
```

## Options

| Flag | Description |
|------|-------------|
| `--action {move,delete,list}` | Action to perform on matching files (required) |
| `--destination PATH` | Destination folder for move action (required with `--action move`) |
| `-v, --verbose` | Increase verbosity |
| `--dry-run` | Show what would be done without performing actions |
| `--yes, -y` | Skip confirmation prompt for destructive actions |

## Cache

The hash cache is stored at `~/.filehashsearch_cache.json` and persists between runs. Only files whose modification time has changed since the last run are rehashed, ensuring speed and accuracy in repeated runs.
