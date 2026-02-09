import hashlib
import os
import shutil
import argparse
import time
import json
import sys

CACHE_FILE = os.path.join(os.path.expanduser("~"), ".filehashsearch_cache.json")


def load_cache():
    """Loads the hash cache from a file."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    """Saves the hash cache to a file."""
    cache_dir = os.path.dirname(CACHE_FILE)
    if cache_dir and not os.path.exists(cache_dir):
        os.makedirs(cache_dir, exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)
    os.chmod(CACHE_FILE, 0o600)


def calculate_sha256(filepath):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def is_cache_valid(filepath, cached_entry):
    """Checks if a cached entry is still valid by comparing file modification times."""
    try:
        current_mtime = os.path.getmtime(filepath)
    except OSError:
        return False
    cached_mtime = cached_entry.get('mtime')
    if cached_mtime is None:
        return False
    return abs(current_mtime - cached_mtime) < 1e-6


def _hash_directory_files(directory, cache, verbose=False, label="Processed"):
    """Walk a directory, compute or retrieve cached SHA-256 hashes for every file.

    Returns:
        results: list of (filepath, file_hash) tuples
        file_count: number of files successfully processed
        total_time: elapsed wall-clock time in seconds
    """
    results = []
    file_count = 0
    start_time = time.time()

    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                file_mtime = os.path.getmtime(filepath)

                if filepath in cache and is_cache_valid(filepath, cache[filepath]):
                    file_hash = cache[filepath]['hash']
                else:
                    file_hash = calculate_sha256(filepath)
                    cache[filepath] = {'hash': file_hash, 'mtime': file_mtime}

                results.append((filepath, file_hash))
                file_count += 1

                if verbose:
                    elapsed_time = time.time() - start_time
                    rate = file_count / elapsed_time if elapsed_time > 0 else 0
                    print(f"[INFO] {label}: {filepath} | "
                          f"Files scanned: {file_count} | Rate: {rate:.2f} files/second")

            except (OSError, IOError) as e:
                print(f"[ERROR] Failed to process file {filepath}: {e}")

    total_time = time.time() - start_time
    if total_time > 0:
        avg_rate = file_count / total_time
        print(f"[INFO] Finished processing {file_count} files in {total_time:.2f} seconds. "
              f"Average rate: {avg_rate:.2f} files/second.")
    else:
        print(f"[INFO] Finished processing {file_count} files in 0.00 seconds.")

    return results, file_count, total_time


def get_files_with_hashes(directory, cache, verbose=False):
    """Returns a dictionary mapping file hashes to lists of file paths for all files in a directory."""
    results, file_count, total_time = _hash_directory_files(
        directory, cache, verbose=verbose, label="Hashed file"
    )
    file_hashes = {}
    for filepath, file_hash in results:
        file_hashes.setdefault(file_hash, []).append(filepath)

    duplicates = {h: paths for h, paths in file_hashes.items() if len(paths) > 1}
    if duplicates:
        print(f"[WARNING] {len(duplicates)} hash(es) correspond to multiple source files "
              f"(duplicate content). Use --verbose to see details.")
        if verbose:
            for h, paths in duplicates.items():
                print(f"  Hash {h[:12]}...: {', '.join(paths)}")

    return file_hashes, file_count, total_time


def find_matching_files(search_hashes, target_directory, cache, verbose=False):
    """Finds files in the target directory that match any hash in search_hashes."""
    results, file_count, total_time = _hash_directory_files(
        target_directory, cache, verbose=verbose, label="Scanned file"
    )
    matching_files = []
    matched_hashes = set()
    for filepath, file_hash in results:
        if file_hash in search_hashes:
            matching_files.append(filepath)
            matched_hashes.add(file_hash)
            print(f"[INFO] Match found: {filepath}")

    return matching_files, file_count, total_time, matched_hashes


def _resolve_destination_path(filepath, destination):
    """Return a non-colliding destination path for the given file."""
    basename = os.path.basename(filepath)
    dest_path = os.path.join(destination, basename)
    if not os.path.exists(dest_path):
        return dest_path
    name, ext = os.path.splitext(basename)
    counter = 1
    while os.path.exists(dest_path):
        dest_path = os.path.join(destination, f"{name}_{counter}{ext}")
        counter += 1
    return dest_path


def perform_action_on_files(files, action, destination=None):
    """Performs the specified action (move, delete, or list) on the given files."""
    if action == "list":
        print("[INFO] Listing matching files:")
        for file in files:
            print(f"[MATCH] {file}")
    else:
        for file in files:
            try:
                if action == "move" and destination:
                    dest_path = _resolve_destination_path(file, destination)
                    shutil.move(file, dest_path)
                    print(f"[INFO] Moved file: {file} -> {dest_path}")
                elif action == "delete":
                    os.remove(file)
                    print(f"[INFO] Deleted file: {file}")
            except Exception as e:
                print(f"[ERROR] Failed to {action} file {file}: {e}")


def print_summary(source_count, source_time, target_count, target_time,
                  match_count, unique_source_hashes, matched_hash_count):
    """Prints a summary of the operation."""
    total_time = source_time + target_time
    not_found_count = unique_source_hashes - matched_hash_count
    print("\n--- SUMMARY ---")
    print(f"Source folder: {source_count} files scanned in {source_time:.2f} seconds.")
    print(f"Target folder: {target_count} files scanned in {target_time:.2f} seconds.")
    print(f"Unique source hashes: {unique_source_hashes}")
    print(f"Source hashes with matches: {matched_hash_count}")
    print(f"Source hashes with NO matches: {not_found_count}")
    print(f"Total matching files found in target: {match_count}")
    print(f"Total execution time: {total_time:.2f} seconds.")
    print("----------------\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find and perform actions on files with matching SHA-256 hashes, with cache."
    )
    parser.add_argument("search_folder", help="Folder to search for files and hash them.")
    parser.add_argument("target_folder", help="Folder to find matching files.")
    parser.add_argument("--action", choices=["move", "delete", "list"], required=True,
                        help="Action to perform on matching files.")
    parser.add_argument("--destination",
                        help="Destination folder for moving files (required for move action).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without actually performing actions.")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip confirmation prompt for destructive actions.")

    args = parser.parse_args()

    if args.action == "move" and not args.destination:
        parser.error("The --destination argument is required for the 'move' action.")

    # Load the cache
    cache = load_cache()

    if args.verbose:
        print(f"[INFO] Starting to hash files in {args.search_folder}")

    # Get hashes for files in the search folder
    search_hashes, source_count, source_time = get_files_with_hashes(
        args.search_folder, cache, verbose=args.verbose
    )

    if args.verbose:
        print(f"[INFO] Finished hashing files in {args.search_folder}")
        print(f"[INFO] Searching for matching files in {args.target_folder}")

    # Find matching files in the target folder
    matching_files, target_count, target_time, matched_hashes = find_matching_files(
        search_hashes, args.target_folder, cache, verbose=args.verbose
    )

    if args.verbose:
        print(f"[INFO] Found {len(matching_files)} matching files.")

    # Perform the action (move, delete, or list)
    if args.dry_run:
        print(f"[DRY RUN] Would {args.action} {len(matching_files)} file(s):")
        for f in matching_files:
            print(f"  {f}")
    else:
        if args.action == "delete" and not args.yes and matching_files:
            print(f"\n[WARNING] About to permanently delete {len(matching_files)} file(s).")
            response = input("Type 'yes' to confirm: ")
            if response.strip().lower() != "yes":
                print("[INFO] Aborted by user.")
                save_cache(cache)
                sys.exit(0)

        if args.verbose:
            print(f"[INFO] Performing {args.action} on matching files.")

        perform_action_on_files(matching_files, args.action, args.destination)

    # Print the summary
    print_summary(source_count, source_time, target_count, target_time,
                  len(matching_files), len(search_hashes), len(matched_hashes))

    # Save the cache
    save_cache(cache)

    if args.verbose:
        print("[INFO] Finished.")


if __name__ == "__main__":
    main()
