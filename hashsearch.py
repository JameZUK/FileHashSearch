import hashlib
import os
import shutil
import argparse
import time
import json

CACHE_FILE = "hash_cache.json"

def load_cache():
    """Loads the hash cache from a file."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    """Saves the hash cache to a file."""
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

def calculate_sha256(filepath):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def is_cache_valid(filepath, cached_entry):
    """Checks if a cached entry is still valid by comparing file modification times."""
    if not os.path.exists(filepath):
        return False
    current_mtime = os.path.getmtime(filepath)
    return current_mtime == cached_entry.get('mtime')

def get_files_with_hashes(directory, cache, verbose=False):
    """Returns a dictionary mapping file hashes to their paths for all files in a directory, using a cache."""
    file_hashes = {}
    file_count = 0
    start_time = time.time()

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_mtime = os.path.getmtime(filepath)
            try:
                # Check cache validity
                if filepath in cache and is_cache_valid(filepath, cache[filepath]):
                    file_hash = cache[filepath]['hash']
                else:
                    # Calculate new hash and update cache
                    file_hash = calculate_sha256(filepath)
                    cache[filepath] = {'hash': file_hash, 'mtime': file_mtime}

                file_hashes[file_hash] = filepath
                file_count += 1
                if verbose:
                    elapsed_time = time.time() - start_time
                    rate = file_count / elapsed_time if elapsed_time > 0 else 0
                    print(f"[INFO] Hashed file: {filepath} | Files scanned: {file_count} | Rate: {rate:.2f} files/second")
            except Exception as e:
                print(f"[ERROR] Failed to hash file {filepath}: {e}")

    total_time = time.time() - start_time
    print(f"[INFO] Finished hashing {file_count} files in {total_time:.2f} seconds. Average rate: {file_count / total_time:.2f} files/second.")
    
    return file_hashes, file_count, total_time

def find_matching_files(search_hashes, target_directory, cache, verbose=False):
    """Finds files in the target directory that match any hash in search_hashes, using a cache."""
    matching_files = []
    file_count = 0
    start_time = time.time()

    for root, _, files in os.walk(target_directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_mtime = os.path.getmtime(filepath)
            try:
                # Check cache validity
                if filepath in cache and is_cache_valid(filepath, cache[filepath]):
                    file_hash = cache[filepath]['hash']
                else:
                    # Calculate new hash and update cache
                    file_hash = calculate_sha256(filepath)
                    cache[filepath] = {'hash': file_hash, 'mtime': file_mtime}

                if file_hash in search_hashes:
                    matching_files.append(filepath)
                    print(f"[INFO] Match found: {filepath}")
                
                file_count += 1
                if verbose:
                    elapsed_time = time.time() - start_time
                    rate = file_count / elapsed_time if elapsed_time > 0 else 0
                    print(f"[INFO] Scanned file: {filepath} | Files scanned: {file_count} | Rate: {rate:.2f} files/second")
            except Exception as e:
                print(f"[ERROR] Failed to hash file {filepath}: {e}")

    total_time = time.time() - start_time
    print(f"[INFO] Finished scanning {file_count} files in {total_time:.2f} seconds. Average rate: {file_count / total_time:.2f} files/second.")
    
    return matching_files, file_count, total_time

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
                    shutil.move(file, destination)
                    print(f"[INFO] Moved file: {file} to {destination}")
                elif action == "delete":
                    os.remove(file)
                    print(f"[INFO] Deleted file: {file}")
            except Exception as e:
                print(f"[ERROR] Failed to {action} file {file}: {e}")

def print_summary(source_count, source_time, target_count, target_time, match_count):
    """Prints a summary of the operation."""
    total_time = source_time + target_time
    print("\n--- SUMMARY ---")
    print(f"Source folder: {source_count} files scanned in {source_time:.2f} seconds.")
    print(f"Target folder: {target_count} files scanned in {target_time:.2f} seconds.")
    print(f"Total matching files found: {match_count}")
    print(f"Total execution time: {total_time:.2f} seconds.")
    print("----------------\n")

def main():
    parser = argparse.ArgumentParser(description="Find and perform actions on files with matching SHA-256 hashes, with cache.")
    parser.add_argument("search_folder", help="Folder to search for files and hash them.")
    parser.add_argument("target_folder", help="Folder to find matching files.")
    parser.add_argument("--action", choices=["move", "delete", "list"], required=True, help="Action to perform on matching files.")
    parser.add_argument("--destination", help="Destination folder for moving files (required for move action).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity.")

    args = parser.parse_args()

    if args.action == "move" and not args.destination:
        parser.error("The --destination argument is required for the 'move' action.")

    # Load the cache
    cache = load_cache()

    if args.verbose:
        print(f"[INFO] Starting to hash files in {args.search_folder}")

    # Get hashes for files in the search folder
    search_hashes, source_count, source_time = get_files_with_hashes(args.search_folder, cache, verbose=args.verbose)

    if args.verbose:
        print(f"[INFO] Finished hashing files in {args.search_folder}")
        print(f"[INFO] Searching for matching files in {args.target_folder}")

    # Find matching files in the target folder
    matching_files, target_count, target_time = find_matching_files(search_hashes, args.target_folder, cache, verbose=args.verbose)

    if args.verbose:
        print(f"[INFO] Found {len(matching_files)} matching files.")

    # Perform the action (move, delete, or list)
    if args.verbose:
        print(f"[INFO] Performing {args.action} on matching files.")
        
    perform_action_on_files(matching_files, args.action, args.destination)

    # Print the summary
    print_summary(source_count, source_time, target_count, target_time, len(matching_files))

    # Save the cache
    save_cache(cache)

    if args.verbose:
        print(f"[INFO] Finished.")

if __name__ == "__main__":
    main()
