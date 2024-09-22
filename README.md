# FileHashSearch
Find files from search directory and search for the same files in a target directory then carry out actions on them

Key Features:

    File Hash Caching:
        The script saves the file hashes and their last modification times to a cache (hash_cache.json).
        If a file has not been modified since it was last hashed, it will reuse the cached hash.

    Cache Validation:
        Before performing any action, the script checks whether the file has changed by comparing its modification time (mtime).
        If the file has changed or is not in the cache, it recalculates the hash and updates the cache.

    Cache File:
        The cache is stored in hash_cache.json in the same directory as the script. It stores file paths, hashes, and modification times.

Usage Example:

    Listing Files (verbose mode):

    bash

python script.py /path/to/search_folder /path/to/target_folder --action list --verbose

Moving Files:

bash

    python script.py /path/to/search_folder /path/to/target_folder --action move --destination /path/to/destination_folder --verbose

This script will now efficiently use the cached hashes between sessions and only rehash files if they have changed, ensuring speed and accuracy in repeated runs. 
