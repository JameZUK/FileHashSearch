import unittest
import tempfile
import os
import json
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import hashsearch


class TestCalculateSha256(unittest.TestCase):
    def test_known_hash(self):
        """SHA-256 of known content matches expected value."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("hello world")
            path = f.name
        try:
            result = hashsearch.calculate_sha256(path)
            self.assertEqual(
                result,
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            )
        finally:
            os.unlink(path)

    def test_empty_file(self):
        """SHA-256 of empty file matches expected value."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            result = hashsearch.calculate_sha256(path)
            self.assertEqual(
                result,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
        finally:
            os.unlink(path)

    def test_large_file(self):
        """Hashing a file larger than the 4096-byte block size works correctly."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * 10000)
            path = f.name
        try:
            result = hashsearch.calculate_sha256(path)
            self.assertEqual(len(result), 64)  # valid hex digest length
        finally:
            os.unlink(path)


class TestCacheValidity(unittest.TestCase):
    def test_valid_cache_entry(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            mtime = os.path.getmtime(path)
            entry = {'hash': 'abc123', 'mtime': mtime}
            self.assertTrue(hashsearch.is_cache_valid(path, entry))
        finally:
            os.unlink(path)

    def test_stale_cache_entry(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            entry = {'hash': 'abc123', 'mtime': 0.0}
            self.assertFalse(hashsearch.is_cache_valid(path, entry))
        finally:
            os.unlink(path)

    def test_missing_file(self):
        entry = {'hash': 'abc123', 'mtime': 12345.0}
        self.assertFalse(hashsearch.is_cache_valid("/nonexistent/file.txt", entry))

    def test_missing_mtime_in_entry(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            entry = {'hash': 'abc123'}
            self.assertFalse(hashsearch.is_cache_valid(path, entry))
        finally:
            os.unlink(path)

    def test_tolerance_accepts_tiny_drift(self):
        """Float mtime within tolerance is accepted (fix #10)."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            mtime = os.path.getmtime(path)
            entry = {'hash': 'abc123', 'mtime': mtime + 1e-9}
            self.assertTrue(hashsearch.is_cache_valid(path, entry))
        finally:
            os.unlink(path)

    def test_tolerance_rejects_large_drift(self):
        """Float mtime outside tolerance is rejected."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            mtime = os.path.getmtime(path)
            entry = {'hash': 'abc123', 'mtime': mtime + 1.0}
            self.assertFalse(hashsearch.is_cache_valid(path, entry))
        finally:
            os.unlink(path)


class TestHashDirectoryFiles(unittest.TestCase):
    def test_empty_directory(self):
        """Empty directory produces zero results and no crash (fix #1)."""
        with tempfile.TemporaryDirectory() as d:
            cache = {}
            results, count, total_time = hashsearch._hash_directory_files(d, cache)
            self.assertEqual(count, 0)
            self.assertEqual(results, [])

    def test_hashes_files(self):
        """Files in directory are hashed and returned."""
        with tempfile.TemporaryDirectory() as d:
            for name in ["a.txt", "b.txt"]:
                with open(os.path.join(d, name), 'w') as f:
                    f.write(name)
            cache = {}
            results, count, _ = hashsearch._hash_directory_files(d, cache)
            self.assertEqual(count, 2)
            self.assertEqual(len(results), 2)
            # All results have filepath and hash
            for filepath, file_hash in results:
                self.assertTrue(os.path.exists(filepath))
                self.assertEqual(len(file_hash), 64)

    def test_populates_cache(self):
        """Cache is populated after hashing."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.txt")
            with open(path, 'w') as f:
                f.write("content")
            cache = {}
            hashsearch._hash_directory_files(d, cache)
            self.assertIn(path, cache)
            self.assertIn('hash', cache[path])
            self.assertIn('mtime', cache[path])

    def test_uses_cache(self):
        """Cached hashes are reused when valid."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.txt")
            with open(path, 'w') as f:
                f.write("content")
            mtime = os.path.getmtime(path)
            cache = {path: {'hash': 'fake_cached_hash', 'mtime': mtime}}
            results, _, _ = hashsearch._hash_directory_files(d, cache)
            # Should use the cached value
            self.assertEqual(results[0][1], 'fake_cached_hash')

    def test_race_condition_getmtime(self):
        """File deleted between walk and getmtime is handled gracefully (fix #2)."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "vanishing.txt")
            with open(path, 'w') as f:
                f.write("temporary")
            cache = {}
            original_getmtime = os.path.getmtime

            def flaky_getmtime(p):
                if os.path.basename(p) == "vanishing.txt":
                    raise FileNotFoundError(f"No such file: {p}")
                return original_getmtime(p)

            os.path.getmtime = flaky_getmtime
            try:
                results, count, _ = hashsearch._hash_directory_files(d, cache)
                self.assertEqual(count, 0)  # file was skipped
            finally:
                os.path.getmtime = original_getmtime


class TestGetFilesWithHashes(unittest.TestCase):
    def test_duplicate_content_preserved(self):
        """Source files with identical content are all tracked (fix #3)."""
        with tempfile.TemporaryDirectory() as d:
            for name in ["a.txt", "b.txt", "c.txt"]:
                with open(os.path.join(d, name), 'w') as f:
                    f.write("same content")
            cache = {}
            file_hashes, count, _ = hashsearch.get_files_with_hashes(d, cache)
            # All 3 files should be represented
            total_paths = sum(len(paths) for paths in file_hashes.values())
            self.assertEqual(total_paths, 3)
            self.assertEqual(count, 3)
            # Only 1 unique hash
            self.assertEqual(len(file_hashes), 1)

    def test_unique_files(self):
        """Files with different content produce different hashes."""
        with tempfile.TemporaryDirectory() as d:
            for i, name in enumerate(["a.txt", "b.txt", "c.txt"]):
                with open(os.path.join(d, name), 'w') as f:
                    f.write(f"unique content {i}")
            cache = {}
            file_hashes, count, _ = hashsearch.get_files_with_hashes(d, cache)
            self.assertEqual(len(file_hashes), 3)
            self.assertEqual(count, 3)


class TestFindMatchingFiles(unittest.TestCase):
    def test_finds_matches(self):
        """Matching files in target are found."""
        with tempfile.TemporaryDirectory() as source, \
             tempfile.TemporaryDirectory() as target:
            # Create identical file in both directories
            for d in [source, target]:
                with open(os.path.join(d, "match.txt"), 'w') as f:
                    f.write("matching content")
            # Create non-matching file in target
            with open(os.path.join(target, "other.txt"), 'w') as f:
                f.write("different content")

            cache = {}
            search_hashes, _, _ = hashsearch.get_files_with_hashes(source, cache)
            matching, count, _, matched_hashes = hashsearch.find_matching_files(
                search_hashes, target, cache
            )
            self.assertEqual(len(matching), 1)
            self.assertEqual(count, 2)  # both target files scanned
            self.assertEqual(len(matched_hashes), 1)

    def test_no_matches(self):
        """No matches when content differs."""
        with tempfile.TemporaryDirectory() as source, \
             tempfile.TemporaryDirectory() as target:
            with open(os.path.join(source, "a.txt"), 'w') as f:
                f.write("source content")
            with open(os.path.join(target, "b.txt"), 'w') as f:
                f.write("target content")

            cache = {}
            search_hashes, _, _ = hashsearch.get_files_with_hashes(source, cache)
            matching, _, _, matched_hashes = hashsearch.find_matching_files(
                search_hashes, target, cache
            )
            self.assertEqual(len(matching), 0)
            self.assertEqual(len(matched_hashes), 0)

    def test_matched_hashes_correct(self):
        """matched_hashes set contains only hashes that were actually found (fix #4)."""
        with tempfile.TemporaryDirectory() as source, \
             tempfile.TemporaryDirectory() as target:
            # 2 unique source files
            with open(os.path.join(source, "a.txt"), 'w') as f:
                f.write("content A")
            with open(os.path.join(source, "b.txt"), 'w') as f:
                f.write("content B")
            # Only match one in target
            with open(os.path.join(target, "match.txt"), 'w') as f:
                f.write("content A")

            cache = {}
            search_hashes, _, _ = hashsearch.get_files_with_hashes(source, cache)
            _, _, _, matched_hashes = hashsearch.find_matching_files(
                search_hashes, target, cache
            )
            self.assertEqual(len(search_hashes), 2)
            self.assertEqual(len(matched_hashes), 1)
            not_found = len(search_hashes) - len(matched_hashes)
            self.assertEqual(not_found, 1)


class TestResolveDestinationPath(unittest.TestCase):
    def test_no_collision(self):
        with tempfile.TemporaryDirectory() as d:
            result = hashsearch._resolve_destination_path("/src/file.txt", d)
            self.assertEqual(result, os.path.join(d, "file.txt"))

    def test_single_collision(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "file.txt"), 'w') as f:
                f.write("existing")
            result = hashsearch._resolve_destination_path("/src/file.txt", d)
            self.assertEqual(result, os.path.join(d, "file_1.txt"))

    def test_multiple_collisions(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ["file.txt", "file_1.txt", "file_2.txt"]:
                with open(os.path.join(d, name), 'w') as f:
                    f.write("existing")
            result = hashsearch._resolve_destination_path("/src/file.txt", d)
            self.assertEqual(result, os.path.join(d, "file_3.txt"))

    def test_no_extension(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Makefile"), 'w') as f:
                f.write("existing")
            result = hashsearch._resolve_destination_path("/src/Makefile", d)
            self.assertEqual(result, os.path.join(d, "Makefile_1"))


class TestPerformActionOnFiles(unittest.TestCase):
    def test_list_action(self, ):
        """List action prints files without modifying them."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.txt")
            with open(path, 'w') as f:
                f.write("content")
            hashsearch.perform_action_on_files([path], "list")
            self.assertTrue(os.path.exists(path))  # file still exists

    def test_delete_action(self):
        """Delete action removes files."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.txt")
            with open(path, 'w') as f:
                f.write("content")
            hashsearch.perform_action_on_files([path], "delete")
            self.assertFalse(os.path.exists(path))

    def test_move_action(self):
        """Move action relocates files to destination."""
        with tempfile.TemporaryDirectory() as src, \
             tempfile.TemporaryDirectory() as dest:
            path = os.path.join(src, "test.txt")
            with open(path, 'w') as f:
                f.write("content")
            hashsearch.perform_action_on_files([path], "move", dest)
            self.assertFalse(os.path.exists(path))
            self.assertTrue(os.path.exists(os.path.join(dest, "test.txt")))

    def test_move_with_collision(self):
        """Move action resolves name collisions (fix #5)."""
        with tempfile.TemporaryDirectory() as src, \
             tempfile.TemporaryDirectory() as dest:
            # Create source file
            path = os.path.join(src, "test.txt")
            with open(path, 'w') as f:
                f.write("new content")
            # Create existing file at destination
            with open(os.path.join(dest, "test.txt"), 'w') as f:
                f.write("existing content")

            hashsearch.perform_action_on_files([path], "move", dest)
            self.assertTrue(os.path.exists(os.path.join(dest, "test.txt")))
            self.assertTrue(os.path.exists(os.path.join(dest, "test_1.txt")))

    def test_delete_nonexistent_file(self):
        """Deleting a nonexistent file logs error without crashing."""
        hashsearch.perform_action_on_files(["/nonexistent/file.txt"], "delete")


class TestCacheLoadSave(unittest.TestCase):
    def setUp(self):
        self._original_cache_file = hashsearch.CACHE_FILE
        self._tmpdir = tempfile.mkdtemp()
        hashsearch.CACHE_FILE = os.path.join(self._tmpdir, "test_cache.json")

    def tearDown(self):
        hashsearch.CACHE_FILE = self._original_cache_file
        shutil.rmtree(self._tmpdir)

    def test_load_empty(self):
        """Loading nonexistent cache returns empty dict."""
        result = hashsearch.load_cache()
        self.assertEqual(result, {})

    def test_save_and_load(self):
        """Cache round-trips through save/load."""
        data = {"/path/to/file": {"hash": "abc123", "mtime": 12345.0}}
        hashsearch.save_cache(data)
        loaded = hashsearch.load_cache()
        self.assertEqual(loaded, data)

    def test_file_permissions(self):
        """Cache file is created with restricted permissions (fix #7)."""
        hashsearch.save_cache({"test": "data"})
        stat = os.stat(hashsearch.CACHE_FILE)
        mode = oct(stat.st_mode & 0o777)
        self.assertEqual(mode, '0o600')


if __name__ == '__main__':
    unittest.main()
