#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pyyaml",
# ]
# ///
"""
Fast duplicate file finder.
Usage: duplicates.py <folder> [<folder>...]

Original References:
https://stackoverflow.com/a/36113168/300783
https://gist.github.com/ntjess/1663d25d09bd762af2f0c60f600191f5
Modified by XxInvictus for:
- CLI arguments for various additional functions including
    - source folder(s) to search for duplicates
    - input csv file with list of files to search for duplicates
    - output csv file with list of duplicates
    - delete duplicates
    - dry run
    - logging
    - verbose output
"""
import argparse
import base64
import csv
import hashlib
import yaml
import logging.config
import os
import sys
from collections import defaultdict
from inspect import getmembers, isfunction
from itertools import repeat
from multiprocessing.pool import ThreadPool
from pathlib import Path

# Load the config file
with open('logconf.yaml', 'rt') as f:
    config = yaml.safe_load(f.read())

# Configure the logging module with the config file
logging.config.dictConfig(config)
logger = logging.getLogger()

parallel_threads = 5
parallel_chunksize = 10

def validate_arguments():
    logger.info("Validating arguments...")
    if args.source:
        validate_source()
    if args.destinations:
        validate_destinations()
    if args.mode:
        validate_mode()
    if args.input:
        validate_input()
    if args.output:
        validate_output()
    if args.test:
        validate_test()

    logger.info("All arguments are valid.")

def validate_source():
    if args.source:
        if not os.path.exists(args.source):
            logger.error(f"Source path '{args.source}' does not exist.")
            raise ValueError(f"Source path '{args.source}' does not exist.")
        if not os.path.isdir(args.source) and not os.path.isfile(args.source):
            logger.error(f"Source path '{args.source}' is not a valid file or directory.")
            raise ValueError(f"Source path '{args.source}' is not a valid file or directory.")

def validate_destinations():
    if args.destinations:
        for dest in args.destinations:
            if not os.path.exists(dest):
                logger.error(f"Destination path '{dest}' does not exist.")
                raise ValueError(f"Destination path '{dest}' does not exist.")
            if not os.path.isdir(dest) and not os.path.isfile(dest):
                logger.error(f"Destination path '{dest}' is not a valid file or directory.")
                raise ValueError(f"Destination path '{dest}' is not a valid file or directory.")

def validate_input():
    if args.input:
        if not args.input.endswith('.csv'):
            logger.error(f"Input file '{args.input}' must have a .csv extension.")
            raise ValueError(f"Input file '{args.input}' must have a .csv extension.")
        if not os.path.isfile(args.input):
            logger.error(f"Input file '{args.input}' does not exist.")
            raise ValueError(f"Input file '{args.input}' does not exist.")
        with open(args.input, newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                if len(row) != 1:
                    logger.error(f"Input CSV file '{args.input}' must have exactly one column per row.")
                    raise ValueError(f"Input CSV file '{args.input}' must have exactly one column per row.")
                path = row[0]
                if not os.path.exists(path):
                    logger.error(f"Path '{path}' in input CSV does not exist.")
                    raise ValueError(f"Path '{path}' in input CSV does not exist.")
                if not os.path.isdir(path) and not os.path.isfile(path):
                    logger.error(f"Path '{path}' in input CSV is not a valid file or directory.")
                    raise ValueError(f"Path '{path}' in input CSV is not a valid file or directory.")

def validate_output():
    if args.output and not args.output.endswith('.csv'):
        logger.error(f"Output file '{args.output}' must have a .csv extension.")
        raise ValueError(f"Output file '{args.output}' must have a .csv extension.")

def validate_mode():
    valid_modes = ['hash', 'combined', 'inode']
    if args.mode and args.mode not in valid_modes:
        logger.error(f"Invalid mode '{args.mode}'. Accepted options are: {', '.join(valid_modes)}.")
        raise ValueError(f"Invalid mode '{args.mode}'. Accepted options are: {', '.join(valid_modes)}.")

def validate_test():
    logger.debug(f"Validating test functions: {args.functions}")
    if args.test and not args.functions:
        logger.error("Test mode requires functions to be provided.")
        raise ValueError("Test mode requires functions to be provided.")
    if not all(x in [o[0] for o in getmembers(sys.modules[__name__]) if isfunction(o[1])] for x in args.functions):
        logger.error("All functions provided for testing are not valid.")
        raise ValueError("All functions provided for testing are not valid.")


def chunk_reader(fobj, chunk_size=1024):
    """ Generator that reads a file in chunks of bytes """
    logger.debug(f"Reading file in chunks of size {chunk_size}.")
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            logger.debug("End of file reached.")
            return
        yield chunk


def get_hash(filename, first_chunk_only=False, hash_algo=hashlib.sha1):
    logger.info(f"Calculating hash for file: {filename}, first_chunk_only={first_chunk_only}.")
    hashobj = hash_algo()
    try:
        with open(filename, "rb") as f:
            if first_chunk_only:
                hashobj.update(f.read(1024))
            else:
                for chunk in chunk_reader(f):
                    hashobj.update(chunk)
        logger.debug(f"Hash calculated successfully for file: {filename}.")
    except OSError as e:
        logger.error(f"Error reading file {filename}: {e}")
        raise
    return hashobj.digest()


def multi_hash(filename, first_chunk_only=False):
    logger.info(f"Calculating hash for file: {filename}, first_chunk_only={first_chunk_only}")
    try:
        file_hash = get_hash(filename, first_chunk_only)
        logger.debug(f"Hash for file {filename}: {file_hash}")
    except OSError as e:
        logger.error(f"Error calculating hash for file {filename}: {e}")
        file_hash = None
    return filename, file_hash


def get_source_files():
    logger.info("Retrieving source files.")
    sources = []
    if args.source:
        sources = [args.source]
    elif args.input:
        logger.info(f"Reading sources from input CSV: {args.input}.")
        with open(args.input, newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            sources = [row[0] for row in csvreader]
    else:
        logger.error("No source provided.")
        raise ValueError("No source provided.")

    source_files = []
    for source in sources:
        try:
            if os.path.isdir(source):
                logger.debug(f"Walking through directory: {source}.")
                for dirpath, _, filenames in Path(source).walk():
                    for filename in filenames:
                        full_path = os.path.join(dirpath, filename)
                        try:
                            full_path = os.path.realpath(full_path)
                        except OSError as e:
                            logger.warning(f"Failed to resolve real path for {full_path}: {e}")
                            continue
                        source_files.append(full_path)
            elif os.path.isfile(source):
                source_files.append(os.path.realpath(source))
        except Exception as e:
            logger.error(f"Failed to get source files from {source}: {e}")
    logger.info(f"Retrieved {len(source_files)} source files.")
    return source_files


def find_duplicates_by_size(paths):
    logger.info("Finding duplicates by file size.")
    source_files = get_source_file_sizes()
    source_matches = []
    files_by_size = defaultdict(list)
    for path in paths:
        logger.debug(f"Processing path: {path}.")
        for dirpath, _, filenames in Path(path).walk():
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                try:
                    full_path = os.path.realpath(full_path)
                    file_size = os.path.getsize(full_path)
                except OSError as e:
                    logger.warning(f"Failed to access file {full_path}: {e}")
                    continue
                if file_size in source_files.keys():
                    source_matches.append(source_files[file_size][0])
                    if len(files_by_size[file_size]) == 0:
                        files_by_size[file_size] = []
                    if source_files[file_size][0] not in files_by_size[file_size]:
                        files_by_size[file_size].append(source_files[file_size][0])
                    files_by_size[file_size].append(full_path)
    logger.info(f"Found {len(files_by_size)} file groups with duplicate sizes.")
    return source_matches, files_by_size


def get_source_file_sizes():
    logger.info("Retrieving file sizes from source directory.")
    source_sizes = defaultdict(list)
    for dirpath, _, filenames in Path(args.source).walk():
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            try:
                full_path = os.path.realpath(full_path)
                file_size = os.path.getsize(full_path)
                source_sizes[file_size].append(full_path)
                logger.debug(f"File: {full_path}, Size: {file_size}")
            except OSError as e:
                logger.warning(f"Failed to access file {full_path}: {e}")
    logger.info(f"Retrieved sizes for {len(source_sizes)} unique file sizes.")
    return source_sizes


def find_duplicates_by_small_hash(source_files, files_by_size):
    logger.info("Finding duplicates by small hash.")
    source_small_hashes = defaultdict(list)
    source_matches = []

    logger.info("Calculating small hashes for source files.")
    with ThreadPool(parallel_threads) as parallel_pool:
        for result in parallel_pool.starmap(multi_hash, zip(source_files, repeat(True)), chunksize=parallel_chunksize):
            if not result[1]:
                continue
            full_hash = base64.b64encode(result[1])
            source_small_hashes[full_hash].append(result[0])

    files_by_small_hash = defaultdict(list)
    logger.info("Calculating small hashes for destination files.")
    for file_size, files in files_by_size.items():
        if len(files) < 2:
            continue
        hash_list = []
        with ThreadPool(parallel_threads) as parallel_pool:
            for result in parallel_pool.starmap(multi_hash, zip(files, repeat(True)), chunksize=parallel_chunksize):
                if not result[1]:
                    continue
                full_hash = base64.b64encode(result[1])
                hash_list.append((result[0], full_hash))
        for filename, small_hash in hash_list:
            if small_hash in source_small_hashes:
                if source_small_hashes[small_hash][0] not in source_matches:
                    source_matches.append(source_small_hashes[small_hash][0])
                files_by_small_hash[(file_size, small_hash)].append(filename)

    logger.info(f"Found {len(files_by_small_hash)} groups of duplicates by small hash.")
    return source_matches, files_by_small_hash


def find_duplicates_by_full_hash(source_files, files_by_small_hash):
    logger.info("Finding duplicates by full hash.")
    source_full_hashes = defaultdict(list)
    source_by_hash = {}
    source_by_filename = {}

    logger.info("Calculating full hashes for source files.")
    with ThreadPool(parallel_threads) as parallel_pool:
        for result in parallel_pool.imap(multi_hash, source_files, chunksize=parallel_chunksize):
            if not result[1]:
                continue
            full_hash = base64.b64encode(result[1])
            source_full_hashes[full_hash].append(result[0])

    files_by_full_hash = defaultdict(dict)
    logger.info("Calculating full hashes for destination files.")
    for files in files_by_small_hash.values():
        if len(files) < 2:
            continue
        hash_list = []
        with ThreadPool(parallel_threads) as parallel_pool:
            for result in parallel_pool.imap(multi_hash, files, chunksize=parallel_chunksize):
                if not result[1]:
                    continue
                full_hash = base64.b64encode(result[1])
                hash_list.append((result[0], full_hash))
        for filename, full_hash in hash_list:
            if full_hash in source_full_hashes:
                source_by_hash[full_hash] = source_full_hashes[full_hash][0]
                source_by_filename[source_full_hashes[full_hash][0]] = full_hash
                files_by_full_hash[full_hash][filename] = None

    logger.info(f"Found {len(files_by_full_hash)} groups of duplicates by full hash.")
    return source_by_hash, source_by_filename, files_by_full_hash


def get_file_inode(file):
    logger.debug(f"Getting inode for file: {file}")
    if not os.path.exists(file):
        logger.warning(f"File does not exist: {file}")
        return file, None
    try:
        inode = os.stat(file).st_ino
        logger.debug(f"Inode for file {file}: {inode}")
        return file, inode
    except OSError as e:
        logger.error(f"Error getting inode for file {file}: {e}")
        return file, None


def find_duplicates_by_inode(source_files, files_input, mode):
    logger.info(f"Finding duplicates by inode in mode: {mode}")
    if mode not in ["combined", "inode"]:
        logger.error("Invalid mode. Accepted modes are: 'combined', 'inode'.")
        raise ValueError("Invalid mode. Accepted modes are: 'combined', 'inode'.")

    source_by_inode_or_hash = {}
    source_by_filename = {}
    files_grouped_by_inode_or_hash = defaultdict(dict)

    logger.info("Getting inodes for source files.")
    with ThreadPool(parallel_threads) as parallel_pool:
        for file, inode in parallel_pool.imap_unordered(get_file_inode, source_files, chunksize=parallel_chunksize):
            if inode is None:
                continue
            source_by_inode_or_hash[inode] = file
            source_by_filename[file] = inode

    logger.info("Getting inodes for destination files.")
    if mode == "inode":
        for file_size, files in files_input.items():
            if len(files) < 2:
                continue
            inode_list = []
            with ThreadPool(parallel_threads) as parallel_pool:
                for file, inode in parallel_pool.imap_unordered(get_file_inode, files, chunksize=parallel_chunksize):
                    if inode is None:
                        continue
                    inode_list.append((file, inode))
            for filename, inode in inode_list:
                if inode in source_by_inode_or_hash:
                    if not files_grouped_by_inode_or_hash[inode]:
                        files_grouped_by_inode_or_hash[inode] = {}
                    files_grouped_by_inode_or_hash[inode][filename] = None
    elif mode == "combined":
        for files in files_input.values():
            if len(files) < 2:
                continue
            inode_list = []
            with ThreadPool(parallel_threads) as parallel_pool:
                for file, inode in parallel_pool.imap_unordered(get_file_inode, files, chunksize=parallel_chunksize):
                    if inode is None:
                        continue
                    inode_list.append((file, inode))
            for filename, inode in inode_list:
                if inode in source_by_inode_or_hash:
                    if not files_grouped_by_inode_or_hash[inode]:
                        files_grouped_by_inode_or_hash[inode] = {}
                    files_grouped_by_inode_or_hash[inode][filename] = None

    logger.info(f"Found {len(files_grouped_by_inode_or_hash)} groups of duplicates by inode.")
    return source_by_inode_or_hash, source_by_filename, files_grouped_by_inode_or_hash


def remove_or_purge_files(delete_list):
    logger.info("Starting file removal process.")
    for file in delete_list:
        try:
            os.remove(file)
            logger.info(f"Successfully removed file: {file}")
        except OSError as e:
            logger.error(f"Failed to remove file {file}: {e}")


def print_to_console(source_files, files_by_full_hash):
    logger.info("Printing duplicate files to console.")
    for source_hash, source_path in source_files.items():
        try:
            files_str = "\n".join("- %s" % file for file in files_by_full_hash[source_hash].keys())
            output_str = f"Duplicate found for {source_path}:\n{files_str}\n"
            logger.debug(f"Output for {source_path}: {output_str}")
        except KeyError:
            output_str = f"No duplicates found for {source_path}\n"
            logger.debug(f"No duplicates for {source_path}")


def check_for_duplicates():
    global parallel_threads, parallel_chunksize
    if args.parallel_threads:
        parallel_threads = args.parallel_threads
    if args.parallel_chunksize:
        parallel_chunksize = args.parallel_chunksize

    logger.info("Starting duplicate check process.")
    original_source_files = get_source_files()

    logger.info("Finding duplicates by size.")
    source_files, files_by_size = find_duplicates_by_size(args.destinations)
    if len(files_by_size) == 0:
        logger.warning("No duplicates by size found.")
        raise ValueError("No duplicates by size found.")

    if args.mode == "hash":
        logger.info("Finding duplicates by small hash.")
        source_files, files_by_small_hash = find_duplicates_by_small_hash(source_files, files_by_size)
        if len(files_by_small_hash) == 0:
            logger.warning("No duplicates by small hash found.")
            raise ValueError("No duplicates by small hash found.")

        logger.info("Finding duplicates by full hash.")
        source_by_inode_or_hash, source_by_filename, files_grouped_by_inode_or_hash = find_duplicates_by_full_hash(source_files, files_by_small_hash)

    elif args.mode == "combined":
        logger.info("Finding duplicates by small hash.")
        source_files, files_by_small_hash = find_duplicates_by_small_hash(source_files, files_by_size)
        if len(files_by_small_hash) == 0:
            logger.warning("No duplicates by small hash found.")
            raise ValueError("No duplicates by small hash found.")

        logger.info("Finding duplicates by inode.")
        source_by_inode_or_hash, source_by_filename, files_grouped_by_inode_or_hash = find_duplicates_by_inode(source_files, files_by_small_hash, mode="combined")

    elif args.mode == "inode":
        logger.info("Finding duplicates by inode.")
        source_by_inode_or_hash, source_by_filename, files_grouped_by_inode_or_hash = find_duplicates_by_inode(source_files, files_by_size, mode="inode")

    else:
        logger.error("Invalid mode specified.")
        raise ValueError("Invalid mode. Accepted modes are: 'hash', 'combined', 'inode'.")

    if len(files_grouped_by_inode_or_hash) == 0:
        logger.warning("No duplicates found.")
        raise ValueError("No duplicates found.")

    logger.info("Printing duplicates to console.")
    print_to_console(source_by_inode_or_hash, files_grouped_by_inode_or_hash)

    if args.remove or args.purge:
        logger.info("Removing or purging duplicate files.")
        delete_list = []
        for file in files_grouped_by_inode_or_hash:
            delete_list.append("".join("%s" % filename for filename in file.keys()))
        if args.purge:
            delete_list.append("".join("%s" % filename for filename in original_source_files))
        remove_or_purge_files(delete_list)

    if args.output:
        logger.info(f"Writing duplicates to output file: {args.output}.")
        with open(args.output, 'w') as csvfile:
            csvwriter = csv.writer(csvfile)
            for source_hash, source_path in source_by_inode_or_hash.items():
                if len(files_grouped_by_inode_or_hash[source_hash]) < 2:
                    continue
                for file in files_grouped_by_inode_or_hash[source_hash].keys():
                    csvwriter.writerow([source_path, file])
            for file in original_source_files:
                if file not in source_by_filename.keys():
                    csvwriter.writerow([file, ""])


def test_function():
    logger.info("Starting test function execution.")
    test_single_file = "test_file.txt"
    #test_multiple_files = ["test_file1.txt", "test_file2.txt", "test_file3.txt"]
    test_mixed_files_dirs = ["test_file1.txt", "test_file2.txt", "test_dir/test_file3.txt"]

    for func in args.functions:
        logger.info(f"Testing function: {func}")
        try:
            match func:
                case "print_to_console":
                    source_files = {"abc": "def", "ghi": "jkl"}
                    files_by_full_hash = {"abc": {"123": None, "456": None}}
                    eval(func)(source_files, files_by_full_hash)
                case "get_hash":
                    with open(test_single_file, "w") as f:
                        f.write("This is a test file.")
                    hash_output = eval(func)(test_single_file, first_chunk_only=True, hash_algo=hashlib.sha1)
                    logger.debug(f"Hash output: {hash_output}")
                    if hash_output != b'&\xd8/\x191\xcb\xdb\xd8<*hq\xb2\xce\xcd\\\xbc\xc8\xc2k':
                        raise ValueError("Hash output does not match expected output.")
                    logger.info("[PASS] Hash output matches expected output.")
                case "get_source_files":
                    logger.info("Generating test files for source files.")
                    test_paths = []
                    for file in test_mixed_files_dirs:
                        Path(os.path.dirname(file)).mkdir(parents=True, exist_ok=True)
                        test_paths.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), file))
                        with open(file, "w") as f:
                            f.write("This is a test file.")
                    args.source = test_paths
                    logger.debug(f"Source files: {eval(func)()}")
        except Exception as e:
            logger.error(f"Error while testing function {func}: {e}")
        finally:
            for file in test_mixed_files_dirs:
                try:
                    os.remove(file)
                    os.rmdir(os.path.dirname(file))
                except OSError:
                    pass
    logger.info("Test function execution completed.")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Duplicate File Finder",
        description="Performs a fast duplicate file search in the specified folder(s) "
        "allowing different operations on the duplicates found.",
    )
    parser.add_argument('--source', '-s',
                        help='Source file/folder(s) to find duplicates of.')
    parser.add_argument('--destinations', '-d', nargs='*',
                        help='Destination file/folder(s) to search for duplicates.')
    parser.add_argument('--mode', '-m', type=str, choices=['hash', 'combined', 'inode'], default='hash', 
                        help='Mode of comparison, inode is recommended for Hardlinks.')
    parser.add_argument('--input', '-i', type=str,
                        help='Input CSV file with list of files to search for duplicates.')
    parser.add_argument('--output', '-o', type=str,
                        help='Output CSV file with list of duplicates.')
    parser.add_argument('--remove', '-r', action='store_true',
                        help='Remove duplicates.')
    parser.add_argument('--purge', '-p', action='store_true',
                        help='Purge original and duplicates.')
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help='Dry run.')
    parser.add_argument('--log-environment', '-l', type=str, choices=['development', 'staging', 'production'],
                        help='Set the logging environment (development, staging, production).')
    parser.add_argument("--test", action="store_true",
                        help="Test mode. Only used with --functions.")
    parser.add_argument("--functions", "-f", nargs="*", 
                        help="Functions to test with --test.")
    parser.add_argument("--parallel-threads", "-t", type=int, 
                        help="Number of parallel threads to use.")
    parser.add_argument('--parallel-chunksize', '-c', type=int,
                        help='Chunk size for parallel processing.')
    args = parser.parse_args()

    # Set the logger based on the --log-environment argument
    if args.log_environment:
        logger = logging.getLogger(args.log_environment)
    logger.info("Logger initialized with environment: %s", args.log_environment or "root")

    validate_arguments()
    if args.test:
        test_function()
    else:
        check_for_duplicates()
