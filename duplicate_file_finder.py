#!/usr/bin/env python
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
import csv
import os
import sys
import hashlib
from collections import defaultdict
from inspect import getmembers, isfunction
from pathlib import Path


def validate_arguments():
    validate_source()
    validate_destinations()
    validate_input()
    validate_output()
    validate_test()
    # No need to validate purge and dry-run as they are boolean flags
    # No need to validate log file as it can be any file path
    # No need to validate verbose as it is a boolean flag

    print("All arguments are valid.")


def validate_source():
    # Check if source is provided and is a valid path
    if args.source:
        if not os.path.exists(args.source):
            raise ValueError(f"Source path '{args.source}' does not exist.")
        if not os.path.isdir(args.source) and not os.path.isfile(args.source):
            raise ValueError(f"Source path '{args.source}' is not a valid file or directory.")


def validate_destinations():
    # Check if destinations are provided and are valid paths
    if args.destinations:
        for dest in args.destinations:
            if not os.path.exists(dest):
                raise ValueError(f"Destination path '{dest}' does not exist.")
            if not os.path.isdir(dest) and not os.path.isfile(dest):
                raise ValueError(f"Destination path '{dest}' is not a valid file or directory.")


def validate_input():
    # Check if input CSV file is provided and has a .csv extension
    if args.input:
        if not args.input.endswith('.csv'):
            raise ValueError(f"Input file '{args.input}' must have a .csv extension.")
        if not os.path.isfile(args.input):
            raise ValueError(f"Input file '{args.input}' does not exist.")
            # Validate paths within the input CSV and ensure only one column per row
        with open(args.input, newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                if len(row) != 1:
                    raise ValueError(f"Input CSV file '{args.input}' must have exactly one column per row.")
                path = row[0]
                if not os.path.exists(path):
                    raise ValueError(f"Path '{path}' in input CSV does not exist.")
                if not os.path.isdir(path) and not os.path.isfile(path):
                    raise ValueError(f"Path '{path}' in input CSV is not a valid file or directory.")


def validate_output():
    # Check if output CSV file is provided and has a .csv extension
    if args.output and not args.output.endswith('.csv'):
        raise ValueError(f"Output file '{args.output}' must have a .csv extension.")


def validate_test():
    # Check if functions are provided in test mode
    print(type(args.functions))
    for func in args.functions:
        print(func)
    print([o[0] for o in getmembers(sys.modules[__name__]) if isfunction(o[1])])
    if args.test and not args.functions:
        raise ValueError("Test mode requires functions to be provided.")
    if not all(x in [o[0] for o in getmembers(sys.modules[__name__]) if isfunction(o[1])] for x in args.functions):
        raise ValueError("All functions provided for testing are not valid.")


def chunk_reader(fobj, chunk_size=1024):
    """ Generator that reads a file in chunks of bytes """
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk


def get_hash(filename, first_chunk_only=False, hash_algo=hashlib.sha1):
    hashobj = hash_algo()
    with open(filename, "rb") as f:
        if first_chunk_only:
            hashobj.update(f.read(1024))
        else:
            for chunk in chunk_reader(f):
                hashobj.update(chunk)
    return hashobj.digest()


def get_source_files():
    sources = []
    if args.source:
        sources = args.source
    elif args.input:
        with open(args.input, newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            sources = [row[0] for row in csvreader]
    source_files = []
    for source in sources:
        try:
            if os.path.isdir(source):
                for dirpath, _, filenames in os.walk(source):
                    for filename in filenames:
                        full_path = os.path.join(dirpath, filename)
                        try:
                            full_path = os.path.realpath(full_path)
                        except OSError:
                            continue
                        source_files.append(full_path)
            elif os.path.isfile(source):
                source_files.append(os.path.realpath(source))
        except Exception as e:
            print(f"Failed to get source files from {source}. {e}")
    return source_files


def find_duplicates_by_size(paths):
    source_files = get_source_file_sizes()
    source_matches = []
    files_by_size = defaultdict(dict)
    for path in paths:
        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                try:
                    # if the target is a symlink (soft one), this will
                    # dereference it - change the value to the actual target file
                    full_path = os.path.realpath(full_path)
                    file_size = os.path.getsize(full_path)
                except OSError:
                    # not accessible (permissions, etc) - pass on
                    continue
                if file_size in source_files.keys():
                    source_matches.append = source_files[file_size][0]
                    if len(files_by_size[file_size]) == 0:
                        files_by_size[file_size] = {}
                    files_by_size[file_size][full_path] = None
                # files_by_size[file_size].append(full_path)
    return source_matches, files_by_size


def get_source_file_sizes():
    source_sizes = defaultdict(list)
    for dirpath, _, filenames in os.walk(args.source):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            try:
                full_path = os.path.realpath(full_path)
                file_size = os.path.getsize(full_path)
            except OSError:
                continue
            source_sizes[file_size].append(full_path)
    return source_sizes


def find_duplicates_by_small_hash(source_files, files_by_size):
    source_small_hashes = defaultdict(list)
    source_matches = []
    for file in source_files:
        source_small_hashes[get_hash(file, first_chunk_only=True)].append(file)
    files_by_small_hash = defaultdict(dict)
    # For all files with the same file size, get their hash on the first 1024 bytes
    for file_size, files in files_by_size.items():
        if len(files) < 2:
            continue  # this file size is unique, no need to spend cpu cycles on it

        for filename in files:
            try:
                small_hash = get_hash(filename, first_chunk_only=True)
            except OSError:
                # the file access might've changed till the exec point got here
                continue
            if small_hash in source_small_hashes.keys():
                source_matches.append = source_small_hashes[small_hash][0]
                if len(files_by_small_hash[(file_size, small_hash)]) == 0:
                    files_by_small_hash[(file_size, small_hash)] = {}
                files_by_small_hash[(file_size, small_hash)][filename] = None
            # files_by_small_hash[(file_size, small_hash)].append(filename)
    return source_matches, files_by_small_hash


def find_duplicates_by_full_hash(source_files, files_by_small_hash):
    # For all files with the hash on the first 1024 bytes, get their hash on the full
    # file - collisions will be duplicates
    source_full_hashes = defaultdict(list)
    source_by_hash = {}
    source_by_filename = {}
    for file in source_files:
        source_full_hashes[get_hash(file, first_chunk_only=False)].append(file)
    files_by_full_hash = defaultdict(dict)
    for files in files_by_small_hash.values():
        if len(files) < 2:
            # the hash of the first 1k bytes is unique -> skip this file
            continue

        for filename in files:
            try:
                full_hash = get_hash(filename, first_chunk_only=False)
            except OSError:
                # the file access might've changed till the exec point got here
                continue

            # Add this file to the list of others sharing the same full hash
            if full_hash in source_full_hashes.keys():
                source_by_hash[full_hash] = source_full_hashes[full_hash][0]
                source_by_filename[source_full_hashes[full_hash][0]] = full_hash
                if len(files_by_full_hash[full_hash]) == 0:
                    files_by_full_hash[full_hash] = {}
                files_by_full_hash[full_hash][filename] = None
                print(files_by_full_hash.values())
            # files_by_full_hash[full_hash].append(filename)
    return source_by_hash, source_by_filename, files_by_full_hash


def remove_or_purge_files(delete_list):
    for file in delete_list:
            os.remove(file)


def print_to_console(source_files, files_by_full_hash):
    # Now, print a summary of all files that share a full hash
    for source_hash, source_path in source_files.items():
        # if len(file_list) < 2:
        #     # Only one file, it's unique
        #     continue
        # else:
        # More than one file share the same full hash
        # Turn [filea, fileb, filec] into
        # - filea
        # - fileb
        try:
            files_str = "\n".join("- %s" % file for file in files_by_full_hash[source_hash].keys())
            output_str = "Duplicate found for {0}:\n{1}\n".format(source_path, files_str)
        except KeyError:
            output_str = "No duplicates found for {0}\n".format(source_path)
        print(output_str)


def check_for_duplicates():

    original_source_files = get_source_files()
    source_files, files_by_size = find_duplicates_by_size(paths)
    if len(files_by_size) == 0:
        raise ValueError("No duplicates by size found.")
    source_files, files_by_small_hash = find_duplicates_by_small_hash(source_files, files_by_size)
    if len(files_by_small_hash) == 0:
        raise ValueError("No duplicates by small hash found.")
    source_by_hash, source_by_filename, files_by_full_hash = find_duplicates_by_full_hash(source_files, files_by_small_hash)
    if len(files_by_full_hash) == 0:
        raise ValueError("No duplicates by full hash found.")
    print_to_console(source_by_hash, files_by_full_hash)

    if args.remove or args.purge:
        delete_list = []
        for file in files_by_full_hash:
            delete_list.append("".join("%s" % filename for filename in file.keys()))
        if args.purge:
            delete_list.append("".join("%s" % filename for filename in original_source_files))
        remove_or_purge_files(delete_list)

    if args.output:
        with open(args.output, 'w') as csvfile:
            csvwriter = csv.writer(csvfile)
            for source_hash, source_path in source_files:
                if len(files_by_full_hash[source_hash]) < 2:
                    continue
                for file in files_by_full_hash[source_hash].keys():
                    csvwriter.writerow([source_path, file])
            for file in original_source_files:
                if file not in source_by_filename.keys():
                    csvwriter.writerow([file, ""])


def test_function():
    for func in args.functions:
        print(f"Testing function: {func}")
        match func:
            case "print_to_console":
                source_files = {"abc": "def", "ghi": "jkl"}
                files_by_full_hash = {"abc": {"123": None, "456": None}}
                eval(func)(source_files, files_by_full_hash)
            case "get_hash":
                try:
                    with open ("test_file.txt", "w") as f:
                        f.write("This is a test file.")
                    hash_output = eval(func)("test_file.txt", first_chunk_only=True, hash_algo=hashlib.sha1)
                    print(hash_output)
                    if hash_output != b'&\xd8/\x191\xcb\xdb\xd8<*hq\xb2\xce\xcd\\\xbc\xc8\xc2k':
                        raise ValueError("Hash output does not match expected output.")
                    else:
                        print("[PASS] Hash output matches expected output.")
                except Exception as e:
                    print(f"[FAIL] {e}")
                finally:
                    try:
                        os.remove("test_file.txt")
                    except OSError:
                        pass
            case "chunk_reader":
                print("Chunk reader is intended for use in get_hash function and not intended to test independently.")
            case "get_source_files":
                test_files = ["test_file1.txt", "test_file2.txt", "test_dir/test_file3.txt"]
                try:
                    print("Generating test files for source files.")
                    test_paths = []
                    for file in test_files:
                        try:
                            Path(os.path.dirname(file)).mkdir(parents=True, exist_ok=True)
                            test_paths.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), file))
                            print(file)
                            with open(file, "w") as f:
                                f.write("This is a test file.")
                        except OSError as e:
                            print(f"Failed to create test file {file}. {e}")
                    print("Simulating direct sources via --source argument.")
                    args.source = test_paths
                    print(eval(func)())
                except Exception as e:
                    print(f"[FAIL] {e}")
                finally:
                    for file in test_files:
                        try:
                            os.remove(file)
                        except OSError:
                            pass
                        try:
                            os.rmdir(os.path.dirname(file))
                        except OSError:
                            pass



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Duplicate File Finder',
        description='Performs a fast duplicate file search in the specified folder(s) '
                    'allowing different operations on the duplicates found.'
    )
    parser.add_argument('--source', '-s', help='Source file/folder(s) to find duplicates of.')
    parser.add_argument('--destinations', '-d', nargs='*', help='Destination file/folder(s) to search for duplicates.')
    parser.add_argument('--input', '-i', help='Input CSV file with list of files to search for duplicates.')
    parser.add_argument('--output', '-o', help='Output CSV file with list of duplicates.')
    parser.add_argument('--remove', '-r', action='store_true', help='Remove duplicates.')
    parser.add_argument('--purge', '-p', action='store_true', help='Purge original and duplicates.')
    parser.add_argument('--dry-run', '-n', action='store_true', help='Dry run.')
    parser.add_argument('--log', '-l', help='Log file to output results.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output.')
    parser.add_argument('--test', '-t', action='store_true', help='Test mode. Only used with --functions.')
    parser.add_argument('--functions', '-f', nargs='*', help='Functions to test with --test.')
    args = parser.parse_args()

    validate_arguments()
    test_function()
    #check_for_duplicates()
