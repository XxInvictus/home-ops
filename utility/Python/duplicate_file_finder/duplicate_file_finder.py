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
import mmap
import logging.config
from collections import defaultdict
from itertools import repeat
from multiprocessing.pool import ThreadPool
from pathlib import Path
import yaml

# Load the config file
with open('logconf.yaml', 'rt') as f:
    config = yaml.safe_load(f.read())

# Configure the logging module with the config file
logging.config.dictConfig(config)
logger = logging.getLogger()

def log_and_raise_error(message):
    """
    Logs an error message and raises a ValueError.
    :param message: The error message to log and raise.
    """
    logger.error(message)
    raise ValueError(message)


class ArgumentValidator:
    """
    Validates command-line arguments for the duplicate file finder.
    """
    def __init__(self, validation_args, validation_logger):
        """
        Initializes the ArgumentValidator with arguments and a logger.
        :param validation_args: Parsed command-line arguments.
        :param validation_logger: Logger instance for logging messages.
        """
        self.args = validation_args
        self.logger = validation_logger
        self.validation_rules = {
            "source": self._validate_path,
            "destinations": self._validate_path,
            "input": self._validate_input,
            "output": self._validate_output,
            "functions": self._validate_functions,
            "mode": self._validate_mode,
            "parallel_threads": self._validate_parallel_threads,
            "log_environment": self._validate_log_environment,
        }
        self.custom_test_cases = [
            "complete_full_hash",
            "complete_inode",
            "complete_combined_hash_by_inode"
        ]

    def validate(self):
        """
        Orchestrates the validation of all arguments based on the defined rules.
        """
        self.logger.info("Validating arguments...")
        for arg_name, validation_method in self.validation_rules.items():
            arg_value = getattr(self.args, arg_name, None)
            if arg_value:
                # noinspection PyArgumentList
                validation_method(arg_name, arg_value)
        self.logger.info("All arguments are valid.")

    def _validate_path(self, arg_name, path_list):
        """
        Validates a list of paths to ensure they exist and are valid.
        :param arg_name: Name of the argument being validated.
        :param path_list: List of paths to validate.
        """
        for path in path_list:
            path_obj = Path(path)
            if not path_obj.exists():
                self._log_and_raise_error(f"{arg_name.capitalize()} path '{path}' does not exist.")
            if not path_obj.is_dir() and not path_obj.is_file():
                self._log_and_raise_error(
                    f"{arg_name.capitalize()} path '{path}' is not a valid file or directory."
                )

    def _validate_input(self, arg_name, input_file):
        """
        Validates the input CSV file.
        :param arg_name: Name of the argument being validated.
        :param input_file: Path to the input file.
        """
        if not input_file.endswith('.csv'):
            self._log_and_raise_error(
                f"{arg_name.capitalize()} file '{input_file}' must have a .csv extension."
            )
        if not Path(input_file).is_file():
            self._log_and_raise_error(
                f"{arg_name.capitalize()} file '{input_file}' does not exist."
            )

    def _validate_output(self, arg_name, output_file):
        """
        Validates the output file.
        :param arg_name: Name of the argument being validated.
        :param output_file: Path to the output file.
        """
        if not output_file.endswith('.csv'):
            self._log_and_raise_error(
                f"{arg_name.capitalize()} file '{output_file}' must have a .csv extension."
            )

    def _validate_functions(self, arg_name, functions):
        """
        Validates the test functions provided.
        :param arg_name: Name of the argument being validated.
        :param functions: List of function names to validate.
        """
        import sys
        from inspect import getmembers, isfunction
        valid_functions = [o[0] for o in getmembers(sys.modules[__name__]) if isfunction(o[1])]
        valid_functions.extend(self.custom_test_cases)
        if not all(func in valid_functions for func in functions):
            self._log_and_raise_error(
                f"One or more {arg_name} are not valid functions."
            )

    def _validate_mode(self, arg_name, mode):
        """
        Validates the mode argument to ensure it is one of the allowed values.
        :param arg_name: Name of the argument being validated.
        :param mode: The mode value to validate.
        """
        valid_modes = ["hash", "combined", "inode"]
        if mode not in valid_modes:
            self._log_and_raise_error(
                f"Invalid {arg_name} '{mode}'. Valid options are: {', '.join(valid_modes)}."
            )

    def _validate_parallel_threads(self, arg_name, threads):
        """
        Validates the parallel threads argument to ensure it is a positive integer.
        :param arg_name: Name of the argument being validated.
        :param threads: The number of threads to validate.
        """
        if not isinstance(threads, int) or threads <= 0:
            self._log_and_raise_error(
                f"{arg_name.capitalize()} must be a positive integer. Provided: {threads}."
            )

    def _validate_log_environment(self, arg_name, environment):
        """
        Validates the log environment argument to ensure it is one of the allowed values.
        :param arg_name: Name of the argument being validated.
        :param environment: The log environment value to validate.
        """
        valid_environments = ["development", "staging", "production"]
        if environment not in valid_environments:
            self._log_and_raise_error(
                f"Invalid {arg_name} '{environment}'. Valid options are: {', '.join(
                    valid_environments
                )}."
            )

    def _log_and_raise_error(self, message):
        """
        Logs an error message and raises a ValueError.
        :param message: The error message to log and raise.
        """
        self.logger.error(message)
        raise ValueError(message)


# noinspection SpellCheckingInspection
def chunk_reader(fobj, chunk_size=1024):
    """
    Reads a file in chunks of bytes.

    :param fobj: File object to read from.
    :param chunk_size: Size of each chunk in bytes.
    :yield: A chunk of the file.
    """
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Reading file in chunks of size {chunk_size}.")
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("End of file reached.")
            return
        yield chunk


def get_hash(filename, first_chunk_only=False, hash_algo=hashlib.sha1):
    """
    Calculates the hash of a file using memory-mapped files for improved performance.

    :param filename: Path to the file.
    :param first_chunk_only: If True, only the first chunk of the file is hashed.
    :param hash_algo: Hashing algorithm to use.
    :return: The calculated hash as a byte string.
    """
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Calculating hash for file: {filename}, first_chunk_only={first_chunk_only}.")
    # noinspection SpellCheckingInspection
    hashobj = hash_algo()
    try:
        with open(filename, "rb") as open_file:
            # Memory-map the file
            # noinspection SpellCheckingInspection
            with mmap.mmap(open_file.fileno(), length=0, access=mmap.ACCESS_READ) as mmapped_file:
                if first_chunk_only:
                    hashobj.update(mmapped_file[:1024])  # Hash only the first 1024 bytes
                else:
                    hashobj.update(mmapped_file)  # Hash the entire file
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Hash calculated successfully for file: {filename}.")
    except OSError as e:
        logger.error(f"Error reading file {filename}: {e}")
        raise
    return hashobj.digest()


def multi_hash(filename, first_chunk_only=False):
    """
    Calculates the hash of a file and returns it along with the filename.

    :param filename: Path to the file.
    :param first_chunk_only: If True, only the first chunk of the file is hashed.
    :return: A tuple containing the filename and its hash.
    """
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Calculating hash for file: {filename}, first_chunk_only={first_chunk_only}")
    try:
        file_hash = get_hash(filename, first_chunk_only)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Hash for file {filename}: {file_hash}")
    except OSError as e:
        logger.error(f"Error calculating hash for file {filename}: {e}")
        file_hash = None
    return filename, file_hash


def generate_hash_list_with_pool(pool, first_chunk, input_files, output_format="set"):
    """
    Generates a list of b64 encoded hashes for the given files using a thread pool.

    :param pool: ThreadPool for parallel processing.
    :param first_chunk: Whether the hash is first chunk only.
    :param input_files: List of files to process.
    :param output_format: Format of the output ('set' or 'dict').
    :return: A set of sets containing file b64-encoded hashes and their corresponding filenames.
    """
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Generating hash list with pool for processing.")
    hash_set = set()
    processing_pool = pool.starmap(
        multi_hash, zip(input_files, repeat(first_chunk)), chunksize=args.parallel_chunksize
    )

    for result in processing_pool:
        if not result[1]:
            continue
        base64_hash = base64.b64encode(result[1])
        hash_set.add((result[0], base64_hash))

    if output_format == "dict":
        hash_dict = defaultdict(set)
        for filename, hash_value in hash_set:
            hash_dict[hash_value].add(Path(filename).resolve(strict=True))
        hash_output = hash_dict
    else:
        hash_output = hash_set

    return hash_output


def build_files_by_hash_output(source_hash_inode_list, destination_hash_inode_list):
    """
    Builds a dictionary of files grouped by their hashes.

    :param source_hash_inode_list: List of source files with their hashes.
    :param destination_hash_inode_list: List of destination files with their hashes.
    :return: A dictionary mapping hashes to lists of filenames.
    """
    logger.info("Building files by hash output.")
    files_by_hash_inode = defaultdict(lambda: defaultdict(set))
    source_matches = []
    for filename, destination_hash_inode_value in destination_hash_inode_list:
        if destination_hash_inode_value in source_hash_inode_list:
            for source_file in source_hash_inode_list[destination_hash_inode_value]:
                if source_file not in source_matches:
                    source_matches.append(source_file)
                files_by_hash_inode[destination_hash_inode_value][source_file].add(filename)
    logger.info(f"Built {len(files_by_hash_inode)} groups of files by hash.")
    return source_matches, files_by_hash_inode


def traverse_directory(directory, recurse_symlinks=True):
    """
    Traverses a directory and retrieves all file paths.

    :param directory: Path to the directory.
    :param recurse_symlinks: Whether to follow symbolic links.
    :return: List of file paths.
    """
    return [
        entry.resolve(strict=True) for entry in Path(directory).rglob(
            '*', recurse_symlinks=recurse_symlinks
        ) if entry.is_file()
    ]


def get_source_files():
    """
    Retrieves the list of source files from the provided source path or input CSV file.

    :return: A list of source file paths.
    """
    logger.info("Retrieving source files.")
    if args.source:
        sources = args.source
    elif args.input:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Reading sources from input CSV: {args.input}.")
        with open(args.input, newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            sources = [row[0] for row in csvreader]
    else:
        sources = None
        log_and_raise_error("No source provided.")

    source_files = []
    for source in sources:
        try:
            source_path = Path(source)
            if source_path.is_dir():
                source_files.extend(traverse_directory(source_path))
            elif source_path.is_file():
                source_files.append(source_path.resolve(strict=True))
        except Exception as e:
            logger.error(f"Failed to get source files from {source}: {e}")
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Retrieved {len(source_files)} source files.")
    return source_files


def find_duplicates_by_size(source_list, destination_list):
    """
    Finds duplicate files based on their sizes.

    :param source_list: List of source file paths.
    :param destination_list: List of destination file paths.
    :return: A tuple containing source matches and a dictionary of files grouped by size.
    """
    logger.info("Finding duplicates by file size.")
    source_files = get_source_file_sizes(source_list)
    source_matches = []
    full_paths = []
    files_by_size = defaultdict(lambda: defaultdict(list))
    for destination in destination_list:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Processing destination: {destination}.")
        try:
            if Path(destination).is_file():
                full_paths.append(Path(destination).resolve(strict=True))
            elif Path(destination).is_dir():
                for dirpath, _, filenames in Path(destination).walk(on_error=print):
                    for filename in filenames:
                        full_path = Path.joinpath(dirpath, filename)
                        full_paths.append(full_path.resolve(strict=True))
        except OSError as e:
            logger.warning(f"Failed to access file {destination} for realpath: {e}")
    logger.info(f"Retrieved {len(full_paths)} destination files for size comparison.")
    for full_path in full_paths:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Getting size for file: {full_path}.")
        file_size = Path(full_path).stat().st_size
        if file_size in source_files.keys():
            for source_file in source_files[file_size]:
                source_matches.append(source_file)
                files_by_size[file_size][source_file].append(str(full_path))
    logger.info(f"Found {len(files_by_size)} file groups with duplicate sizes.")
    if len(files_by_size) == 0:
        log_and_raise_error("No duplicates by size found.")
    return source_matches, files_by_size

# source_matches syntax is [sourcefile1, sourcefile2]
# files_by_size syntax is {size: {original: [duplicates]}}


def filter_by_filetype(source_files, files_by_size):
    """
    Filters destination files to include only those with the same file type as the source files.

    :param source_files: List of source file paths.
    :param files_by_size: Dictionary of files grouped by size.
    :return: A filtered dictionary of files grouped by size with matching file types.
    """
    logger.info("Filtering destinations by file type.")
    filtered_files_by_size = defaultdict(lambda: defaultdict(list))

    for file_size, files in files_by_size.items():
        for source_file in source_files:
            source_suffix = Path(source_file).suffix
            for original, destinations in files.items():
                filtered_destinations = [
                    dest for dest in destinations if Path(dest).suffix == source_suffix
                ]
                if filtered_destinations:
                    filtered_files_by_size[file_size][original].extend(filtered_destinations)

    logger.info(f"Filtered {len(filtered_files_by_size)} file groups by file type.")
    return filtered_files_by_size


def get_source_file_sizes(source_list):
    """
    Retrieves file sizes from the source directory.

    :return: A dictionary mapping file sizes to lists of file paths.
    """
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Retrieving file sizes from source directory.")
    source_sizes = defaultdict(list)

    for source in source_list:
        try:
            source_path = Path(source)
            if source_path.is_file():
                source_sizes[source_path.stat().st_size].append(
                    str(source_path.resolve(strict=True))
                )
            elif source_path.is_dir():
                for entry in traverse_directory(source_path):
                    source_sizes[entry.stat().st_size].append(str(entry))
        except OSError as e:
            logger.warning(f"Failed to access file {source} for realpath: {e}")
    logger.info(f"Retrieved sizes for {len(source_sizes)} unique file sizes.")
    return source_sizes


def find_duplicates_by_small_hash(source_files, files_by_size, pool):
    """
    Finds duplicate files based on their small hash values.

    :param source_files: List of source file paths.
    :param files_by_size: Dictionary of files grouped by size.
    :param pool: ThreadPool for parallel processing.
    :return: A tuple containing source matches and a dictionary of files grouped by small hash.
    """
    # source_matches syntax is {size: [sourcefile1, sourcefile2]}
    # files_by_size syntax is {size: {original: [duplicates]}}
    logger.info("Finding duplicates by small hash.")
    logger.info("Calculating small hashes for source files.")
    source_small_hashes = generate_hash_list_with_pool(
        pool, True, source_files, "dict"
    )

    files_by_small_hash = defaultdict(lambda: defaultdict(set))
    source_matches = []
    logger.info("Calculating small hashes for destination files.")

    for file_size, files in files_by_size.items():
        if len(files) == 0:
            continue
        destination_hash_list = set()
        for size_matched_files in files.values():
            if len(size_matched_files) == 0:
                continue
            destination_hashes = generate_hash_list_with_pool(
                pool, True, size_matched_files
            )
            destination_hash_list.update(destination_hashes)
            source_matches, files_by_small_hash = build_files_by_hash_output(
                source_small_hashes, destination_hash_list
            )

    logger.info(
        f"Found {len(files_by_small_hash.items())} groups of duplicates by small hash."
    )
    # source_matches format is [filename]
    # files_by_small_hash format is {small_hash: {source_file: [filename1, filename2]}}
    if len(files_by_small_hash) == 0:
        log_and_raise_error("No duplicates by small hash found.")
    return source_matches, files_by_small_hash


def find_duplicates_by_full_hash(source_files, files_by_small_hash, pool):
    """
    Finds duplicate files based on their full hash values.

    :param source_files: List of source file paths.
    :param files_by_small_hash: Dictionary of files grouped by small hash.
    :param pool: ThreadPool for parallel processing.
    :return: A tuple containing source matches, source by filename,
        and a dictionary of files grouped by full hash.
    """
    logger.info("Finding duplicates by full hash.")
    logger.info("Calculating full hashes for source files.")
    source_full_hashes = generate_hash_list_with_pool(pool, False, source_files, "dict")

    files_by_full_hash = defaultdict(lambda: defaultdict(set))
    source_matches = []
    logger.info("Calculating full hashes for destination files.")
    for file_size, files in files_by_small_hash.items():
        if len(files) == 0:
            continue
        destination_hash_list = set()
        for destinations in files.values():
            destination_hashes = generate_hash_list_with_pool(pool, False, destinations)
            destination_hash_list.update(destination_hashes)
            source_matches, files_by_full_hash = build_files_by_hash_output(
                source_full_hashes, destination_hash_list
            )

    logger.info(f"Found {len(files_by_full_hash)} groups of duplicates by full hash.")
    if len(files_by_full_hash) == 0:
        log_and_raise_error("No duplicates by full hash found.")
    return source_matches, files_by_full_hash


def get_file_inode(file):
    """
    Retrieves the inode of a file.

    :param file: Path to the file.
    :return: A tuple containing the file path and its inode.
    """
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Getting inode for file: {file}")
    if not Path(file).exists():
        logger.warning(f"File does not exist: {file}")
        return file, None
    try:
        inode = Path(file).stat().st_ino
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Inode for file {file}: {inode}")
        return file, inode
    except OSError as e:
        logger.error(f"Error getting inode for file {file}: {e}")
        return file, None


def find_duplicates_by_inode(source_files, files_input, pool, mode="inode"):
    """
    Finds duplicate files based on their inodes.

    :param source_files: List of source file paths.
    :param files_input: Dictionary of files grouped by size or hash.
    :param mode: Mode of operation ('combined' or 'inode').
    :param pool: ThreadPool for parallel processing.
    :return: A tuple containing source matches, source by filename,
        and a dictionary of files grouped by inode.
    """
    logger.info("Finding duplicates by inode.")

    source_inodes = defaultdict(set)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Getting inodes for source files.")
    for file, inode in pool.imap_unordered(
        get_file_inode, source_files, chunksize=args.parallel_chunksize
    ):
        if inode is None:
            continue
        source_inodes[inode].add(file)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Getting inodes for destination files.")
    destination_inode_list = set()
    for _, files in files_input.items():
        if len(files) == 0:
            continue
        if mode == "inode":
            destination_inode_list = set()
            for size_matched_files in files.values():
                if len(size_matched_files) == 0:
                    continue
                for file, inode in pool.imap_unordered(
                        get_file_inode, size_matched_files, chunksize=args.parallel_chunksize
                ):
                    if inode is None:
                        continue
                    destination_inode_list.add((file, inode))
        elif mode == "combined":
            for source, destinations in files.items():
                if len(destinations) == 0:
                    continue
                normalised_destinations = [
                    Path(destination).resolve(strict=True) for destination in destinations
                ]
                destination_inode_list = set()
                for file, inode in pool.imap_unordered(
                    get_file_inode, normalised_destinations, chunksize=args.parallel_chunksize
                ):
                    if inode is None:
                        continue
                    destination_inode_list.add((file, inode))
                    # inode_list format is [(filename, inode)]
        else:
            log_and_raise_error(f"Invalid mode specified: {mode}. Use 'combined' or 'inode'.")

    if len(destination_inode_list) == 0:
        log_and_raise_error("No destination files found for inode calculation.")
    source_matches, files_by_inode = build_files_by_hash_output(
        source_inodes, destination_inode_list
    )
    logger.info(f"Found {len(files_by_inode)} groups of duplicates by inode.")
    # source_by_inode format is {inode: filename}
    # source_by_filename format is {filename: inode}
    # files_by_inode format is {inode: {filename: None}}
    if len(files_by_inode) == 0:
        log_and_raise_error("No duplicates by inode found.")
    return source_matches, files_by_inode


def remove_or_purge_files(output_files, source_files):
    """
    Removes or lists files to be deleted based on the --dry-run argument.
    Logs non-matching file types in the parent directory if it isn't empty.

    :param output_files: Dictionary of files grouped by inode or hash.
    :param source_files: List of source file paths.
    """
    logger.info("Removing or purging duplicate files.")
    delete_list = []
    if args.remove_mode in ("dest_only", "all"):
        for _, files in output_files.items():
            for _, destinations in files.items():
                delete_list.append("".join(f"{destination}" for destination in destinations))
    if args.remove_mode in ("source_only", "all"):
        delete_list.append("".join(f"{source}" for source in source_files))
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Files to be deleted: {delete_list}")

    if args.dry_run:
        logger.info("Dry run enabled. The following files would be removed:")
        [logger.info(f"File: {file}") for file in delete_list]
    else:
        logger.info("Starting file removal process.")
        for file in delete_list:
            try:
                file_path = Path(file)
                file_path.unlink()
                logger.info(f"Successfully removed file: {file}")

                if args.parent_check:
                    # Check if the parent directory is empty
                    parent_dir = file_path.parent
                    if not any(parent_dir.iterdir()):
                        parent_dir.rmdir()
                        logger.info(f"Removed empty parent directory: {parent_dir}")
                    else:
                        # Log files in the parent directory that don't match the file type
                        deleted_file_suffix = file_path.suffix
                        non_matching_files = [
                            f for f in parent_dir.iterdir()
                            if f.is_file() and f.suffix != deleted_file_suffix
                        ]
                        if non_matching_files:
                            logger.info(
                                f"Parent directory '{parent_dir}' is not empty. "
                                f"Files with non-matching file types: {', '.join(map(str, non_matching_files))}"
                            )
            except OSError as e:
                logger.error(f"Failed to remove file or directory {file}: {e}")


def print_to_console(source_matches, files_by_inode_or_hash):
    """
    Prints duplicate files to the console.

    :param source_matches: List of source files that have duplicates.
    :param files_by_inode_or_hash: Dictionary mapping inodes or hashes to lists of duplicate files.
    """
    logger.info("Printing duplicates to console.")
    if not source_matches:
        log_and_raise_error("No source matches found.")
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Printing source matches to console.")
        for source_file in source_matches:
            logger.debug(f"Source file: {source_file}")
        logger.debug("Printing duplicate files to console.")
    for source_identifier, matches_by_source in files_by_inode_or_hash.items():
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Source identifier: {source_identifier}")
        for source_file, matches in matches_by_source.items():
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Source file: {source_file}")
            for match in matches:
                logger.info(f"Duplicate found for {source_file}: {match}")


def check_for_duplicates(pool):
    """
    Main function to check for duplicate files based on the specified mode.
    Handles the entire process of finding duplicates and performing actions on them.
    """
    logger.info("Starting duplicate check process.")
    original_source_files = get_source_files()

    source_files, files_by_size = find_duplicates_by_size(original_source_files, args.destinations)

    if args.filter_by_filetype:
        files_by_size = filter_by_filetype(source_files, files_by_size)

    if args.mode == "hash":
        source_files, files_by_small_hash = find_duplicates_by_small_hash(
            source_files, files_by_size, pool
        )
        source_matches, files_by_inode_or_hash = find_duplicates_by_full_hash(
            source_files, files_by_small_hash, pool
        )
    elif args.mode == "combined":
        source_files, files_by_small_hash = find_duplicates_by_small_hash(
            source_files, files_by_size, pool
        )
        source_matches, files_by_inode_or_hash = find_duplicates_by_inode(
            source_files, files_by_small_hash, pool, mode="combined"
        )
    elif args.mode == "inode":
        source_matches, files_by_inode_or_hash = find_duplicates_by_inode(
            source_files, files_by_size, pool, mode="inode"
        )
    else:
        source_matches = files_by_inode_or_hash = None
        log_and_raise_error("Invalid mode specified. Use 'hash', 'combined', or 'inode'.")

    if len(source_matches) == 0:
        log_and_raise_error("No source matches found.")
    if len(files_by_inode_or_hash) == 0:
        log_and_raise_error("No duplicates found.")

    print_to_console(source_matches, files_by_inode_or_hash)

    if args.remove_mode:
        remove_or_purge_files(files_by_inode_or_hash, original_source_files)

    if args.output:
        logger.info(f"Writing duplicates to output file: {args.output}.")
        with open(args.output, 'w') as csvfile:
            csvwriter = csv.writer(csvfile)
            for source_identifier, matches_by_source in files_by_inode_or_hash.items():
                for source_file, matches in matches_by_source.items():
                    csvwriter.writerow([source_identifier, source_file, matches])


def generate_test_hash_or_inode_input_output(source_files, destination_files, index_count=1):
    """
    Generates a test hash or inode input/output mapping for testing purposes.

    :param source_files: List of source file paths.
    :param destination_files: List of destination file paths.
    :param index_count: Number of indices to generate.
    :return: A dictionary mapping hashes or inodes to lists of source and destination files.
    """
    test_hash_or_inode_input_output = defaultdict(lambda: defaultdict(list))
    logger.info("Generating test hash or inode input/output mapping.")
    source_count = 0
    while index_count > 0:
        for source_file in source_files:
            source_full_path = Path.joinpath(
                Path.cwd(), Path(source_file).with_stem(
                    f"{Path(source_file).stem}_{source_count}"
                )
            )
            for destination_file in destination_files:
                destination_full_path = Path.joinpath(
                    Path.cwd(), Path(destination_file).with_stem(
                        f"{Path(destination_file).stem}_{source_count}"
                    )
                )
                test_hash_or_inode_input_output[index_count][source_full_path].append(
                    destination_full_path
                )
            source_count += 1
        index_count -= 1
    return test_hash_or_inode_input_output


def generate_test_hash_or_inode_output_validation_string(
    index_type, test_hash_or_inode_input_output, index_values=None
):
    """
    Generates a validation string for test hash or inode output.

    :return: A string representing the validation output.
    """
    validation_string = defaultdict(lambda: defaultdict(set))
    match index_type:
        case "small_hash":
            # noinspection SpellCheckingInspection
            index = b'My5ENSKDEvcy9pXariwU03kozg0='
        case "full_hash":
            # noinspection SpellCheckingInspection
            index = b"IhGErg9dviNS5WO6UEDmQ1eHS7Q="
        case "by_inode":
            index = "unknown"
        case _:
            index = None
            log_and_raise_error("Invalid index type specified.")
    source_list = []
    destination_list = defaultdict(set)
    for hash_match in test_hash_or_inode_input_output.values():
        for source, destinations in hash_match.items():
            source_list.append(source)
            if index_type == "by_inode":
                destination_list[source].update(destinations)
            elif index_type in ("full_hash", "small_hash"):
                destination_list["all"].update(destinations)
    if index_type == "by_inode":
        dict_index = index_values
    elif index_type in ("full_hash", "small_hash"):
        dict_index = [index]
    else:
        dict_index = None
    if dict_index is None:
        log_and_raise_error("Invalid index values specified.")
    for identifier in dict_index:
        for source in source_list:
            if index_type == "by_inode":
                source_inode = get_file_inode(source)[1]
                validation_string[source_inode][source].update(destination_list[source])
            elif index_type in ("full_hash", "small_hash"):
                validation_string[identifier][source].update(destination_list["all"])
    return validation_string


def test_folder_file_generator(file, test_string_iterations=1, link_type=None, link_target=None):
    """
    Creates a directory structure and writes test content to the file.
    Optionally creates a hardlink or symlink for inode testing.
    Returns separate lists of created files and directories.

    :param file: Path to the test file.
    :param test_string_iterations: Number of iterations for the test string.
    :param link_type: Type of link to create ('hardlink' or 'symlink').
    :param link_target: Target file for the link.
    :return: A tuple containing two lists: (created_files, created_dirs).
    """
    created_files = []
    created_dirs = []
    file_path = Path(file).resolve()

    # Check and create parent directories if they don't exist
    if not file_path.parent.exists():
        file_path.parent.mkdir(parents=True, exist_ok=True)
        created_dirs.append(str(file_path.parent))

    if link_type and link_target:
        link_target_path = Path(link_target).resolve()
        if not link_target_path.exists():
            raise ValueError(f"Link target '{link_target}' does not exist.")
        if link_type == "hardlink":
            file_path.hardlink_to(link_target_path)
        elif link_type == "symlink":
            file_path.symlink_to(link_target_path)
        else:
            raise ValueError(f"Invalid link type: {link_type}. Use 'hardlink' or 'symlink'.")
        created_files.append(str(file_path))
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"{link_type.capitalize()} created: {file_path} -> {link_target_path}")
    else:
        # Create the file only if it doesn't already exist
        if not file_path.exists():
            test_file_contents = "This is a test file." * test_string_iterations
            with open(file_path, "w") as open_file:
                open_file.write(test_file_contents)
            created_files.append(str(file_path))
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Test file created: {file_path}")

    return created_files, created_dirs


def output_test_results(success = True, actual_output = None, expected_output = None):
    """
    Outputs the results of the test cases.
    :param success: Boolean indicating if the test was successful.
    :param actual_output: The actual output from the test case.
    :param expected_output: The expected output for comparison.
    """
    if success:
        logger.info("[PASS] Actual Output matches Expected Output.")
    else:
        logger.error("[FAIL] Actual Output does NOT match Expected Output.")
        logger.error(f"Actual Output: {actual_output}")
        logger.error(f"Expected Output: {expected_output}")
        raise AssertionError("Test case failed.")


def cleanup_test_files(files, directories):
    """
    Cleans up test files and directories.
    Ensures all files are removed before attempting to remove directories.

    :param files: List of file paths to remove.
    :param directories: List of directory paths to remove.
    """
    logger.info("Cleaning up test files and directories.")

    # Remove files first
    for file in files:
        try:
            file_path = Path(file)
            if file_path.exists() and file_path.is_file():
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Removing file: {file}")
                file_path.unlink()
        except OSError as e:
            logger.warning(f"Failed to remove file {file}: {e}")

    # Remove directories after files
    for directory in directories:
        try:
            dir_path = Path(directory)
            if dir_path.exists() and dir_path.is_dir():
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Removing directory: {directory}")
                dir_path.rmdir()
        except OSError as e:
            logger.warning(f"Failed to remove directory {directory}: {e}")


def test_function(pool):
    """
    Executes test cases for the specified functions.
    Validates the correctness of the functions using predefined test cases.
    """
    logger.info("Starting test function execution.")
    test_mixed_files_dirs = ["test_file1.txt", "test_file2.txt", "test_dir/test_file3.txt"]
    test_source_files = ["test_source/test_file1.txt", "test_source/test_file2.txt"]
    test_destinations = ["test_dest/test_file1.txt", "test_dest/test_file2.txt"]

    for func in args.functions:
        logger.info(f"Testing function: {func}")
        created_files = []
        created_dirs = []
        try:
            match func:
                case "print_to_console":
                    logger.info("Generating test files for print_to_console.")
                    for file in test_mixed_files_dirs:
                        files, dirs = test_folder_file_generator(file)
                        created_files.extend(files)
                        created_dirs.extend(dirs)
                    test_hash_or_inode_input_output = generate_test_hash_or_inode_input_output(
                        test_source_files, test_destinations
                    )
                    eval(func)(test_mixed_files_dirs, test_hash_or_inode_input_output)

                case "get_hash":
                    files, dirs = test_folder_file_generator(test_mixed_files_dirs[0])
                    created_files.extend(files)
                    created_dirs.extend(dirs)
                    hash_output = eval(func)(
                        test_mixed_files_dirs[0], first_chunk_only=True, hash_algo=hashlib.sha1
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Hash output: {hash_output}")
                    output_test_results(
                        hash_output == b"&\xd8/\x191\xcb\xdb\xd8<*hq\xb2\xce\xcd\\\xbc\xc8\xc2k",
                        hash_output,
                        b"&\xd8/\x191\xcb\xdb\xd8<*hq\xb2\xce\xcd\\\xbc\xc8\xc2k"
                    )

                case "get_source_files":
                    logger.info("Generating test files for source files.")
                    for file in test_mixed_files_dirs:
                        files, dirs = test_folder_file_generator(file)
                        created_files.extend(files)
                        created_dirs.extend(dirs)
                    args.source = [Path(file).resolve() for file in test_mixed_files_dirs]
                    source_files = eval(func)()
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Source files: {source_files}")
                    output_test_results(
                        len(source_files) == len(test_mixed_files_dirs),
                        len(source_files), len(test_mixed_files_dirs)
                    )

                case "find_duplicates_by_size":
                    logger.info("Generating test files for find_duplicates_by_size.")
                    for file in test_source_files + test_destinations:
                        files, dirs = test_folder_file_generator(file)
                        created_files.extend(files)
                        created_dirs.extend(dirs)
                    args.source = test_source_files
                    args.destinations = test_destinations
                    original_source_files = get_source_files()
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Source files: {original_source_files}")
                    source_matches, files_by_size = eval(func)(
                        original_source_files, args.destinations
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Source matches: {source_matches}")
                        logger.debug(f"Files by size: {files_by_size}")

                case (
                    "find_duplicates_by_small_hash"
                    | "find_duplicates_by_full_hash"
                    | "find_duplicates_by_inode"
                ):
                    logger.info(f"Generating test files for {func}.")
                    source_matches = []
                    index_values = set()
                    test_hash_or_inode_input_output = generate_test_hash_or_inode_input_output(
                        test_source_files, test_destinations
                    )
                    for hash_match in test_hash_or_inode_input_output.values():
                        for source, destinations in hash_match.items():
                            # Generate source files
                            files, dirs = test_folder_file_generator(source, 100)
                            created_files.extend(files)
                            created_dirs.extend(dirs)
                            if func == "find_duplicates_by_inode":
                                index_values.add(get_file_inode(source)[1])
                            for destination in destinations:
                                # Generate destination files or links
                                if func == "find_duplicates_by_inode":
                                    files, dirs = test_folder_file_generator(
                                        destination, link_type="hardlink", link_target=source
                                    )
                                else:
                                    files, dirs = test_folder_file_generator(destination, 100)
                                created_files.extend(files)
                                created_dirs.extend(dirs)
                            source_matches.append(source)

                    source_matches, files_by_hash_or_inode = eval(func)(
                        source_matches, test_hash_or_inode_input_output, pool
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Source matches: {source_matches}")
                        logger.debug(
                            f"Files by {' '.join(func.split('_')[-2:])}: {files_by_hash_or_inode}"
                        )

                    validation_string = generate_test_hash_or_inode_output_validation_string(
                        "_".join(func.split("_")[-2:]),
                        test_hash_or_inode_input_output, index_values
                    )
                    output_test_results(
                        dict(files_by_hash_or_inode) == dict(validation_string),
                        files_by_hash_or_inode, validation_string
                    )

                case "complete_full_hash":
                    logger.info("Generating test files for complete flow of size to full hash.")
                    for file in test_source_files + test_destinations:
                        files, dirs = test_folder_file_generator(file, 100)
                        created_files.extend(files)
                        created_dirs.extend(dirs)
                    args.source = test_source_files
                    original_source_files = get_source_files()
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Source files: {original_source_files}")
                    source_matches, files_by_size = find_duplicates_by_size(
                        original_source_files, test_destinations
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Files by size: {files_by_size}")
                    source_matches, files_by_small_hash = find_duplicates_by_small_hash(
                        source_matches, files_by_size, pool
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Files by small hash: {files_by_small_hash}")
                    source_matches, files_by_full_hash = find_duplicates_by_full_hash(
                        source_matches, files_by_small_hash, pool
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Files by full hash: {files_by_full_hash}")
                    validation_string = generate_test_hash_or_inode_output_validation_string(
                        "full_hash", files_by_full_hash
                    )
                    output_test_results(
                        dict(files_by_full_hash) == dict(validation_string),
                        files_by_full_hash, validation_string
                    )

                case "complete_combined_hash_by_inode":
                    logger.info(
                        "Generating test files for complete flow of size to combined."
                    )
                    inode_sources = set()
                    inode_destinations = set()
                    index_values = set()
                    test_hash_or_inode_input_output = (generate_test_hash_or_inode_input_output(
                            test_source_files, test_destinations)
                    )
                    for hash_match in test_hash_or_inode_input_output.values():
                        for source, destinations in hash_match.items():
                            # Generate source files
                            files, dirs = test_folder_file_generator(source, 100)
                            created_files.extend(files)
                            created_dirs.extend(dirs)
                            inode_sources.add(source)
                            inode_destinations.update(destinations)
                            index_values.add(get_file_inode(source)[1])
                            for destination in destinations:
                                # Generate destination links
                                files, dirs = test_folder_file_generator(
                                    destination, link_type="hardlink", link_target=source
                                )
                                created_files.extend(files)
                                created_dirs.extend(dirs)
                    args.source = inode_sources
                    original_source_files = get_source_files()
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Source files: {original_source_files}")
                    source_matches, files_by_size = find_duplicates_by_size(
                        original_source_files, inode_destinations
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Files by size: {files_by_size}")
                    source_matches, files_by_small_hash = find_duplicates_by_small_hash(
                        source_matches, files_by_size, pool
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Files by small hash: {files_by_small_hash}")
                    source_matches, files_by_inode = find_duplicates_by_inode(
                        source_matches, files_by_small_hash, pool, mode="combined"
                    )
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Files by combined: {files_by_inode}")
                    validation_string = generate_test_hash_or_inode_output_validation_string(
                        "_".join(func.split("_")[-2:]),
                        test_hash_or_inode_input_output, index_values
                    )
                    output_test_results(
                        dict(files_by_inode) == dict(validation_string),
                        files_by_inode, validation_string
                    )

        except Exception as e:
            logger.error(f"Error while testing function {func}: {e}")
        finally:
            cleanup_test_files(created_files, created_dirs)
    logger.info("Test function execution completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Duplicate File Finder",
        description="Performs a fast duplicate file search in the specified folder(s) "
        "allowing different operations on the duplicates found.",
    )
    parser.add_argument('--source', '-s', nargs='*',
                        help='Source file/folder(s) to find duplicates of.')
    parser.add_argument('--destinations', '-d', nargs='*',
                        help='Destination file/folder(s) to search for duplicates.')
    parser.add_argument('--mode', '-m', type=str,
                        choices=['hash', 'combined', 'inode'], default='hash',
                        help='Mode of comparison, inode is recommended for Hardlinks.')
    parser.add_argument('--input', '-i', type=str,
                        help='Input CSV file with list of files to search for duplicates.')
    parser.add_argument('--output', '-o', type=str,
                        help='Output CSV file with list of duplicates.')
    parser.add_argument(
        "--remove-mode", "-r", type=str, choices=['source_only', 'dest_only', 'all'],
        help="File Removal mode of source_only, dest_only, or all."
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Dry run.")
    parser.add_argument('--log-environment', '-l', type=str,
                        choices=['development', 'staging', 'production'],
                        help='Set the logging environment (development, staging, production).')
    parser.add_argument(
        "--test", action="store_true", help="Test mode. Only used with --functions."
    )
    parser.add_argument("--functions", "-f", nargs="*",
                        help="Functions to test with --test.")
    parser.add_argument("--parallel-threads", "-t", type=int, default=5,
                        help="Number of parallel threads to use.")
    # noinspection SpellCheckingInspection
    parser.add_argument('--parallel-chunksize', '-c', type=int, default=10,
                        help='Chunk size for parallel processing.')
    parser.add_argument('--filter-by-filetype', action='store_true',
                        help='Filter duplicates to only those the same file type as the source.')
    parser.add_argument('--parent-check', action = 'store_true',
                        help='Check if the parent directory is empty after removing files.')
    args = parser.parse_args()

    # Set the logger based on the --log-environment argument
    if args.log_environment:
        logger = logging.getLogger(args.log_environment)
    logger.info("Logger initialized with environment: %s", args.log_environment or "root")

    validator = ArgumentValidator(args, logger)
    validator.validate()
    logger.info("Opening thread pool with %d threads.", args.parallel_threads)
    with ThreadPool(args.parallel_threads) as main_pool:
        try:
            if args.test:
                test_function(main_pool)
            else:
                check_for_duplicates(main_pool)
        finally:
            logger.info("Thread pool closed.")
