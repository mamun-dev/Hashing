import os
import hashlib
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)


# Function to verify file integrity by comparing the file's current hash with the saved hash in a text file
def verify_file_integrity(file_path, hash_file_path):
    # Read the saved hash from the hash file
    with open(hash_file_path, "r") as hash_file:
        original_hash = hash_file.read().strip()

    # Determine which algorithm to use based on the hash file name
    if "_SHA256_hash.txt" in hash_file_path:
        computed_hash = hash_file_sha256(file_path)
        algorithm = "SHA-256"
    elif "_SHA3_512_hash.txt" in hash_file_path:
        computed_hash = hash_file_sha3(file_path)
        algorithm = "SHA3-512"
    else:
        print(f"Error: Unsupported or unknown hash file format for {file_path}.")
        return False

    print(f"Original Hash from {hash_file_path}: {original_hash}")
    print(f"Computed Hash using {algorithm} for {file_path}: {computed_hash}")

    # Compare the two hashes
    if computed_hash == original_hash:
        # Valid file, set output color to green
        print(Fore.GREEN + f"The file '{file_path}' is valid. No changes detected.\n")
        return True
    else:
        # Modified or corrupted file, set output color to red
        print(Fore.RED + f"The file '{file_path}' has been modified or corrupted!\n")
        return False


# Function to compute SHA-256 hash for verification
def hash_file_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# Function to compute SHA3-512 hash for verification
def hash_file_sha3(file_path):
    sha3_hash = hashlib.sha3_512()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha3_hash.update(byte_block)
    return sha3_hash.hexdigest()


# Function to process and verify all files in a directory
def verify_directory(directory_path):
    print(f"Verifying files in directory: {directory_path}\n")

    # Iterate over all files in the directory
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)

        # Ensure it's a file (skip directories)
        if os.path.isfile(file_path):
            # Check for the hash files
            if filename.endswith("_SHA256_hash.txt") or filename.endswith("_SHA3_512_hash.txt"):
                # Determine the original file name (remove the _SHA256_hash.txt or _SHA3_512_hash.txt part)
                original_file_name = filename.replace("_SHA256_hash.txt", "").replace("_SHA3_512_hash.txt", "")
                original_file_path = os.path.join(directory_path, original_file_name)

                # Debug: Print the files being processed
                print(f"Found hash file: {filename}")
                print(f"Looking for original file: {original_file_path}")

                # Verify the file if it exists
                if os.path.exists(original_file_path):
                    verify_file_integrity(original_file_path, file_path)
                else:
                    print(f"Original file '{original_file_name}' not found for hash verification.\n")


# Example Usage: Verify all files in the 'files_directory'
directory_path = r'C:\Users\mamun\OneDrive\Desktop\Web_Engineering_Lab\files'  # Replace with your directory path
verify_directory(directory_path)
