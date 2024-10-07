import os
import hashlib


# Function to compute SHA-256 hash for small files and save it in a text file
def hash_and_save_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)

    hash_value = sha256_hash.hexdigest()

    # Save the hash to a text file with the algorithm name
    hash_file_path = f"{file_path}_SHA256_hash.txt"
    with open(hash_file_path, "w") as hash_file:
        hash_file.write(hash_value)

    print(f"SHA-256 Hash saved in {hash_file_path}")
    return hash_value


# Function to compute SHA3-512 hash for large files and save it in a text file
def hash_and_save_sha3(file_path):
    sha3_hash = hashlib.sha3_512()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha3_hash.update(byte_block)

    hash_value = sha3_hash.hexdigest()

    # Save the hash to a text file with the algorithm name
    hash_file_path = f"{file_path}_SHA3_512_hash.txt"
    with open(hash_file_path, "w") as hash_file:
        hash_file.write(hash_value)

    print(f"SHA3-512 Hash saved in {hash_file_path}")
    return hash_value


# Function to check if the hash file already exists
def hash_file_exists(file_path, algorithm):
    if algorithm == 'SHA-256':
        hash_file_path = f"{file_path}_SHA256_hash.txt"
    else:  # For SHA3-512
        hash_file_path = f"{file_path}_SHA3_512_hash.txt"

    # Check if the hash file already exists
    return os.path.exists(hash_file_path)


# Function to process all files in a directory and hash them
def process_directory_for_hashing(directory_path):
    # Iterate over all files in the directory
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)

        # Ensure it's a file (skip directories) and ignore hash files
        if os.path.isfile(file_path) and not filename.endswith(("_SHA256_hash.txt", "_SHA3_512_hash.txt")):
            # Get the file size in KB
            file_size_kb = os.path.getsize(file_path) / 1024

            # Determine hash based on file size
            if file_size_kb < 1024:
                # Use SHA-256 for small files
                print(f"Processing small file: {filename} ({file_size_kb:.2f} KB)")

                # Check if SHA-256 hash file already exists
                if hash_file_exists(file_path, 'SHA-256'):
                    print(f"Hash file for {filename} already exists, skipping hashing.")
                else:
                    print(f"Hash file for {filename} not found, generating hash.")
                    hash_and_save_sha256(file_path)

            else:
                # Use SHA3-512 for large files
                print(f"Processing large file: {filename} ({file_size_kb:.2f} KB)")

                # Check if SHA3-512 hash file already exists
                if hash_file_exists(file_path, 'SHA3-512'):
                    print(f"Hash file for {filename} already exists, skipping hashing.")
                else:
                    print(f"Hash file for {filename} not found, generating hash.")
                    hash_and_save_sha3(file_path)


# Example Usage: Hash all files in the 'files_directory'
directory_path = r'C:\Users\mamun\OneDrive\Desktop\Web_Engineering_Lab\files'  # Replace with your directory path
process_directory_for_hashing(directory_path)
