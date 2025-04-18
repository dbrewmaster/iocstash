import os
import time
import mmap
import csv
import numpy as np
from tqdm import tqdm

# generating large files with random data
def generate_random_text(size):
    return np.random.bytes(size).decode('latin1', 'ignore')

def generate_file(file_type, file_path, file_size):
    start_time = time.time()
    chunk_size = 1024 * 1024 * 1024  # 1GB chunk size for ultra-fast disk writing
    generated_size = 0
    
    with open(file_path, 'wb') as file:
        with tqdm(total=file_size, unit='B', unit_scale=True, desc="Generating File") as pbar:
            while generated_size < file_size:
		#generating random chunk of data
                chunk = os.urandom(min(chunk_size, file_size - generated_size))
                file.write(chunk)
                generated_size += len(chunk)
                pbar.update(len(chunk))
    
    end_time = time.time()
    print("\nOperation is finished")
    print(f"Processing time: {end_time - start_time:.2f} seconds")
    print(f"Path of the file: {os.path.abspath(file_path)}")
    print(f"Size of the file: {os.path.getsize(file_path) / (1024 * 1024):.2f} MB")

# Provide user inputs
if __name__ == "__main__":
    file_size = int(input("Enter the size of the file in MB: ")) * 1024 * 1024
    file_type = input("Enter the file type (csv/txt): ").strip().lower()
    file_path = input("Enter the full path to store the file (including filename): ")
    
    # Validate file type
    if file_type not in ['csv', 'txt']:
        print("Invalid file type. Please choose either 'csv' or 'txt'.")
    else:
        generate_file(file_type, file_path, file_size)
