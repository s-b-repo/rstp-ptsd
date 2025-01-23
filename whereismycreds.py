import itertools
import os
import sys

def generate_credentials(output_file, min_length, max_length):
    chars = "0123456789!@#$%^&*()_+-=<>?/|{}[]"
    
    total = sum(len(chars) ** i for i in range(min_length, max_length + 1))
    count = 0
    
    with open(output_file, "w") as f:
        for length in range(min_length, max_length + 1):
            for combo in itertools.product(chars, repeat=length):
                credential = "".join(combo)
                f.write(f"{credential}:{credential}\n")
                count += 1
                
                # Print progress
                if count % 10000 == 0 or count == total:
                    percent_done = (count / total) * 100
                    sys.stdout.write(f"\rProgress: {percent_done:.2f}% completed")
                    sys.stdout.flush()
    
    print("\nCredentials saved to", output_file)

def main():
    output_file = "generated_creds.txt"
    
    min_length = int(input("Enter minimum password length: "))
    max_length = int(input("Enter maximum password length: "))
    
    if min_length > max_length or min_length < 1:
        print("Invalid length range. Exiting.")
        sys.exit(1)
    
    generate_credentials(output_file, min_length, max_length)
    
    file_size = os.path.getsize(output_file) / (1024 * 1024)
    print(f"File size: {file_size:.2f} MB")
    
    response = input("Do you want to proceed? (y/n): ")
    if response.lower() != "y":
        print("Operation aborted.")
        os.remove(output_file)
        sys.exit(1)

if __name__ == "__main__":
    main()
