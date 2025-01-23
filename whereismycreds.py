import itertools
import os
import sys

def generate_credentials(output_file):
    chars = "0123456789!@#$%^&*()_+-=<>?/|{}[]"
    total = len(chars) ** 7
    
    with open(output_file, "w") as f:
        for count, combo in enumerate(itertools.product(chars, repeat=7), 1):
            credential = "".join(combo)
            f.write(f"{credential}:{credential}\n")
            
            # Print progress
            if count % 10000 == 0 or count == total:
                percent_done = (count / total) * 100
                sys.stdout.write(f"\rProgress: {percent_done:.2f}% completed")
                sys.stdout.flush()
    
    print("\nCredentials saved to", output_file)

def main():
    output_file = "generated_creds.txt"
    generate_credentials(output_file)
    
    file_size = os.path.getsize(output_file) / (1024 * 1024)
    print(f"File size: {file_size:.2f} MB")
    
    response = input("Do you want to proceed? (y/n): ")
    if response.lower() != "y":
        print("Operation aborted.")
        os.remove(output_file)
        sys.exit(1)

if __name__ == "__main__":
    main()
