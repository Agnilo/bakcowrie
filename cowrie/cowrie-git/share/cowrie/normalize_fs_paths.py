import pickle

def normalize_paths(tree):
    for entry in tree:
        if isinstance(entry, list):
            # Normalize entry name
            entry[0] = entry[0].replace('/', '\\')
            # If it's a directory, recursively normalize its contents
            if entry[1] == 1:  # 1 indicates a directory
                normalize_paths(entry[7])  # Field 7 stores directory contents

def main():
    input_file = 'fs.pickle'  # Adjust if needed
    output_file = 'fs.pickle'

    with open(input_file, 'rb') as f:
        filesystem = pickle.load(f)

    # Normalize paths in the filesystem
    normalize_paths(filesystem[7])  # Field 7 is the root directory's contents

    # Save back the modified filesystem
    with open(output_file, 'wb') as f:
        pickle.dump(filesystem, f)

    print("Normalized paths in fs.pickle")

if __name__ == '__main__':
    main()