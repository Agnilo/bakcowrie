import pickle

# Path to the fs.pickle file
pickle_file = 'fs.pickle'

# Load and inspect fs.pickle
with open(pickle_file, 'rb') as f:
    fs_data = pickle.load(f)

print(type(fs_data))
if isinstance(fs_data, dict):
    print("Keys:", list(fs_data.keys()))
elif isinstance(fs_data, list):
    print("Sample entries:", fs_data[:5])
else:
    print("Unexpected structure:", fs_data)
