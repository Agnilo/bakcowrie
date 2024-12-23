import pickle

# Load the fs.pickle file
pickle_file = 'share/cowrie/fs.pickle'

with open(pickle_file, 'rb') as f:
    fs_data = pickle.load(f)

# Fix the directory path
if '\\new\\directory' in fs_data:
    fs_data['/new/directory'] = fs_data.pop('\\new\\directory')

# Save the updated pickle file
with open(pickle_file, 'wb') as f:
    pickle.dump(fs_data, f)

print("Updated fs.pickle with corrected paths.")
