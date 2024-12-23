import pickle

with open('fs.pickle', 'rb') as f:
    fs_data = pickle.load(f)

print(fs_data)
