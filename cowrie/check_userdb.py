import os

# Path to the userdb.txt file
userdb_path = r"C:\Users\ITWORK\Desktop\bakalauras\cowrie\cowrie-git\etc\userdb.txt"

if os.path.exists(userdb_path):
    print(f"File exists: {userdb_path}")
    if os.access(userdb_path, os.R_OK):
        print("File is readable.")
    else:
        print("File exists but is not readable.")
else:
    print("File does not exist.")