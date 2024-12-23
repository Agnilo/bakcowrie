#!/usr/bin/env python

import os
import mysql.connector
import datetime

# Database connection details
db = mysql.connector.connect(
    host="127.0.0.1",  # Use localhost or the IP of the MySQL container
    user="cowrie",     # Your MySQL user
    password="yourpassword",  # Your MySQL password
    database="cowrie"  # The database containing the input table
)

cursor = db.cursor()

def get_mkdir_commands():
    """Fetches distinct mkdir commands from the input table."""
    cursor.execute("SELECT DISTINCT input FROM input WHERE input LIKE 'mkdir %'")
    mkdir_commands = cursor.fetchall()
    return mkdir_commands

def create_persistent_directories():
    """Creates directories in honeyfs based on attacker mkdir commands."""
    
    # Path to honeyfs (ensure this matches the mount point inside the container)
    honeyfs_path = "/honeyfs"  # For the container environment, this is the path

    mkdir_commands = get_mkdir_commands()
    for command in mkdir_commands:
        # Extract directory path from the command
        directory_path = command[0].split("mkdir ")[1].strip()

        # Build the full path within honeyfs directory
        full_path = os.path.join(honeyfs_path, directory_path.lstrip('/'))

        # Normalize the path for the container
        full_path = os.path.normpath(full_path)  # This handles the correct separators

        # Create the directory if it does not exist
        if not os.path.exists(full_path):
            os.makedirs(full_path)
            print(f"{datetime.datetime.now()}: Created persistent directory: {full_path}")

if __name__ == "__main__":
    create_persistent_directories()
    db.close()