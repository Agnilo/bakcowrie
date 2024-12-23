import mysql.connector
import datetime
from twisted.python import log
from mysql.connector import Error


def get_session_id(db, username: str, password: str, ip: str) -> str | None:
    """
    Retrieve the most recent session ID for the given username, password, and IP.
    """
    query = """
        SELECT session
        FROM auth
        WHERE username = %s AND password = %s AND ip = %s
        ORDER BY timestamp DESC LIMIT 1
    """
    try:
        cursor = db.cursor()
        cursor.execute(query, (username, password, ip))
        result = cursor.fetchone()
        cursor.close()
        return result[0] if result else None
    except Error as e:
        log.msg(f"MySQL error fetching session ID: {e}")
        return None

def log_directory_creation(session_id: str, directory_path: str) -> None:
    """
    Log directory creation in the input table with a timestamp.
    """
    try:
        conn = mysql.connector.connect(
            host="cowrie-git-mysql-1",
            user="cowrie",
            password="yourpassword",
            database="cowrie"
        )
        cursor = conn.cursor()

        current_time = datetime.datetime.now()  # Get the current timestamp

        query = """
        INSERT INTO input (session, timestamp, input)
        VALUES (%s, %s, %s)
        """
        cursor.execute(query, (session_id, current_time, f"mkdir {directory_path}"))
        conn.commit()
        cursor.close()
        conn.close()
        log.msg(f"DEBUG: Logged directory creation for session '{session_id}', directory: '{directory_path}'.")
    except Error as e:
        log.err(f"ERROR: Failed to log directory creation: {e}")


def validate_directory(session_id: str, directory_path: str) -> bool:
    """
    Validate that the directory exists for the given session.
    """
    try:
        conn = mysql.connector.connect(
            host="cowrie-git-mysql-1",
            user="cowrie",
            password="yourpassword",
            database="cowrie"
        )
        cursor = conn.cursor()

        query = """
        SELECT COUNT(*)
        FROM input
        WHERE session = %s AND input = %s
        """
        cursor.execute(query, (session_id, f"mkdir {directory_path}"))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result[0] > 0  # Directory is valid if the count is greater than 0
    except Error as e:
        log.err(f"ERROR: Failed to validate directory: {e}")
        return False


def remove_logged_directory(session_id: str, directory_path: str) -> None:
    """
    Remove the directory entry from the input table.
    """
    try:
        conn = mysql.connector.connect(
            host="cowrie-git-mysql-1",
            user="cowrie",
            password="yourpassword",
            database="cowrie"
        )
        cursor = conn.cursor()

        query = """
        DELETE FROM input
        WHERE session = %s AND input = %s
        """
        cursor.execute(query, (session_id, f"mkdir {directory_path}"))
        conn.commit()
        cursor.close()
        conn.close()
        log.msg(f"DEBUG: Removed directory '{directory_path}' for session '{session_id}' from logs.")
    except Error as e:
        log.err(f"ERROR: Failed to remove directory from logs: {e}")
