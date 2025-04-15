from datetime import datetime

def log_unauthorized_access(username, action):
    with open("unauthorized_access.log", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] Unauthorized access attempt by '{username}' on '{action}'\n")

 