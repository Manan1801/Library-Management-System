import datetime
import logging
from functools import wraps
from flask import session, request

from datetime import datetime

def log_unauthorized_access(username, action):
    with open("unauthorized_access.log", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] Unauthorized access attempt by '{username}' on '{action}'\n")
import os

def write_log_to_file(action, log_file='system_logs.txt'):
    """
    Writes a log entry to a local file with a timestamp.

    Parameters:
        action (str): Description of the action to log.
        log_file (str): Filename of the log file (default: system_logs.txt).
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {action}\n"

    # Create logs directory if not exists (optional, for cleanliness)
    
    # Write to the file
    with open('./logs.txt', 'a') as f:
        f.write(log_entry)

# Configure logging for unauthorized access
# logging.basicConfig(
#     filename='unauthorized_access.log',
#     level=logging.WARNING,
#     format='%(asctime)s - %(message)s'
# )

# def log_unauthorized_access(user_id=None, ip=None, endpoint=None):
#     """Log unauthorized access attempts."""
#     if not ip:
#         ip = request.remote_addr
#     if not endpoint:
#         endpoint = request.endpoint

#     message = f"Unauthorized access attempt - IP: {ip}"
#     if user_id:
#         message += f", User ID: {user_id}"
#     if endpoint:
#         message += f", Endpoint: {endpoint}"

#     logging.warning(message)

# def is_session_valid():
#     """Check if the current session is valid and not expired."""
#     if 'session_id' not in session:
#         return False

#     expiry = session.get('expiry')
#     if not expiry:
#         return False

#     current_time = datetime.datetime.now().timestamp()
#     return current_time < expiry

# def extend_session():
#     """Extend the current session expiry time."""
#     if 'session_id' in session:
#         new_expiry = datetime.datetime.now() + datetime.timedelta(hours=2)
#         session['expiry'] = int(new_expiry.timestamp())

# def clear_session():
#     """Clear all session data."""
#     session.clear()

# def get_user_role():
#     """Get the role of the currently logged-in user."""
#     return session.get('role', 'guest')

# def get_member_id():
#     """Get the member ID of the currently logged-in user."""
#     return session.get('member_id')

# def set_session_data(member_id, username, role, session_id, expiry):
#     """Set session data for a logged-in user."""
#     session['member_id'] = member_id
#     session['username'] = username
#     session['role'] = role
#     session['session_id'] = session_id
#     session['expiry'] = expiry

# def require_valid_session(f):
#     """Decorator to ensure valid session for protected routes."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if not is_session_valid():
#             log_unauthorized_access()
#             clear_session()
#             return {'error': 'Invalid or expired session'}, 401
#         extend_session()
#         return f(*args, **kwargs)
#     return decorated_function

