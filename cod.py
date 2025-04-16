from itsdangerous import URLSafeTimedSerializer
from flask.sessions import SecureCookieSessionInterface

def decode_flask_cookie(secret_key, cookie_value):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.loads(cookie_value)

# Replace this with your actual secret_key and cookie value:
secret_key = 'lms2025 '
cookie = '.eJyrVopPy0kszkgtVrKKrlZSKAFSSrmpxcWJ6alKOkqOKbmZeQqJyclAEYWi1MLSzKLUFD2l2Fqdwak2ICc1sThVISc_XSEzj1g1sbUA171W3A.Z_7khw.-MY78O4ngTHi-ArxmOOREfkml_A'

print(decode_flask_cookie(secret_key, cookie))
