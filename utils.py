import random
import string
import datetime
import smtplib
import os
from dotenv import load_dotenv
load_dotenv()

def send_otp(email, subject,message):
    """Send OTP via email"""
    sender_email = os.getenv("MAIL_USERNAME")
    sender_password = os.getenv("MAIL_PASSWORD")
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, f"Subject: {subject}\n\n{message}")
        server.quit()
    except Exception as e:
        raise Exception(f"Failed to send OTP: {str(e)}")



def generate_unique_password(length=8):
    """Generate a random password with letters, numbers, and special characters."""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(characters) for _ in range(length))

def calculate_fine(issue_date, return_date=None):
    """Calculate fine based on the number of days a book is overdue."""
    if not return_date:
        return_date = datetime.datetime.now()
    
    due_date = issue_date + datetime.timedelta(days=14)  # 2 weeks lending period
    if return_date <= due_date:
        return 0
    
    days_overdue = (return_date - due_date).days
    fine_per_day = 2  # Rs. 2 per day
    return days_overdue * fine_per_day

def get_book_availability(book_id):
    """Check if a book is available for borrowing."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT Availability 
            FROM BOOK_AVAILABILITY 
            WHERE BookID = %s
        """, (book_id,))
        result = cursor.fetchone()
        return result['Availability'] if result else False
    
    finally:
        cursor.close()
        conn.close()

def update_book_availability(book_id, is_available):
    """Update the availability status of a book."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE BOOK_AVAILABILITY 
            SET Availability = %s 
            WHERE BookID = %s
        """, (is_available, book_id))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_member_active_books(member_id):
    """Get list of books currently issued to a member."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT b.Book_ID, b.Book_Name, t.Issue_Date, t.Due_Date
            FROM TRANSACTIONS t
            JOIN BOOKS_DETAILS b ON t.Book_ID = b.Book_ID
            WHERE t.Member_ID = %s AND t.Status = 'Issued'
        """, (member_id,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

def check_book_limit(member_id):
    """Check if member has reached their book borrowing limit."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT COUNT(*) as book_count 
            FROM TRANSACTIONS 
            WHERE Member_ID = %s AND Status = 'Issued'
        """, (member_id,))
        result = cursor.fetchone()
        return result[0] < 5  # Maximum 5 books allowed
    finally:
        cursor.close()
        conn.close()

def log_transaction(book_id, member_id, transaction_type):
    """Log a book transaction (issue/return)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        now = datetime.datetime.now()
        due_date = now + datetime.timedelta(days=14) if transaction_type == 'issue' else None
        
        if transaction_type == 'issue':
            cursor.execute("""
                INSERT INTO TRANSACTIONS 
                (Book_ID, Member_ID, Issue_Date, Due_Date, Status)
                VALUES (%s, %s, %s, %s, 'Issued')
            """, (book_id, member_id, now, due_date))
        else:  # return
            cursor.execute("""
                UPDATE TRANSACTIONS 
                SET Return_Date = %s, Status = 'Returned'
                WHERE Book_ID = %s AND Member_ID = %s AND Status = 'Issued'
            """, (now, book_id, member_id))
            
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()