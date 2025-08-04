import os
import mysql.connector
from mysql.connector import Error

db_config = {
    'host': os.getenv('DB_HOST', '10.0.116.125'),  
    'user': os.getenv('DB_USER', 'cs432g8'),
    'password': os.getenv('DB_PASSWORD', 'X7mLpNZq'),
    'database': os.getenv('DB_NAME', 'cs432g8')
}

secret_key = "lms2025"

# Function to create a database connection
def create_db_connection():
    try:
        connection = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password'],
            database=db_config['database']
        )
        if connection.is_connected():
            print('Successfully connected to the database')
            return connection
    except Error as e:
        print(f"Error: {e}")
        return None

def insert_book_into_db(book_id, book_info):
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO BOOKS_DETAILS(Book_ID, Book_Name, Book_Author, Book_Publication_Year, Total_Reviews, Quantity, BOOK_GENRE)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        data = (book_id, book_info['Book_Name'], book_info['Book_Author'], book_info['Book_Publication_Year'],
                book_info['Total_Reviews'], book_info['Quantity'], book_info['BOOK_GENRE'])
        cursor.execute(insert_query, data)
        connection.commit()
        print(f"Book '{book_info['Book_Name']}' inserted successfully.")
        cursor.close()
        connection.close()
    else:
        print("Failed to connect to the database.")


books = [
    (217, {
        "Book_Name": "AI Revolution",
        "Book_Author": "John Smith",
        "Book_Publication_Year": 2018,
        "Total_Reviews": 124,
        "Quantity": 5,
        "BOOK_GENRE": "Technology, AI"
    }),
    (214, {
        "Book_Name": "The Last Leaf",
        "Book_Author": "O. Henry",
        "Book_Publication_Year": 2005,
        "Total_Reviews": 88,
        "Quantity": 3,
        "BOOK_GENRE": "Fiction"
    }),
    (215, {
        "Book_Name": "Quantum Computing",
        "Book_Author": "Alice Johnson",
        "Book_Publication_Year": 2021,
        "Total_Reviews": 56,
        "Quantity": 2,
        "BOOK_GENRE": "Science, Technology"
    }),
    (216, {
        "Book_Name": "Python Programming",
        "Book_Author": "Guido van Rossum",
        "Book_Publication_Year": 2015,
        "Total_Reviews": 300,
        "Quantity": 7,
        "BOOK_GENRE": "Programming, Tech"
    })
]

for book_id, book_info in books:
    insert_book_into_db(book_id, book_info)
