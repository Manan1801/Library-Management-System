import mysql.connector
import os
from dotenv import load_dotenv
from bplustree_module.bplustree import BPlusTree
  # adjust based on actual import path

load_dotenv()

db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

def load_books_into_bplustree():
    tree = BPlusTree(order=3)

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM BOOKS_DETAILS")
        rows = cursor.fetchall()

        for row in rows:
            book_id = row[0]
            book_data = {
                "Book_Name": row[1],
                "Book_Author": row[2],
                "Book_Publication_Year": row[3],
                "Total_Reviews": row[4],
                "Quantity": row[5],
                "BOOK_GENRE": row[6]
            }
            tree.insert(book_id, book_data)

        cursor.close()
        conn.close()

        return tree

    except mysql.connector.Error as e:
        print("❌ Error:", e)
        return None
