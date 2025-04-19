import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
load_dotenv()


db_config = {
	'host': os.getenv('DB_HOST'),
	'user': os.getenv('DB_USER'),
	'password': os.getenv('DB_PASSWORD'),
	'database': os.getenv('DB_NAME')
}

def get_db_connection():
	return mysql.connector.connect(**db_config) 

# Function to create a database connection
def create_db_connection():
    try:
        connection = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME')
)

        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error: {e}")
        return None

# BPlusTreeNode Class
class BPlusTreeNode:
    def __init__(self, leaf=False):
        self.leaf = leaf
        self.keys = []
        self.values = []
        self.children = []
        self.next = None

# BPlusTree Class with Database Integration
class BPlusTree:
    def __init__(self, t=3):
        self.root = BPlusTreeNode(True)
        self.t = t

    def insert(self, key, value):
        root = self.root
        if len(root.keys) == (2 * self.t) - 1:
            new_root = BPlusTreeNode()
            new_root.children.append(self.root)
            self._split_child(new_root, 0)
            self.root = new_root
        self._insert_non_full(self.root, key, value)
        self._update_db('insert', key, value)

    def _insert_non_full(self, node, key, value):
        if node.leaf:
            i = 0
            while i < len(node.keys) and node.keys[i] < key:
                i += 1
            node.keys.insert(i, key)
            node.values.insert(i, value)
        else:
            i = 0
            while i < len(node.keys) and key >= node.keys[i]:
                i += 1
            child = node.children[i]
            if len(child.keys) == (2 * self.t) - 1:
                self._split_child(node, i)
                if key > node.keys[i]:
                    i += 1
            self._insert_non_full(node.children[i], key, value)

    def _split_child(self, parent, index):
        t = self.t
        node = parent.children[index]
        new_node = BPlusTreeNode(node.leaf)
        parent.keys.insert(index, node.keys[t - 1])
        parent.children.insert(index + 1, new_node)
        new_node.keys = node.keys[t:]
        node.keys = node.keys[:t - 1]

        if node.leaf:
            new_node.values = node.values[t:]
            node.values = node.values[:t - 1]
            new_node.next = node.next
            node.next = new_node
        else:
            new_node.children = node.children[t:]
            node.children = node.children[:t]

    def delete(self, key):
        self._delete(self.root, key)
        self._update_db('delete', key)

    def _delete(self, node, key):
        t = self.t
        if node.leaf:
            if key in node.keys:
                idx = node.keys.index(key)
                node.keys.pop(idx)
                node.values.pop(idx)
        else:
            idx = 0
            while idx < len(node.keys) and key > node.keys[idx]:
                idx += 1
            child = node.children[idx]
            if len(child.keys) < t:
                if idx > 0 and len(node.children[idx - 1].keys) >= t:
                    self._borrow_from_prev(node, idx)
                elif idx < len(node.children) - 1 and len(node.children[idx + 1].keys) >= t:
                    self._borrow_from_next(node, idx)
                else:
                    if idx < len(node.children) - 1:
                        self._merge(node, idx)
                    else:
                        self._merge(node, idx - 1)
                    child = node.children[idx if idx < len(node.children) else idx - 1]
            self._delete(child, key)

    def _borrow_from_prev(self, node, idx):
        child = node.children[idx]
        sibling = node.children[idx - 1]
        if child.leaf:
            child.keys.insert(0, sibling.keys.pop(-1))
            child.values.insert(0, sibling.values.pop(-1))
            node.keys[idx - 1] = child.keys[0]
        else:
            child.keys.insert(0, node.keys[idx - 1])
            node.keys[idx - 1] = sibling.keys.pop(-1)
            child.children.insert(0, sibling.children.pop(-1))

    def _borrow_from_next(self, node, idx):
        child = node.children[idx]
        sibling = node.children[idx + 1]
        if child.leaf:
            child.keys.append(sibling.keys.pop(0))
            child.values.append(sibling.values.pop(0))
            node.keys[idx] = sibling.keys[0]
        else:
            child.keys.append(node.keys[idx])
            node.keys[idx] = sibling.keys.pop(0)
            child.children.append(sibling.children.pop(0))

    def _merge(self, node, idx):
        child = node.children[idx]
        sibling = node.children[idx + 1]
        if not child.leaf:
            child.keys.append(node.keys[idx])
            child.keys.extend(sibling.keys)
            child.children.extend(sibling.children)
        else:
            child.keys.extend(sibling.keys)
            child.values.extend(sibling.values)
            child.next = sibling.next
        node.keys.pop(idx)
        node.children.pop(idx + 1)

    def _update_db(self, operation, key, value=None):
        connection = create_db_connection()
        if connection:
            cursor = connection.cursor()
            if operation == 'insert':
                query = """
                    INSERT INTO BOOKS_DETAILS(Book_ID, Book_Name, Book_Author, Book_Publication_Year, Total_Reviews, Quantity, BOOK_GENRE)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                data = (key, value['Book_Name'], value['Book_Author'], value['Book_Publication_Year'],
                        value['Total_Reviews'], value['Quantity'], value['BOOK_GENRE'])
                cursor.execute(query, data)
            if operation == 'delete':
                # First delete from BOOK_AVAILABILITY (child)
                cursor.execute("DELETE FROM BOOK_AVAILABILITY WHERE BookID = %s", (key,))
                # Then delete from BOOKS_DETAILS (parent)
                cursor.execute("DELETE FROM BOOKS_DETAILS WHERE Book_ID = %s", (key,))

            connection.commit()
            cursor.close()
            connection.close()

    def get_all(self):
        node = self.root
        while not node.leaf:
            node = node.children[0]
        while node:
            for i in range(len(node.keys)):
                yield node.keys[i], node.values[i]
            node = node.next

    def range_query(self, start_key, end_key):
        results = []
        current = self._find_leaf(start_key)
        
        while current:
            for i, key in enumerate(current.keys):
                if start_key <= key <= end_key:
                    results.append((key, current.children[i]))
                elif key > end_key:
                    return results
            current = current.next
        return results



# Example usage
def main():
    # Create a BPlusTree with minimum degree t=2
    bptree = BPlusTree(t=2)

    # Sample books to insert
    books = [

        (220, {
            "Book_Name": "Application and Web Development",
            "Book_Author": "Love Babbar",
            "Book_Publication_Year": 2018,
            "Total_Reviews": 124,
            "Quantity": 5,
            "BOOK_GENRE": "Development"
        }),
        (221, {
            "Book_Name": "DSA and C++ PRrogramming",
            "Book_Author": "Striver",
            "Book_Publication_Year": 2005,
            "Total_Reviews": 2000,
            "Quantity": 59,
            "BOOK_GENRE": "Software Development"
        }),
    ]

    print("Inserting books...")
    for book_id, info in books:
        bptree.insert(book_id, info)

    print("\nAll books after insertion:")
    for book_id, info in bptree.get_all():
        print(f"{book_id} → {info['Book_Name']}")

    print("\nDeleting Book ID 213...")
    bptree.delete(213)

    print("\nAll books after deletion:")
    for book_id, info in bptree.get_all():
        print(f"{book_id} → {info['Book_Name']}")

if __name__ == "__main__":
    main()