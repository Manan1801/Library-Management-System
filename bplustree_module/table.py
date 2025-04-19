# table.py
from bplustree import BPlusTree
from bruteforce import BruteForceDB

class Table:
    def __init__(self, name, use_bplustree=True):
        self.name = name
        self.use_bplustree = use_bplustree
        self.store = BPlusTree() if use_bplustree else BruteForceDB()

    def insert(self, key, record):
        self.store.insert(key, record)

    def search(self, key):
        return self.store.search(key)

    def delete(self, key):
        return self.store.delete(key)

    def update(self, key, new_record):
        return self.store.update(key, new_record)

    def range_query(self, start_key, end_key):
        return self.store.range_query(start_key, end_key)

    def get_all(self):
        return self.store.get_all()
