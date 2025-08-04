# bruteforce.py
class BruteForceDB:
    def __init__(self):
        self.data = []

    def insert(self, key, value):
        self.data.append((key, value))

    def search(self, key):
        for k, v in self.data:
            if k == key:
                return v
        return None

    def delete(self, key):
        for i, (k, v) in enumerate(self.data):
            if k == key:
                del self.data[i]
                return True
        return False

    def range_query(self, start, end):
        return [(k, v) for k, v in self.data if start <= k <= end]

    def update(self, key, new_value):
        for i, (k, v) in enumerate(self.data):
            if k == key:
                self.data[i] = (k, new_value)
                return True
        return False

    def get_all(self):
        return sorted(self.data, key=lambda x: x[0])