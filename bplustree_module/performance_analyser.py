# performance_analyzer.py
import random
import time
import tracemalloc
from bplustree import BPlusTree
from bruteforce import BruteForceDB

def generate_data(n):
    return [(str(i), {"value": random.randint(1, 10000)}) for i in random.sample(range(10 * n), n)]

class PerformanceAnalyzer:
    def __init__(self, data_size):
        self.data = generate_data(data_size)

    def _benchmark(self, structure, op_name):
        tracemalloc.start()
        start_time = time.time()

        if op_name == "insert":
            for k, v in self.data:
                structure.insert(k, v)

        elif op_name == "search":
            for k, _ in self.data:
                structure.search(k)

        elif op_name == "delete":
            for k, _ in self.data:
                structure.delete(k)

        elif op_name == "range_query":
            keys = [k for k, _ in self.data]
            for i in range(0, len(keys) - 10, 10):
                structure.range_query(keys[i], keys[i + 5])

        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return {
            "time": round(end_time - start_time, 4),
            "peak_memory_kb": round(peak / 1024, 2)
        }

    def run_all_tests(self):
        results = {}

        print("Running on B+ Tree...")
        bpt = BPlusTree()
        results["BPlusTree"] = {
            "insert": self._benchmark(bpt, "insert"),
            "search": self._benchmark(bpt, "search"),
            "range_query": self._benchmark(bpt, "range_query"),
            # delete left for final impl
        }

        print("Running on BruteForceDB...")
        brute = BruteForceDB()
        results["BruteForce"] = {
            "insert": self._benchmark(brute, "insert"),
            "search": self._benchmark(brute, "search"),
            "range_query": self._benchmark(brute, "range_query"),
        }

        return results

# Example standalone usage:
if __name__ == '__main__':
    analyzer = PerformanceAnalyzer(data_size=1000)
    result = analyzer.run_all_tests()
    print(result)