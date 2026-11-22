# Dictionaries
#
# A dictionary stores KEY: VALUE pairs. You look up a value by its key,
# like looking up a word (key) in a real dictionary to get its meaning.
#
#   - Written with curly braces: {"name": "Rahul", "age": 25}
#   - Keys must be UNIQUE and IMMUTABLE (str, int, float, tuple)
#   - Values can be anything, including lists and other dictionaries
#   - Changeable (mutable)
#   - Keep the order items were added (Python 3.7+)
#   - Looking up a key is very fast, even with millions of items
#
# Topics covered here:
#   1. Creating dictionaries
#   2. Accessing values: [] and get()
#   3. Adding and changing items
#   4. Removing items
#   5. Checking keys
#   6. Looping: keys, values, items
#   7. Useful methods: update, setdefault, copy, fromkeys
#   8. Dictionary comprehensions
#   9. Nested dictionaries
#  10. Merging dictionaries
#  11. Sorting dictionaries
#  12. Counting and grouping (Counter, defaultdict)
#  13. Dictionaries and JSON
#  14. Practical examples
#  15. Time complexity cheat sheet


import json
from collections import Counter, defaultdict


# ---------------------------------------------------------------
# 1. Creating dictionaries
# ---------------------------------------------------------------

print("--- 1. Creating dictionaries ---")

student = {
    "name": "Rahul",
    "age": 25,
    "major": "Cybersecurity",
    "courses": ["Python", "Networks"],
}

empty = {}
from_dict_func = dict(city="Chennai", country="India")
from_pairs = dict([("a", 1), ("b", 2)])
from_zip = dict(zip(["x", "y", "z"], [10, 20, 30]))
number_keys = {1: "one", 2: "two"}
tuple_keys = {(0, 0): "origin"}

print(student)
print(empty, type(empty).__name__)
print(from_dict_func)
print(from_pairs)
print(from_zip)
print(number_keys, tuple_keys)

# Duplicate keys: the LAST value wins
dup = {"a": 1, "a": 2}
print("duplicate key:", dup)


# ---------------------------------------------------------------
# 2. Accessing values
# ---------------------------------------------------------------

print("\n--- 2. Accessing values ---")

print("student['name'] =", student["name"])
print("student['courses'][0] =", student["courses"][0])

# [] raises KeyError if the key is missing
try:
    print(student["gpa"])
except KeyError as error:
    print("KeyError:", error)

# get() returns None (or a default you choose) instead of an error
print("get('gpa'):", student.get("gpa"))
print("get('gpa', 0.0):", student.get("gpa", 0.0))
print("get('age', 0):", student.get("age", 0))


# ---------------------------------------------------------------
# 3. Adding and changing items
# ---------------------------------------------------------------

print("\n--- 3. Adding and changing ---")

student["gpa"] = 3.8                  # new key -> adds it
student["age"] = 26                   # existing key -> changes it
student["courses"].append("Cryptography")   # change a value in place
print(student)


# ---------------------------------------------------------------
# 4. Removing items
# ---------------------------------------------------------------

print("\n--- 4. Removing ---")

inventory = {"apples": 5, "bananas": 12, "cherries": 30, "dates": 7}

removed = inventory.pop("bananas")    # remove a key, return its value
print("pop('bananas') ->", removed, "|", inventory)

missing = inventory.pop("kiwi", 0)    # default avoids KeyError
print("pop('kiwi', 0) ->", missing)

last_item = inventory.popitem()       # remove the LAST added pair
print("popitem() ->", last_item, "|", inventory)

del inventory["apples"]               # delete a key
print("del ['apples'] ->", inventory)

inventory.clear()                     # remove everything
print("clear() ->", inventory)


# ---------------------------------------------------------------
# 5. Checking keys
# ---------------------------------------------------------------

print("\n--- 5. Checking keys ---")

print("'name' in student:", "name" in student)        # checks KEYS
print("'Rahul' in student:", "Rahul" in student)      # not a key!
print("'Rahul' in values:", "Rahul" in student.values())
print("len(student):", len(student))


# ---------------------------------------------------------------
# 6. Looping
# ---------------------------------------------------------------

print("\n--- 6. Looping ---")

prices = {"pen": 10, "notebook": 50, "bag": 500}

print("Keys:")
for item in prices:                   # same as prices.keys()
    print(" ", item)

print("Values:")
for price in prices.values():
    print(" ", price)

print("Items:")
for item, price in prices.items():    # the most useful one
    print(f"  {item:<10} Rs. {price}")

print("keys():  ", list(prices.keys()))
print("values():", list(prices.values()))
print("items(): ", list(prices.items()))

# Don't add or remove keys while looping over a dictionary.
# Loop over list(d) or build a new dictionary instead.


# ---------------------------------------------------------------
# 7. Useful methods
# ---------------------------------------------------------------

print("\n--- 7. Methods ---")

settings = {"theme": "light", "font_size": 12}

settings.update({"theme": "dark", "language": "en"})   # change and add
print("update():", settings)

settings.setdefault("font_size", 16)  # key exists -> keeps 12
settings.setdefault("autosave", True) # key missing -> adds it
print("setdefault():", settings)

backup = settings.copy()              # shallow copy
backup["theme"] = "blue"
print("original theme:", settings["theme"], "| copy theme:", backup["theme"])

blank = dict.fromkeys(["a", "b", "c"], 0)   # same value for each key
print("fromkeys():", blank)


# ---------------------------------------------------------------
# 8. Dictionary comprehensions
# ---------------------------------------------------------------
#
#   {key_expr: value_expr for item in iterable if condition}

print("\n--- 8. Comprehensions ---")

squares = {n: n ** 2 for n in range(1, 6)}
print("squares:", squares)

word_lengths = {w: len(w) for w in ["python", "is", "fun"]}
print("word lengths:", word_lengths)

expensive = {item: p for item, p in prices.items() if p > 20}
print("expensive:", expensive)

with_tax = {item: round(p * 1.18, 2) for item, p in prices.items()}
print("with 18% tax:", with_tax)

swapped = {v: k for k, v in prices.items()}       # values become keys
print("swapped:", swapped)


# ---------------------------------------------------------------
# 9. Nested dictionaries
# ---------------------------------------------------------------

print("\n--- 9. Nested dictionaries ---")

users = {
    "rahul": {"email": "rahul@example.com", "roles": ["admin", "dev"], "active": True},
    "asha": {"email": "asha@example.com", "roles": ["dev"], "active": False},
}

print("rahul's email:", users["rahul"]["email"])
print("asha's first role:", users["asha"]["roles"][0])

users["ben"] = {"email": "ben@example.com", "roles": [], "active": True}
users["asha"]["active"] = True

for username, info in users.items():
    status = "active" if info["active"] else "inactive"
    roles = ", ".join(info["roles"]) or "none"
    print(f"  {username:<6} {status:<9} roles: {roles}")

# Safe lookup through several levels
print("missing level:", users.get("zoe", {}).get("email", "not found"))


# ---------------------------------------------------------------
# 10. Merging dictionaries
# ---------------------------------------------------------------
#
# When both have the same key, the value on the RIGHT wins.

print("\n--- 10. Merging ---")

defaults = {"theme": "light", "volume": 5, "notifications": True}
user_prefs = {"theme": "dark", "volume": 8}

merged = defaults | user_prefs        # Python 3.9+
print("| :", merged)

merged2 = {**defaults, **user_prefs}  # works in older versions too
print("**:", merged2)

defaults |= {"volume": 3}             # merge in place
print("|=:", defaults)


# ---------------------------------------------------------------
# 11. Sorting dictionaries
# ---------------------------------------------------------------

print("\n--- 11. Sorting ---")

scores = {"Chen": 95, "Asha": 88, "Ben": 72, "Dev": 88}

print("sorted keys:", sorted(scores))
print("by key:", dict(sorted(scores.items())))
print("by value (high first):",
      dict(sorted(scores.items(), key=lambda kv: kv[1], reverse=True)))

top = max(scores, key=scores.get)     # key with the highest value
print("top scorer:", top, scores[top])


# ---------------------------------------------------------------
# 12. Counting and grouping
# ---------------------------------------------------------------

print("\n--- 12. Counting and grouping ---")

words = "the cat sat on the mat the end".split()

# Counting by hand with get()
counts = {}
for w in words:
    counts[w] = counts.get(w, 0) + 1
print("manual count:", counts)

# Counter does the same in one line
counter = Counter(words)
print("Counter:", counter)
print("most common 2:", counter.most_common(2))

# Grouping by hand with setdefault()
by_length = {}
for w in words:
    by_length.setdefault(len(w), []).append(w)
print("grouped by length:", by_length)

# defaultdict creates a missing value automatically
by_letter = defaultdict(list)
for w in ["apple", "avocado", "banana", "blueberry", "cherry"]:
    by_letter[w[0]].append(w)
print("defaultdict:", dict(by_letter))


# ---------------------------------------------------------------
# 13. Dictionaries and JSON
# ---------------------------------------------------------------
#
# JSON (used by web APIs and config files) looks almost exactly like
# a Python dictionary, so converting between them is easy.

print("\n--- 13. JSON ---")

text = json.dumps(users["rahul"], indent=2)   # dict -> JSON text
print(text)

data = json.loads('{"status": "ok", "count": 3, "items": [1, 2, 3]}')
print("from JSON:", data, "| count =", data["count"])


# ---------------------------------------------------------------
# 14. Practical examples
# ---------------------------------------------------------------

print("\n--- 14. Practical examples ---")

# Lookup table instead of a long if/elif chain
port_services = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}
for port in [22, 443, 8080]:
    print(f"Port {port}: {port_services.get(port, 'unknown')}")

# Count failed logins per IP
log = [
    ("10.0.0.5", "SUCCESS"),
    ("192.168.1.50", "FAILED"),
    ("192.168.1.50", "FAILED"),
    ("172.16.0.3", "FAILED"),
    ("192.168.1.50", "FAILED"),
]
failed = Counter(ip for ip, status in log if status == "FAILED")
for ip, n in failed.items():
    alert = "  <-- ALERT" if n >= 3 else ""
    print(f"  {ip:<14} {n} failed{alert}")

# Simple caching (memoization): remember results already calculated
cache = {}


def slow_square(n):
    if n in cache:
        return cache[n], "from cache"
    cache[n] = n * n
    return cache[n], "calculated"


print(slow_square(9))
print(slow_square(9))


# ---------------------------------------------------------------
# 15. Time complexity cheat sheet
# ---------------------------------------------------------------
#
#   Operation                     | Speed
#   ------------------------------|---------------------------
#   d[key], d[key] = value        | O(1)   instant
#   key in d                      | O(1)   instant
#   del d[key], d.pop(key)        | O(1)
#   looping over d                | O(n)
#   value in d.values()           | O(n)   checks one by one
