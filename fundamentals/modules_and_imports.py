# Modules and Imports
#
# A module is a .py file containing code (functions, variables, classes)
# that other files can reuse. A package is a folder of modules.
#
# Python comes with a big "standard library" of modules (math, random,
# datetime, os, ...). You can also install extra ones with pip, and
# write your own.
#
# Topics covered here:
#   1. import module
#   2. from module import name
#   3. import ... as alias
#   4. Importing your own module (my_helpers.py)
#   5. if __name__ == "__main__":
#   6. Useful standard library modules
#   7. Exploring a module: dir() and help()
#   8. Installing third-party packages with pip
#   9. Packages (folders of modules)
#  10. Good practices


# ---------------------------------------------------------------
# 1. import module: use it as module.name
# ---------------------------------------------------------------

print("--- 1. import module ---")

import math

print("math.pi =", math.pi)
print("math.sqrt(16) =", math.sqrt(16))
print("math.ceil(4.2) =", math.ceil(4.2))
print("math.floor(4.8) =", math.floor(4.8))
print("math.factorial(5) =", math.factorial(5))


# ---------------------------------------------------------------
# 2. from module import name: use the name directly
# ---------------------------------------------------------------

print("\n--- 2. from module import name ---")

from random import randint, choice, shuffle

print("randint(1, 6) =", randint(1, 6))           # random number 1-6
print("choice(...) =", choice(["red", "green", "blue"]))

cards = [1, 2, 3, 4, 5]
shuffle(cards)
print("shuffled =", cards)

# from module import *   imports EVERYTHING. Avoid it: you can't tell
# where names came from, and it can overwrite your own variables.


# ---------------------------------------------------------------
# 3. Aliases with "as"
# ---------------------------------------------------------------

print("\n--- 3. Aliases ---")

import datetime as dt                       # shorter name for the module
from statistics import mean as average      # rename a function

print("Today is", dt.date.today())
print("average([2, 4, 9]) =", average([2, 4, 9]))

# Common aliases you'll see in real code:
#   import numpy as np
#   import pandas as pd
#   import matplotlib.pyplot as plt


# ---------------------------------------------------------------
# 4. Importing your own module
# ---------------------------------------------------------------
#
# my_helpers.py is in the same folder as this file, so it can be
# imported by its file name without the .py.

print("\n--- 4. Your own module ---")

import my_helpers

print(my_helpers.GREETING)
print("circle_area(3) =", round(my_helpers.circle_area(3), 2))
print("is_even(7) =", my_helpers.is_even(7))

from my_helpers import shout

print(shout("modules are useful"))


# ---------------------------------------------------------------
# 5. if __name__ == "__main__":
# ---------------------------------------------------------------
#
# Every module has a special variable __name__:
#   - "__main__"   when you run the file directly
#   - the module name ("my_helpers") when it's imported
#
# my_helpers.py has a block under if __name__ == "__main__": that did
# NOT run when we imported it above. Try running it directly:
#   python3 fundamentals/my_helpers.py

print("\n--- 5. __name__ ---")
print("In this file, __name__ =", __name__)
print("In my_helpers, __name__ =", my_helpers.__name__)


def main():
    print("main() runs only when this file is run directly.")


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------
# 6. Useful standard library modules
# ---------------------------------------------------------------

print("\n--- 6. Standard library tour ---")

# datetime: dates and times
from datetime import datetime, timedelta

now = datetime.now()
print("Now:", now.strftime("%Y-%m-%d %H:%M"))
print("In 7 days:", (now + timedelta(days=7)).strftime("%A, %d %B"))

# os: talk to the operating system
import os

print("Current folder:", os.path.basename(os.getcwd()))
print("Path separator:", os.sep)

# sys: info about Python itself
import sys

print("Python version:", sys.version.split()[0])

# collections: extra data structures
from collections import Counter

letters = Counter("mississippi")
print("Counter:", letters.most_common(2))

# string: handy groups of characters
import string

print("Digits:", string.digits)
print("Punctuation:", string.punctuation)

# hashlib: hashing (useful in cybersecurity)
import hashlib

digest = hashlib.sha256(b"password123").hexdigest()
print("SHA-256 of 'password123':", digest[:16] + "...")

# secrets: secure random values (use this, not random, for passwords/tokens)
import secrets

print("Secure token:", secrets.token_hex(8))

# time: pauses and timing
import time

start = time.perf_counter()
sum(range(1_000_000))
print(f"Summing 1 million numbers took {time.perf_counter() - start:.4f} s")


# ---------------------------------------------------------------
# 7. Exploring a module
# ---------------------------------------------------------------

print("\n--- 7. Exploring ---")

public_names = [name for name in dir(my_helpers) if not name.startswith("_")]
print("Names in my_helpers:", public_names)
print("math has", len(dir(math)), "names, e.g.", dir(math)[-5:])

# help(math.sqrt)       # uncomment to read the documentation
# help(my_helpers)      # docstrings from your own module show up here


# ---------------------------------------------------------------
# 8. Third-party packages with pip
# ---------------------------------------------------------------
#
# Packages that don't come with Python are installed from PyPI:
#
#   pip install requests          install a package
#   pip list                      see installed packages
#   pip freeze > requirements.txt save them to a file
#   pip install -r requirements.txt   install from that file
#
# Use a virtual environment so each project has its own packages:
#
#   python3 -m venv .venv
#   source .venv/bin/activate     (macOS/Linux)
#
# Then in code:
#   import requests
#   response = requests.get("https://api.github.com")


# ---------------------------------------------------------------
# 9. Packages: folders of modules
# ---------------------------------------------------------------
#
#   my_project/
#       main.py
#       utils/
#           __init__.py       (marks the folder as a package)
#           text_tools.py
#           math_tools.py
#
# In main.py:
#   from utils import text_tools
#   from utils.math_tools import add


# ---------------------------------------------------------------
# 10. Good practices
# ---------------------------------------------------------------
#
#   - Put imports at the TOP of the file. (They are spread out in this
#     file only so each one sits next to its explanation.)
#   - Order: standard library, then third-party, then your own modules.
#   - Avoid "from module import *".
#   - Don't name your files after modules you use (e.g. random.py or
#     math.py), or Python will import YOUR file instead of the real one.
#   - Put a file's "run me" code under if __name__ == "__main__":
