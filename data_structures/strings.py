# Strings
#
# A string is an ordered sequence of characters, used for any text.
# Strings are IMMUTABLE: once created, they can't be changed. Every
# string method returns a NEW string instead of changing the old one.
#
# Topics covered here:
#   1. Creating strings
#   2. Indexing (getting one character)
#   3. Slicing (getting part of a string)
#   4. Immutability
#   5. Combining and repeating
#   6. Changing case
#   7. Removing whitespace and characters
#   8. Searching: in, find, index, count, startswith, endswith
#   9. Replacing
#  10. Splitting and joining
#  11. Checking content: isdigit, isalpha, isupper, ...
#  12. Alignment and padding
#  13. Looping over strings
#  14. Comparing strings
#  15. Characters and their codes: ord, chr
#  16. Bytes and encoding
#  17. Useful constants from the string module
#  18. Practical examples: palindrome, word count, password check


import string


# ---------------------------------------------------------------
# 1. Creating strings
# ---------------------------------------------------------------

print("--- 1. Creating strings ---")

single = 'Hello'
double = "Hello"
with_quote = "It's easy"              # use the other quote type inside
triple = """This string
spans several
lines."""
empty = ""
from_number = str(2026)               # convert another type to a string

print(single, double, with_quote)
print(triple)
print("Empty string length:", len(empty))
print("From number:", from_number, type(from_number))


# ---------------------------------------------------------------
# 2. Indexing: get one character by its position
# ---------------------------------------------------------------
#
#   String:     P   y   t   h   o   n
#   Index:      0   1   2   3   4   5
#   Negative:  -6  -5  -4  -3  -2  -1

print("\n--- 2. Indexing ---")

word = "Python"
print("word[0] =", word[0])           # first character
print("word[3] =", word[3])
print("word[-1] =", word[-1])         # last character
print("word[-2] =", word[-2])         # second to last
print("len(word) =", len(word))
# word[10] would raise IndexError: string index out of range


# ---------------------------------------------------------------
# 3. Slicing: string[start:stop:step]
# ---------------------------------------------------------------
#
# start is included, stop is NOT included.
# Leave a part out to use the default (start=0, stop=end, step=1).

print("\n--- 3. Slicing ---")

text = "Hello, World!"
print("text[0:5]  =", text[0:5])      # Hello
print("text[7:]   =", text[7:])       # World!  (from 7 to the end)
print("text[:5]   =", text[:5])       # Hello   (from the start to 5)
print("text[-6:]  =", text[-6:])      # World!  (last 6 characters)
print("text[::2]  =", text[::2])      # every 2nd character
print("text[::-1] =", text[::-1])     # reversed
print("text[:]    =", text[:])        # a full copy

# Slicing never raises an error, even past the end
print("text[5:100] =", text[5:100])


# ---------------------------------------------------------------
# 4. Immutability
# ---------------------------------------------------------------

print("\n--- 4. Immutability ---")

name = "rahul"
# name[0] = "R"                       # TypeError: strings can't be changed

name.upper()                          # returns a new string...
print("After name.upper():", name)    # ...but name is unchanged!

name = name.upper()                   # save the new string to keep it
print("After name = name.upper():", name)

# To "change" one character, build a new string
name = "rahul"
name = "R" + name[1:]
print("Built a new string:", name)


# ---------------------------------------------------------------
# 5. Combining and repeating
# ---------------------------------------------------------------

print("\n--- 5. Combining and repeating ---")

first = "Rahul"
last = "Venkat"

print(first + " " + last)             # concatenation with +
print(f"{first} {last}")              # f-string (usually cleaner)
print("=" * 20)                       # repeat with *
print("ha" * 3)

# + only joins strings with strings
age = 25
# print("Age: " + age)                # TypeError
print("Age: " + str(age))             # convert first
print(f"Age: {age}")                  # or use an f-string


# ---------------------------------------------------------------
# 6. Changing case
# ---------------------------------------------------------------

print("\n--- 6. Changing case ---")

msg = "learning PYTHON is Fun"
print("upper():     ", msg.upper())
print("lower():     ", msg.lower())
print("title():     ", msg.title())         # First Letter Of Each Word
print("capitalize():", msg.capitalize())    # only the first letter
print("swapcase():  ", msg.swapcase())

# Case-insensitive comparison: lower both sides first
print("'YES'.lower() == 'yes':", "YES".lower() == "yes")


# ---------------------------------------------------------------
# 7. Removing whitespace and characters
# ---------------------------------------------------------------

print("\n--- 7. Stripping ---")

messy = "   hello world   "
print(f"strip():  [{messy.strip()}]")      # both sides
print(f"lstrip(): [{messy.lstrip()}]")     # left side only
print(f"rstrip(): [{messy.rstrip()}]")     # right side only

# Strip specific characters instead of whitespace
print("'***sale***'.strip('*') =", "***sale***".strip("*"))
print("'www.site.com'.strip('w.') =", "www.site.com".strip("w."))

# Remove an exact prefix or suffix (Python 3.9+)
filename = "report_final.txt"
print("removesuffix('.txt'):", filename.removesuffix(".txt"))
print("removeprefix('report_'):", filename.removeprefix("report_"))


# ---------------------------------------------------------------
# 8. Searching
# ---------------------------------------------------------------

print("\n--- 8. Searching ---")

sentence = "the quick brown fox jumps over the lazy dog"

print("'fox' in sentence:", "fox" in sentence)
print("'cat' not in sentence:", "cat" not in sentence)

print("find('the'):", sentence.find("the"))          # first position
print("rfind('the'):", sentence.rfind("the"))        # last position
print("find('cat'):", sentence.find("cat"))          # -1 if not found

print("index('quick'):", sentence.index("quick"))    # like find...
# sentence.index("cat")                              # ...but raises ValueError

print("count('o'):", sentence.count("o"))
print("startswith('the'):", sentence.startswith("the"))
print("endswith('dog'):", sentence.endswith("dog"))

# startswith/endswith accept a tuple of options
file = "photo.png"
print("Is image?", file.endswith((".png", ".jpg", ".gif")))


# ---------------------------------------------------------------
# 9. Replacing
# ---------------------------------------------------------------

print("\n--- 9. Replacing ---")

quote = "I like cats. Cats are great. cats!"
print(quote.replace("cats", "dogs"))         # case-sensitive
print(quote.replace("cats", "dogs", 1))      # only the first match
print("a-b-c".replace("-", ""))              # remove characters

# Replace several characters at once with translate()
table = str.maketrans({"a": "4", "e": "3", "o": "0"})
print("translate():", "hello leet coder".translate(table))


# ---------------------------------------------------------------
# 10. Splitting and joining
# ---------------------------------------------------------------

print("\n--- 10. Splitting and joining ---")

# split(): string -> list
print("split():", "red green blue".split())          # on any whitespace
print("split(','):", "a,b,,c".split(","))            # on a separator
print("split(',', 1):", "a,b,c".split(",", 1))       # at most 1 split

# rsplit splits from the right
path = "home/rahul/docs/notes.txt"
folder, file_name = path.rsplit("/", 1)
print(f"folder={folder}, file={file_name}")

# splitlines(): split on line breaks
poem = "Roses are red\nViolets are blue"
print("splitlines():", poem.splitlines())

# partition(): split once into (before, separator, after)
print("partition('='):", "user=rahul".partition("="))

# join(): list -> string. The string you call it on goes BETWEEN items
words = ["Python", "is", "awesome"]
print("' '.join():", " ".join(words))
print("'-'.join():", "-".join(words))
print("''.join():", "".join(["a", "b", "c"]))
print("join numbers:", ", ".join(str(n) for n in [1, 2, 3]))   # convert first


# ---------------------------------------------------------------
# 11. Checking content
# ---------------------------------------------------------------
#
# These methods return True or False.

print("\n--- 11. Checking content ---")

samples = ["12345", "hello", "Hello123", "HELLO", "   ", "Hello World"]

print(f"{'value':<14}{'digit':<7}{'alpha':<7}{'alnum':<7}{'upper':<7}{'lower':<7}{'space':<7}")
for s in samples:
    print(f"{s!r:<14}{s.isdigit()!s:<7}{s.isalpha()!s:<7}{s.isalnum()!s:<7}"
          f"{s.isupper()!s:<7}{s.islower()!s:<7}{s.isspace()!s:<7}")

print("'Hello World'.istitle():", "Hello World".istitle())


# ---------------------------------------------------------------
# 12. Alignment and padding
# ---------------------------------------------------------------

print("\n--- 12. Alignment and padding ---")

label = "Menu"
print(f"[{label.ljust(10)}]")         # left-align in 10 characters
print(f"[{label.rjust(10)}]")         # right-align
print(f"[{label.center(10)}]")        # centre
print(f"[{label.center(10, '-')}]")   # centre with a fill character
print("'42'.zfill(5) =", "42".zfill(5))   # pad with zeros


# ---------------------------------------------------------------
# 13. Looping over strings
# ---------------------------------------------------------------

print("\n--- 13. Looping ---")

for ch in "abc":
    print(ch, end=" ")
print()

for i, ch in enumerate("abc"):
    print(f"index {i}: {ch}")

# Count vowels
vowels = sum(1 for ch in "programming in python" if ch in "aeiou")
print("Vowels in 'programming in python':", vowels)

# Keep only certain characters (a string comprehension using join)
phone = "+1 (765) 555-0123"
digits_only = "".join(ch for ch in phone if ch.isdigit())
print("Digits only:", digits_only)


# ---------------------------------------------------------------
# 14. Comparing strings
# ---------------------------------------------------------------
#
# Strings are compared character by character using their codes.
# Uppercase letters (A=65) come before lowercase (a=97).

print("\n--- 14. Comparing ---")

print("'apple' == 'apple':", "apple" == "apple")
print("'apple' == 'Apple':", "apple" == "Apple")
print("'apple' < 'banana':", "apple" < "banana")
print("'Zebra' < 'apple':", "Zebra" < "apple")
print("'10' < '9':", "10" < "9")      # True! compares '1' with '9'

fruits = ["banana", "apple", "Cherry"]
print("sorted():", sorted(fruits))
print("sorted(key=str.lower):", sorted(fruits, key=str.lower))


# ---------------------------------------------------------------
# 15. Characters and their codes
# ---------------------------------------------------------------

print("\n--- 15. ord and chr ---")

print("ord('A') =", ord("A"))         # character -> number
print("ord('a') =", ord("a"))
print("chr(66) =", chr(66))           # number -> character

# Caesar cipher: shift each letter by a fixed amount


def caesar(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch
    return result


secret = caesar("Hello, World!", 3)
print("Encrypted:", secret)
print("Decrypted:", caesar(secret, -3))


# ---------------------------------------------------------------
# 16. Bytes and encoding
# ---------------------------------------------------------------
#
# Computers store text as bytes. encode() turns a string into bytes,
# decode() turns bytes back into a string. UTF-8 is the usual encoding.

print("\n--- 16. Bytes and encoding ---")

text = "café ₹"
data = text.encode("utf-8")
print("encoded:", data)
print("characters:", len(text), "| bytes:", len(data))
print("decoded:", data.decode("utf-8"))


# ---------------------------------------------------------------
# 17. Constants from the string module
# ---------------------------------------------------------------

print("\n--- 17. string module ---")

print("ascii_lowercase:", string.ascii_lowercase)
print("ascii_uppercase:", string.ascii_uppercase)
print("digits:         ", string.digits)
print("punctuation:    ", string.punctuation)


# ---------------------------------------------------------------
# 18. Practical examples
# ---------------------------------------------------------------

print("\n--- 18. Practical examples ---")


# Palindrome check (ignores case, spaces and punctuation)
def is_palindrome(text):
    cleaned = "".join(ch.lower() for ch in text if ch.isalnum())
    return cleaned == cleaned[::-1]


for phrase in ["racecar", "A man, a plan, a canal: Panama", "hello"]:
    print(f"{phrase!r} palindrome? {is_palindrome(phrase)}")


# Word frequency
def word_count(text):
    counts = {}
    for w in text.lower().split():
        w = w.strip(string.punctuation)
        if w:
            counts[w] = counts.get(w, 0) + 1
    return counts


print("\nWord count:", word_count("The cat and the hat. The end!"))


# Simple password strength check
def password_strength(password):
    checks = {
        "at least 8 characters": len(password) >= 8,
        "an uppercase letter": any(ch.isupper() for ch in password),
        "a lowercase letter": any(ch.islower() for ch in password),
        "a digit": any(ch.isdigit() for ch in password),
        "a symbol": any(ch in string.punctuation for ch in password),
    }
    missing = [rule for rule, passed in checks.items() if not passed]
    score = len(checks) - len(missing)
    return score, missing


print()
for pw in ["password", "Passw0rd", "S3cure!Pass"]:
    score, missing = password_strength(pw)
    note = "missing " + ", ".join(missing) if missing else "strong"
    print(f"{pw:<12} score {score}/5 -> {note}")
