# Data Types
#
# Every value in Python has a data type. The type decides what the
# value can do (e.g. you can add numbers, but uppercase a string).
#
# Built-in types covered here:
#   Numbers:     int, float, complex
#   Text:        str
#   Boolean:     bool
#   Sequences:   list, tuple, range
#   Mapping:     dict
#   Sets:        set, frozenset
#   Nothing:     NoneType (None)


# ---------------------------------------------------------------
# 1. Numbers: int, float, complex
# ---------------------------------------------------------------

print("--- Numbers ---")

count = 42                 # int: whole numbers, any size
big_number = 1_000_000     # underscores make big numbers readable
temperature = -3.5         # float: numbers with a decimal point
scientific = 2.5e3         # float in scientific notation (2500.0)
z = 3 + 4j                 # complex: real part + imaginary part

print(count, type(count))
print(big_number, type(big_number))
print(temperature, type(temperature))
print(scientific, type(scientific))
print(z, type(z), "real:", z.real, "imag:", z.imag)

# Number operations
print("10 / 3  =", 10 / 3)     # true division always gives a float
print("10 // 3 =", 10 // 3)    # floor division gives an int
print("10 % 3  =", 10 % 3)     # remainder
print("2 ** 10 =", 2 ** 10)    # power
print("round(3.14159, 2) =", round(3.14159, 2))
print("abs(-7) =", abs(-7))

# Floats are not always exact
print("0.1 + 0.2 =", 0.1 + 0.2)


# ---------------------------------------------------------------
# 2. Strings: str
# ---------------------------------------------------------------

print("\n--- Strings ---")

language = "Python"
quote = 'She said "hi"'        # single quotes let you use " inside
multi_line = """This string
spans two lines."""

print(language, type(language))
print(quote)
print(multi_line)

# Strings are sequences of characters
print("Length:", len(language))
print("First char:", language[0])
print("Last char:", language[-1])
print("Slice [0:3]:", language[0:3])

# Common string methods
print(language.upper())
print(language.lower())
print("  padded  ".strip())
print(language.replace("Py", "My"))
print("a,b,c".split(","))
print("-".join(["x", "y", "z"]))
print("Py" in language)        # check if text is inside a string

# Strings are immutable: language[0] = "J" would raise a TypeError.
# Instead, create a new string:
new_language = "J" + language[1:]
print(new_language)


# ---------------------------------------------------------------
# 3. Booleans: bool
# ---------------------------------------------------------------

print("\n--- Booleans ---")

is_raining = False
has_ticket = True

print(is_raining, type(is_raining))
print("and:", has_ticket and is_raining)
print("or: ", has_ticket or is_raining)
print("not:", not is_raining)

# Comparisons produce booleans
print("5 > 3:", 5 > 3)
print("5 == 3:", 5 == 3)

# "Truthy" and "falsy" values: these all count as False
print(bool(0), bool(0.0), bool(""), bool([]), bool({}), bool(None))
# Most other values count as True
print(bool(1), bool("hi"), bool([0]))


# ---------------------------------------------------------------
# 4. Lists: list (ordered, changeable, allows duplicates)
# ---------------------------------------------------------------

print("\n--- Lists ---")

fruits = ["apple", "banana", "cherry"]
mixed = [1, "two", 3.0, True]   # a list can hold different types

print(fruits, type(fruits))
print(mixed)

fruits.append("mango")          # add to the end
fruits.insert(1, "kiwi")        # add at a position
fruits.remove("banana")         # remove by value
last = fruits.pop()             # remove and return the last item
fruits[0] = "green apple"       # change an item

print("Fruits:", fruits)
print("Popped:", last)
print("Length:", len(fruits))
print("Sorted:", sorted(fruits))


# ---------------------------------------------------------------
# 5. Tuples: tuple (ordered, NOT changeable)
# ---------------------------------------------------------------

print("\n--- Tuples ---")

point = (10, 20)
single = (5,)                   # a one-item tuple needs a trailing comma

print(point, type(point))
print(single, type(single))
print("x =", point[0], "y =", point[1])

# Unpacking a tuple into variables
x, y = point
print(f"Unpacked: x={x}, y={y}")

# point[0] = 99 would raise a TypeError because tuples can't change


# ---------------------------------------------------------------
# 6. Range: range (a sequence of numbers)
# ---------------------------------------------------------------

print("\n--- Range ---")

numbers = range(5)              # 0, 1, 2, 3, 4
evens = range(0, 11, 2)         # start, stop (excluded), step

print(numbers, type(numbers))
print(list(numbers))
print(list(evens))


# ---------------------------------------------------------------
# 7. Dictionaries: dict (key-value pairs)
# ---------------------------------------------------------------

print("\n--- Dictionaries ---")

student = {
    "name": "Rahul",
    "age": 25,
    "courses": ["Python", "SQL"],
}

print(student, type(student))
print("Name:", student["name"])
print("Grade:", student.get("grade", "not set"))  # safe lookup with default

student["age"] = 26             # update a value
student["grade"] = "A"          # add a new key
del student["courses"]          # remove a key

print("Updated:", student)
print("Keys:", list(student.keys()))
print("Values:", list(student.values()))

for key, value in student.items():
    print(f"  {key} -> {value}")


# ---------------------------------------------------------------
# 8. Sets: set and frozenset (unordered, unique items)
# ---------------------------------------------------------------

print("\n--- Sets ---")

colors = {"red", "green", "blue", "red"}   # duplicate "red" is dropped
print(colors, type(colors))

colors.add("yellow")
colors.discard("green")
print("After changes:", colors)

a = {1, 2, 3, 4}
b = {3, 4, 5, 6}
print("Union:       ", a | b)
print("Intersection:", a & b)
print("Difference:  ", a - b)

empty_set = set()               # note: {} makes an empty dict, not a set
print(type(empty_set), type({}))

frozen = frozenset([1, 2, 3])   # like a set, but can't be changed
print(frozen, type(frozen))


# ---------------------------------------------------------------
# 9. None: NoneType
# ---------------------------------------------------------------

print("\n--- None ---")

result = None
print(result, type(result))

if result is None:              # use "is" to check for None
    print("No result yet")


# ---------------------------------------------------------------
# 10. Checking and converting types
# ---------------------------------------------------------------

print("\n--- Checking and converting ---")

value = 3.7
print("type():", type(value))
print("isinstance(value, float):", isinstance(value, float))
print("isinstance(value, (int, float)):", isinstance(value, (int, float)))

print(int("15"), float("2.5"), str(100))
print(list("abc"))              # string -> list of characters
print(tuple([1, 2, 3]))         # list -> tuple
print(set([1, 1, 2, 3]))        # list -> set (removes duplicates)
print(dict([("a", 1), ("b", 2)]))  # list of pairs -> dict


# ---------------------------------------------------------------
# Summary: mutable vs immutable
# ---------------------------------------------------------------
#
# Immutable (can't be changed after creation):
#   int, float, complex, str, bool, tuple, frozenset, None
#
# Mutable (can be changed in place):
#   list, dict, set
