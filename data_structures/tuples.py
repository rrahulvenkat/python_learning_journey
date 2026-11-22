# Tuples
#
# A tuple is an ORDERED, UNCHANGEABLE (immutable) collection that
# allows DUPLICATES. Tuples are written with round brackets: (1, 2, 3)
#
# Think of a tuple as a fixed record: once made, it stays the same.
#
# Use a tuple when:
#   - the data should not change (coordinates, RGB colours, dates)
#   - you want to return several values from a function
#   - you need a dictionary key or set item made of several values
#     (lists can't do this, tuples can)
#
# Topics covered here:
#   1. Creating tuples
#   2. Indexing and slicing
#   3. Immutability
#   4. Tuple methods: count, index
#   5. Operations: +, *, in, len, min, max
#   6. Packing and unpacking
#   7. Looping over tuples
#   8. Returning several values from a function
#   9. Tuples as dictionary keys and set items
#  10. Named tuples
#  11. Tuple vs list
#  12. Practical examples


from collections import namedtuple
import sys


# ---------------------------------------------------------------
# 1. Creating tuples
# ---------------------------------------------------------------

print("--- 1. Creating tuples ---")

point = (3, 7)
colors = ("red", "green", "blue")
mixed = (1, "two", 3.0, True)
nested = ((1, 2), (3, 4))
empty = ()

# The comma makes the tuple, not the brackets
no_brackets = 10, 20, 30
single = (5,)                         # one item needs a trailing comma
not_a_tuple = (5)                     # this is just the int 5!

from_list = tuple([1, 2, 3])
from_string = tuple("abc")

print(point, colors, mixed)
print(nested, empty)
print("no_brackets:", no_brackets, type(no_brackets).__name__)
print("single:", single, type(single).__name__)
print("not_a_tuple:", not_a_tuple, type(not_a_tuple).__name__)
print(from_list, from_string)


# ---------------------------------------------------------------
# 2. Indexing and slicing (same as lists)
# ---------------------------------------------------------------

print("\n--- 2. Indexing and slicing ---")

days = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

print("days[0] =", days[0])
print("days[-1] =", days[-1])
print("days[:5] =", days[:5])         # weekdays (slicing gives a new tuple)
print("days[5:] =", days[5:])         # weekend
print("days[::-1] =", days[::-1])
print("nested[1][0] =", nested[1][0])


# ---------------------------------------------------------------
# 3. Immutability
# ---------------------------------------------------------------

print("\n--- 3. Immutability ---")

# These all raise errors:
#   point[0] = 10        TypeError: 'tuple' object does not support item assignment
#   point.append(5)      AttributeError: tuples have no append
#   del point[0]         TypeError

try:
    point[0] = 10
except TypeError as error:
    print("TypeError:", error)

# To "change" a tuple, build a new one
point = (10,) + point[1:]
print("new point:", point)

# Or convert to a list, change it, and convert back
temp = list(colors)
temp.append("yellow")
colors = tuple(temp)
print("new colors:", colors)

# Note: if a tuple contains a list, that list CAN still change
record = ("Rahul", [90, 85])
record[1].append(78)
print("tuple with a list inside:", record)


# ---------------------------------------------------------------
# 4. Tuple methods (only two!)
# ---------------------------------------------------------------

print("\n--- 4. Methods ---")

grades = ("A", "B", "A", "C", "A")
print("count('A'):", grades.count("A"))
print("index('C'):", grades.index("C"))


# ---------------------------------------------------------------
# 5. Operations
# ---------------------------------------------------------------

print("\n--- 5. Operations ---")

a = (1, 2, 3)
b = (4, 5)

print("a + b =", a + b)               # join into a new tuple
print("a * 2 =", a * 2)               # repeat
print("2 in a:", 2 in a)
print("len, min, max, sum:", len(a), min(a), max(a), sum(a))
print("sorted(a, reverse=True):", sorted(a, reverse=True))   # gives a list

# Tuples are compared item by item, left to right
print("(1, 2, 3) < (1, 3, 0):", (1, 2, 3) < (1, 3, 0))


# ---------------------------------------------------------------
# 6. Packing and unpacking
# ---------------------------------------------------------------

print("\n--- 6. Packing and unpacking ---")

person = "Rahul", 25, "Chennai"       # packing: values into a tuple
name, age, city = person              # unpacking: tuple into variables
print(f"name={name}, age={age}, city={city}")

# The number of variables must match, unless you use *
first, *rest = (1, 2, 3, 4)
print(f"first={first}, rest={rest}")  # rest is a list

*start, last = (1, 2, 3, 4)
print(f"start={start}, last={last}")

# Use _ for values you don't need
_, _, city_only = person
print("city only:", city_only)

# Swapping uses packing and unpacking behind the scenes
x, y = 1, 2
x, y = y, x
print(f"swapped: x={x}, y={y}")


# ---------------------------------------------------------------
# 7. Looping over tuples
# ---------------------------------------------------------------

print("\n--- 7. Looping ---")

for day in days[:3]:
    print(day, end=" ")
print()

# Very common: a list of tuples, unpacked in the loop
employees = [("Asha", "Engineer"), ("Ben", "Designer"), ("Chen", "Analyst")]
for emp_name, role in employees:
    print(f"{emp_name} works as: {role}")


# ---------------------------------------------------------------
# 8. Returning several values from a function
# ---------------------------------------------------------------

print("\n--- 8. Returning several values ---")


def get_stats(numbers):
    return min(numbers), max(numbers), sum(numbers) / len(numbers)


stats = get_stats([4, 8, 15, 16, 23, 42])
print("returned:", stats, type(stats).__name__)

low, high, avg = get_stats([4, 8, 15, 16, 23, 42])
print(f"low={low}, high={high}, avg={avg}")

# divmod is a built-in that returns a tuple
quotient, remainder = divmod(17, 5)
print(f"divmod(17, 5): quotient={quotient}, remainder={remainder}")


# ---------------------------------------------------------------
# 9. Tuples as dictionary keys and set items
# ---------------------------------------------------------------
#
# Dictionary keys and set items must be immutable ("hashable").
# Tuples work; lists don't.

print("\n--- 9. As dictionary keys ---")

city_at = {
    (13.08, 80.27): "Chennai",
    (40.43, -86.91): "West Lafayette",
}
print("City at (13.08, 80.27):", city_at[(13.08, 80.27)])

visited = {(0, 0), (0, 1), (1, 1)}
print("(0, 1) visited?", (0, 1) in visited)

# {[1, 2]: "x"} would raise TypeError: unhashable type: 'list'


# ---------------------------------------------------------------
# 10. Named tuples: tuples with field names
# ---------------------------------------------------------------
#
# Easier to read than point[0] and point[1], but still a tuple.

print("\n--- 10. Named tuples ---")

Point = namedtuple("Point", ["x", "y"])
p = Point(3, 4)
print(p)
print("p.x =", p.x, "| p[1] =", p[1])

Student = namedtuple("Student", "name age grade")
s = Student("Asha", 20, "A")
print(f"{s.name} is {s.age} and got an {s.grade}")
print("as dict:", s._asdict())

s2 = s._replace(grade="A+")           # makes a NEW tuple with one change
print("replaced:", s2)


# ---------------------------------------------------------------
# 11. Tuple vs list
# ---------------------------------------------------------------
#
#                 | Tuple              | List
#   --------------|--------------------|---------------------
#   Syntax        | (1, 2, 3)          | [1, 2, 3]
#   Changeable?   | No (immutable)     | Yes (mutable)
#   Methods       | count, index       | many (append, sort...)
#   Dict key?     | Yes                | No
#   Memory/speed  | Smaller, faster    | Bigger, slower
#   Use for       | fixed records      | collections that change

print("\n--- 11. Tuple vs list ---")

as_list = [1, 2, 3, 4, 5]
as_tuple = (1, 2, 3, 4, 5)
print("list size: ", sys.getsizeof(as_list), "bytes")
print("tuple size:", sys.getsizeof(as_tuple), "bytes")


# ---------------------------------------------------------------
# 12. Practical examples
# ---------------------------------------------------------------

print("\n--- 12. Practical examples ---")

# RGB colours as constants
WHITE = (255, 255, 255)
PURDUE_GOLD = (206, 184, 136)
r, g, b = PURDUE_GOLD
print(f"Gold -> red {r}, green {g}, blue {b}, hex #{r:02x}{g:02x}{b:02x}")

# Sorting records by several fields: grade first, then name
results = [("Ben", "B"), ("Asha", "A"), ("Dev", "B"), ("Chen", "A")]
by_grade = sorted(results, key=lambda rec: (rec[1], rec[0]))
print("sorted by grade, then name:", by_grade)

# Distance between two points
def distance(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    return ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5


print("distance (0,0) to (3,4):", distance((0, 0), (3, 4)))
