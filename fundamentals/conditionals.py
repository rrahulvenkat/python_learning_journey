# Conditionals
#
# Conditionals let your program make decisions: run some code only
# when a condition is True.
#
# Types of conditionals covered here:
#   1. if
#   2. if / else
#   3. if / elif / else
#   4. Nested if
#   5. Combining conditions with and / or / not
#   6. Truthy and falsy conditions
#   7. Conditional expression (one-line if / else)
#   8. match / case (Python 3.10+)
#   9. pass (placeholder for an empty block)
#
# Important: Python uses INDENTATION (usually 4 spaces) to mark
# which lines belong inside an if block. Don't forget the colon ":".


# ---------------------------------------------------------------
# 1. if: run code only when the condition is True
# ---------------------------------------------------------------

print("--- if ---")

temperature = 32

if temperature > 30:
    print("It's hot today!")
    print("Drink plenty of water.")   # also inside the if block

print("This line always runs.")      # not indented, so outside the if


# ---------------------------------------------------------------
# 2. if / else: choose between two paths
# ---------------------------------------------------------------

print("\n--- if / else ---")

age = 16

if age >= 18:
    print("You can vote.")
else:
    print("You are too young to vote.")

number = 7
if number % 2 == 0:
    print(f"{number} is even")
else:
    print(f"{number} is odd")


# ---------------------------------------------------------------
# 3. if / elif / else: choose between many paths
# ---------------------------------------------------------------

print("\n--- if / elif / else ---")

# Python checks each condition from top to bottom and runs ONLY
# the first block whose condition is True.

marks = 78

if marks >= 90:
    grade = "A"
elif marks >= 75:
    grade = "B"
elif marks >= 60:
    grade = "C"
elif marks >= 40:
    grade = "D"
else:
    grade = "F"

print(f"Marks: {marks}, Grade: {grade}")

# Order matters! If "marks >= 40" came first, 78 would get a "D".


# ---------------------------------------------------------------
# 4. Nested if: an if inside another if
# ---------------------------------------------------------------

print("\n--- Nested if ---")

has_ticket = True
bag_checked = False

if has_ticket:
    print("Ticket verified.")
    if bag_checked:
        print("You may board the flight.")
    else:
        print("Please go to bag check first.")
else:
    print("Please buy a ticket.")


# ---------------------------------------------------------------
# 5. Combining conditions: and, or, not
# ---------------------------------------------------------------

print("\n--- Combining conditions ---")

age = 25
has_license = True

# and: both must be True
if age >= 18 and has_license:
    print("You can drive.")

# or: at least one must be True
day = "Sunday"
if day == "Saturday" or day == "Sunday":
    print("It's the weekend!")

# A cleaner way to check against several values: use "in"
if day in ("Saturday", "Sunday"):
    print("Still the weekend (checked with 'in').")

# not: flips the condition
is_raining = False
if not is_raining:
    print("No umbrella needed.")

# Chained comparison: checks a range in one go
score = 55
if 50 <= score <= 100:
    print("You passed.")


# ---------------------------------------------------------------
# 6. Truthy and falsy conditions
# ---------------------------------------------------------------

print("\n--- Truthy and falsy ---")

# A condition doesn't have to be True/False. Python treats these
# values as False: 0, 0.0, "", [], (), {}, set(), None
# Everything else is treated as True.

name = ""
if name:
    print(f"Hello, {name}!")
else:
    print("Name is empty.")

shopping_list = ["milk", "eggs"]
if shopping_list:
    print(f"You have {len(shopping_list)} items to buy.")

result = None
if result is None:
    print("No result yet.")


# ---------------------------------------------------------------
# 7. Conditional expression (ternary): if / else on one line
# ---------------------------------------------------------------

print("\n--- Conditional expression ---")

# Format: value_if_true if condition else value_if_false

age = 20
status = "adult" if age >= 18 else "minor"
print(f"Age {age} is an {status}.")

x = -5
absolute = x if x >= 0 else -x
print(f"Absolute value of {x} is {absolute}")

# Can be used directly inside print or an f-string
items = 1
print(f"You have {items} {'item' if items == 1 else 'items'}.")


# ---------------------------------------------------------------
# 8. match / case: compare one value against many patterns
# ---------------------------------------------------------------

print("\n--- match / case ---")

# Similar to "switch" in other languages. Needs Python 3.10 or newer.

command = "stop"

match command:
    case "start":
        print("Starting the engine.")
    case "stop":
        print("Stopping the engine.")
    case "pause" | "wait":           # | means "or"
        print("Pausing.")
    case _:                          # _ matches anything (like else)
        print("Unknown command.")

# match can also add an extra condition with "if" (a guard)
temperature = 15

match temperature:
    case t if t < 0:
        print("Freezing")
    case t if t < 20:
        print("Cold")
    case t if t < 30:
        print("Pleasant")
    case _:
        print("Hot")

# match can unpack tuples and lists
point = (0, 5)

match point:
    case (0, 0):
        print("At the origin")
    case (0, y):
        print(f"On the y-axis at y={y}")
    case (x, 0):
        print(f"On the x-axis at x={x}")
    case (x, y):
        print(f"At x={x}, y={y}")


# ---------------------------------------------------------------
# 9. pass: an empty block placeholder
# ---------------------------------------------------------------

print("\n--- pass ---")

# Python doesn't allow an empty block. Use "pass" when you want to
# write the code later.

level = 3
if level > 5:
    pass   # TODO: add bonus reward later
else:
    print("Keep playing to reach level 6.")


# ---------------------------------------------------------------
# Putting it together: a small example
# ---------------------------------------------------------------

print("\n--- Example: movie ticket price ---")

age = 67
is_student = False
day = "Tuesday"

if age < 5:
    price = 0
elif age < 18 or is_student:
    price = 8
elif age >= 65:
    price = 6
else:
    price = 12

if day == "Tuesday" and price > 0:
    price -= 2   # Tuesday discount

print(f"Age {age}, student: {is_student}, day: {day}")
print(f"Ticket price: ${price}")
