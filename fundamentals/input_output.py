# Input and Output
#
# Output: showing information to the user with print().
# Input:  reading what the user types with input().
#
# Topics covered here:
#   1. print() basics: sep, end
#   2. Escape characters (\n, \t, \\, \")
#   3. String formatting: f-strings, .format(), % (old style)
#   4. Format specifiers: decimals, width, alignment, commas, percent
#   5. input() basics: input always returns a string
#   6. Converting input to numbers
#   7. Reading several values on one line
#   8. Validating input in a loop
#   9. Small interactive program
#
# input() waits for you to type, so the interactive examples only run
# when RUN_INTERACTIVE is True. Change it below to try them.

RUN_INTERACTIVE = False


# ---------------------------------------------------------------
# 1. print() basics
# ---------------------------------------------------------------

print("--- 1. print() basics ---")

print("Hello, World!")
print("Python", "is", "fun")             # several values, separated by spaces
print("2026", "11", "22", sep="-")       # sep: what goes BETWEEN values
print("Loading", end="")                 # end: what goes at the END (default "\n")
print("...", end="")
print(" done!")
print()                                  # empty line
print("Name:", "Rahul", "| Age:", 25)    # mix strings and numbers


# ---------------------------------------------------------------
# 2. Escape characters
# ---------------------------------------------------------------

print("--- 2. Escape characters ---")

print("Line one\nLine two")              # \n new line
print("Name:\tRahul")                    # \t tab
print("She said \"hello\"")              # \" double quote inside double quotes
print('It\'s working')                   # \' single quote inside single quotes
print("Folder: C:\\Users\\Rahul")        # \\ a real backslash
print(r"Raw string: C:\new\test")        # r"..." ignores escape characters


# ---------------------------------------------------------------
# 3. String formatting
# ---------------------------------------------------------------

print("\n--- 3. String formatting ---")

name = "Rahul"
age = 25
gpa = 3.756

# f-strings (recommended, Python 3.6+)
print(f"{name} is {age} years old.")
print(f"Next year: {age + 1}")           # expressions work inside {}
print(f"Uppercase: {name.upper()}")      # so do method calls
print(f"{age = }")                       # debug style: prints "age = 25"

# .format() (older, still common)
print("{} is {} years old.".format(name, age))
print("{n} has a GPA of {g}".format(n=name, g=gpa))

# % formatting (oldest style, you'll see it in old code)
print("%s is %d years old." % (name, age))


# ---------------------------------------------------------------
# 4. Format specifiers: {value:spec}
# ---------------------------------------------------------------

print("\n--- 4. Format specifiers ---")

price = 1234567.891
ratio = 0.8567

print(f"2 decimals:      {gpa:.2f}")         # 3.76
print(f"No decimals:     {gpa:.0f}")         # 4
print(f"Thousands comma: {price:,.2f}")      # 1,234,567.89
print(f"Percent:         {ratio:.1%}")       # 85.7%
print(f"Zero padded:     {7:03}")            # 007
print(f"Binary:          {10:b}")            # 1010
print(f"Hex:             {255:x}")           # ff

# Width and alignment: < left, > right, ^ centre
print(f"[{name:<10}]")                       # left-aligned in 10 spaces
print(f"[{name:>10}]")                       # right-aligned
print(f"[{name:^10}]")                       # centred
print(f"[{name:*^10}]")                      # centred, padded with *

# Printing a neat table
print()
items = [("Pen", 2, 10.5), ("Notebook", 3, 45.0), ("Backpack", 1, 1299.99)]
print(f"{'Item':<10}{'Qty':>5}{'Price':>10}")
print("-" * 25)
for item, qty, cost in items:
    print(f"{item:<10}{qty:>5}{cost:>10.2f}")


# ---------------------------------------------------------------
# 5-9. Input (only runs when RUN_INTERACTIVE = True)
# ---------------------------------------------------------------


def input_basics():
    print("\n--- 5. input() basics ---")

    user_name = input("What is your name? ")     # the text is the prompt
    print(f"Nice to meet you, {user_name}!")

    # input() ALWAYS returns a string, even if you type a number
    value = input("Type a number: ")
    print(f"You typed {value!r}, which is a {type(value).__name__}")


def converting_input():
    print("\n--- 6. Converting input ---")

    age = int(input("Enter your age: "))         # string -> int
    height = float(input("Enter your height in metres: "))   # string -> float
    print(f"In 10 years you'll be {age + 10}.")
    print(f"Your height is {height * 100:.0f} cm.")

    # Without int(), "20" + 10 would raise a TypeError,
    # and "20" * 2 would give "2020", not 40.


def multiple_values():
    print("\n--- 7. Several values on one line ---")

    # .split() breaks the text on spaces
    first, last = input("Enter your first and last name: ").split()
    print(f"First: {first}, Last: {last}")

    # map() converts every piece to an int
    numbers = list(map(int, input("Enter numbers separated by spaces: ").split()))
    print(f"Sum: {sum(numbers)}, Max: {max(numbers)}")

    # Split on a different character
    date = input("Enter a date as DD/MM/YYYY: ")
    day, month, year = date.split("/")
    print(f"Day {day}, month {month}, year {year}")


def validated_input():
    print("\n--- 8. Validating input ---")

    # Keep asking until the input is valid
    while True:
        text = input("Enter a score between 0 and 100: ")
        try:
            score = int(text)
        except ValueError:
            print("That's not a whole number. Try again.")
            continue
        if 0 <= score <= 100:
            break
        print("Score must be between 0 and 100.")

    print(f"Accepted score: {score}")

    # Yes/no question
    answer = input("Do you want to continue? (y/n): ").strip().lower()
    if answer in ("y", "yes"):
        print("Continuing...")
    else:
        print("Stopping.")


def tip_calculator():
    print("\n--- 9. Tip calculator ---")

    bill = float(input("Bill amount: "))
    tip_percent = float(input("Tip percentage (e.g. 15): "))
    people = int(input("Number of people: "))

    tip = bill * tip_percent / 100
    total = bill + tip
    per_person = total / people

    print(f"\n{'Bill:':<12}{bill:>10.2f}")
    print(f"{'Tip:':<12}{tip:>10.2f}")
    print(f"{'Total:':<12}{total:>10.2f}")
    print(f"{'Per person:':<12}{per_person:>10.2f}")


if RUN_INTERACTIVE:
    input_basics()
    converting_input()
    multiple_values()
    validated_input()
    tip_calculator()
else:
    print("\n(Set RUN_INTERACTIVE = True at the top of this file to try the input() examples.)")
