# Loops
#
# Loops let you repeat code without writing it again and again.
#
# Python has two kinds of loops:
#   - for loop:   repeats once for each item in a sequence
#   - while loop: repeats as long as a condition is True
#
# Topics covered here:
#   1. for loop over a list, string, tuple
#   2. for loop with range()
#   3. Looping over a dictionary
#   4. enumerate(): get the index and the item
#   5. zip(): loop over two lists together
#   6. while loop
#   7. break: stop the loop early
#   8. continue: skip to the next round
#   9. else on a loop
#  10. Nested loops
#  11. List comprehensions (a short way to build lists with a loop)
#  12. Common loop patterns (sum, count, find max, build a string)


# ---------------------------------------------------------------
# 1. for loop over a sequence
# ---------------------------------------------------------------

print("--- for loop over a list ---")

fruits = ["apple", "banana", "cherry"]

for fruit in fruits:
    print("I like", fruit)

print("\n--- for loop over a string ---")

for letter in "Hello":
    print(letter)

print("\n--- for loop over a tuple ---")

for number in (10, 20, 30):
    print(number * 2)


# ---------------------------------------------------------------
# 2. for loop with range()
# ---------------------------------------------------------------

print("\n--- range(stop) ---")
for i in range(5):              # 0, 1, 2, 3, 4 (stop is NOT included)
    print(i, end=" ")           # end=" " keeps output on one line
print()                         # move to a new line

print("--- range(start, stop) ---")
for i in range(1, 6):           # 1 to 5
    print(i, end=" ")
print()

print("--- range(start, stop, step) ---")
for i in range(0, 21, 5):       # 0, 5, 10, 15, 20
    print(i, end=" ")
print()

print("--- counting down ---")
for i in range(5, 0, -1):       # 5, 4, 3, 2, 1
    print(i, end=" ")
print("Liftoff!")

print("--- multiplication table of 7 ---")
for i in range(1, 11):
    print(f"7 x {i:2} = {7 * i}")


# ---------------------------------------------------------------
# 3. Looping over a dictionary
# ---------------------------------------------------------------

print("\n--- Looping over a dictionary ---")

prices = {"pen": 10, "notebook": 50, "bag": 500}

for item in prices:                     # loops over the keys
    print("Key:", item)

for price in prices.values():           # loops over the values
    print("Value:", price)

for item, price in prices.items():      # loops over key-value pairs
    print(f"{item} costs Rs. {price}")


# ---------------------------------------------------------------
# 4. enumerate(): index and item together
# ---------------------------------------------------------------

print("\n--- enumerate ---")

colors = ["red", "green", "blue"]

for index, color in enumerate(colors):
    print(index, color)

for position, color in enumerate(colors, start=1):   # start counting at 1
    print(f"{position}. {color}")


# ---------------------------------------------------------------
# 5. zip(): loop over two (or more) lists at the same time
# ---------------------------------------------------------------

print("\n--- zip ---")

names = ["Asha", "Ben", "Chen"]
scores = [88, 92, 79]

for name, score in zip(names, scores):
    print(f"{name} scored {score}")

# zip stops at the shortest list


# ---------------------------------------------------------------
# 6. while loop: repeat while a condition is True
# ---------------------------------------------------------------

print("\n--- while loop ---")

count = 1
while count <= 5:
    print("Count is", count)
    count += 1          # IMPORTANT: update the variable, or the loop never ends

# Example: how many years to double money at 10% interest?
money = 1000
years = 0
while money < 2000:
    money = money * 1.10
    years += 1
print(f"Money doubles in {years} years (final: {money:.2f})")

# while loops are useful when you don't know in advance how many
# times to repeat. With a for loop, you usually do know.


# ---------------------------------------------------------------
# 7. break: stop the loop immediately
# ---------------------------------------------------------------

print("\n--- break ---")

numbers = [3, 8, 12, 5, 20, 7]

for n in numbers:
    if n > 10:
        print(f"Found the first number greater than 10: {n}")
        break               # exit the loop, skip the rest
    print(f"{n} is not greater than 10")

# break with while True: an "infinite" loop you exit on purpose
attempt = 0
while True:
    attempt += 1
    print("Attempt", attempt)
    if attempt == 3:
        print("Done after 3 attempts")
        break


# ---------------------------------------------------------------
# 8. continue: skip the rest of this round, go to the next
# ---------------------------------------------------------------

print("\n--- continue ---")

for i in range(1, 11):
    if i % 2 == 0:
        continue            # skip even numbers
    print(i, end=" ")
print("<- odd numbers only")


# ---------------------------------------------------------------
# 9. else on a loop
# ---------------------------------------------------------------

print("\n--- for / else ---")

# The else block runs only if the loop finished WITHOUT a break.
# Useful for "search" loops.

target = 9
for n in [1, 3, 5, 7]:
    if n == target:
        print(f"Found {target}")
        break
else:
    print(f"{target} was not found")

# Example: check if a number is prime
num = 29
for divisor in range(2, num):
    if num % divisor == 0:
        print(f"{num} is not prime (divisible by {divisor})")
        break
else:
    print(f"{num} is prime")


# ---------------------------------------------------------------
# 10. Nested loops: a loop inside another loop
# ---------------------------------------------------------------

print("\n--- Nested loops ---")

for row in range(1, 4):
    for col in range(1, 4):
        print(f"({row},{col})", end=" ")
    print()     # new line after each row

print("--- Star triangle ---")
for i in range(1, 6):
    print("*" * i)

# Note: break only exits the INNERMOST loop it is in.


# ---------------------------------------------------------------
# 11. List comprehensions: build a list with a loop in one line
# ---------------------------------------------------------------

print("\n--- List comprehensions ---")

# The long way
squares = []
for x in range(1, 6):
    squares.append(x ** 2)
print("Squares (loop):         ", squares)

# The short way: [expression for item in sequence]
squares = [x ** 2 for x in range(1, 6)]
print("Squares (comprehension):", squares)

# With a condition: [expression for item in sequence if condition]
evens = [x for x in range(1, 11) if x % 2 == 0]
print("Even numbers:", evens)

upper_fruits = [f.upper() for f in fruits]
print("Upper fruits:", upper_fruits)

# Dictionary comprehension
square_map = {x: x ** 2 for x in range(1, 4)}
print("Square map:", square_map)


# ---------------------------------------------------------------
# 12. Common loop patterns
# ---------------------------------------------------------------

print("\n--- Common patterns ---")

marks = [72, 85, 90, 64, 88]

# Sum (accumulator)
total = 0
for m in marks:
    total += m
print("Total:", total, "| built-in sum():", sum(marks))

# Count items that match a condition
above_80 = 0
for m in marks:
    if m > 80:
        above_80 += 1
print("Marks above 80:", above_80)

# Find the maximum
highest = marks[0]
for m in marks:
    if m > highest:
        highest = m
print("Highest:", highest, "| built-in max():", max(marks))

# Build a string
word = "python"
reversed_word = ""
for ch in word:
    reversed_word = ch + reversed_word
print(f"'{word}' reversed is '{reversed_word}'")

# Loop over a list in reverse
for fruit in reversed(fruits):
    print(fruit, end=" ")
print("<- reversed")

# Tip: don't add or remove items from a list while looping over it.
# Loop over a copy instead, e.g.  for x in my_list[:]:
