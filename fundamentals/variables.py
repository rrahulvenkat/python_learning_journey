# Variables
#
# A variable is a name that refers to a value stored in memory.
# In Python you create a variable just by assigning a value with "=".
# You don't declare a type; Python works it out from the value.


# ---------------------------------------------------------------
# 1. Declaring variables of different types
# ---------------------------------------------------------------

# Integer (whole number)
age = 25

# Float (number with a decimal point)
height = 5.9

# String (text), use single or double quotes
name = "Rahul"
city = 'Chennai'

# Boolean (True or False)
is_student = True

# None (means "no value yet")
middle_name = None

# List (ordered, changeable collection)
hobbies = ["reading", "cricket", "coding"]

# Tuple (ordered, unchangeable collection)
coordinates = (13.08, 80.27)

# Dictionary (key-value pairs)
person = {"name": "Rahul", "age": 25}

# Set (unordered collection of unique items)
favourite_numbers = {3, 7, 7, 9}  # the duplicate 7 is kept only once


# ---------------------------------------------------------------
# 2. Printing variables and checking their types
# ---------------------------------------------------------------

print("--- Values and types ---")
print(age, type(age))
print(height, type(height))
print(name, type(name))
print(is_student, type(is_student))
print(middle_name, type(middle_name))
print(hobbies, type(hobbies))
print(coordinates, type(coordinates))
print(person, type(person))
print(favourite_numbers, type(favourite_numbers))


# ---------------------------------------------------------------
# 3. Using variables
# ---------------------------------------------------------------

print("\n--- Using variables ---")

# Arithmetic with numbers
age_next_year = age + 1
print("Next year I will be", age_next_year)

# Joining strings (concatenation)
greeting = "Hello, " + name + "!"
print(greeting)

# f-strings: the easiest way to put variables inside text
print(f"{name} is {age} years old and lives in {city}.")

# Accessing items in collections
print(f"First hobby: {hobbies[0]}")
print(f"Latitude: {coordinates[0]}")
print(f"Name from dictionary: {person['name']}")


# ---------------------------------------------------------------
# 4. Reassigning variables
# ---------------------------------------------------------------

print("\n--- Reassigning ---")

score = 10
print("Score:", score)

score = score + 5   # use the old value to make a new one
print("Score after adding 5:", score)

score += 5          # shorthand for score = score + 5
print("Score after += 5:", score)

# A variable can even be given a value of a different type
score = "ten"
print("Score is now a string:", score, type(score))


# ---------------------------------------------------------------
# 5. Assigning multiple variables at once
# ---------------------------------------------------------------

print("\n--- Multiple assignment ---")

x, y, z = 1, 2, 3
print(x, y, z)

a = b = c = 0       # same value to several names
print(a, b, c)

# Swapping two variables without a temporary variable
x, y = y, x
print("After swap: x =", x, "y =", y)


# ---------------------------------------------------------------
# 6. Constants
# ---------------------------------------------------------------

# Python has no true constants. By convention, names in ALL_CAPS
# tell other programmers "don't change this value".
PI = 3.14159
MAX_USERS = 100

radius = 2
area = PI * radius ** 2
print("\n--- Constants ---")
print(f"Area of circle with radius {radius}: {area}")


# ---------------------------------------------------------------
# 7. Converting between types (type casting)
# ---------------------------------------------------------------

print("\n--- Type conversion ---")

number_text = "42"
number = int(number_text)        # string -> int
print(number + 8)

price = float("19.99")           # string -> float
print(price)

age_text = str(age)              # int -> string
print("Age as text: " + age_text)

print(int(7.8))                  # float -> int (drops the decimal part: 7)
print(bool(0), bool(1))          # 0 is False, other numbers are True


# ---------------------------------------------------------------
# 8. Naming rules and good practice
# ---------------------------------------------------------------
#
# Allowed:
#   - letters, digits and underscores:  user_name, total2
#   - must start with a letter or underscore:  _hidden, count
#   - case-sensitive: Name and name are different variables
#
# Not allowed:
#   - starting with a digit:   2nd_place = 1    -> SyntaxError
#   - spaces or dashes:        my name, my-name -> SyntaxError
#   - Python keywords:         class, if, for   -> SyntaxError
#
# Style (PEP 8): use snake_case for variable names, e.g. total_price

first_name = "Rahul"
First_Name = "Different variable!"
print("\n--- Case sensitivity ---")
print(first_name)
print(First_Name)
