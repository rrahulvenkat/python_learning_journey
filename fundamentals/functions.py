# Functions
#
# A function is a named, reusable block of code that performs a task.
# You define it once and call (run) it as many times as you need.
#
# Why use functions?
#   - Reuse: write code once, use it many times
#   - Organisation: break a big problem into small, named pieces
#   - Readability: calculate_tax(salary) says what it does
#   - Testing: small functions are easy to check on their own
#
# Topics covered here:
#   PART A: Basics
#     1. Defining and calling a function
#     2. Parameters vs arguments
#     3. Return values (and returning several values)
#     4. Docstrings and type hints
#   PART B: Ways of passing arguments (methods of calling)
#     5. Positional arguments
#     6. Keyword arguments
#     7. Default parameter values
#     8. *args (any number of positional arguments)
#     9. **kwargs (any number of keyword arguments)
#    10. Keyword-only and positional-only parameters
#    11. Unpacking a list/dict into arguments when calling
#   PART C: Types of functions
#    12. Built-in functions
#    13. User-defined functions
#    14. Lambda (anonymous) functions
#    15. Recursive functions
#    16. Higher-order functions (functions that take/return functions)
#    17. Nested functions and closures
#    18. Generator functions (yield)
#    19. Decorators
#    20. Methods (functions that belong to an object)
#   PART D: Scope
#    21. Local, global and nonlocal variables


# ===============================================================
# PART A: BASICS
# ===============================================================

# ---------------------------------------------------------------
# 1. Defining and calling a function
# ---------------------------------------------------------------
#
# Syntax:
#   def function_name(parameters):
#       body (indented)
#
# Defining a function does NOT run it. Calling it does.

print("--- 1. Define and call ---")


def say_hello():
    print("Hello! Welcome to Python functions.")


say_hello()     # call the function
say_hello()     # call it again; the same code runs again


# ---------------------------------------------------------------
# 2. Parameters vs arguments
# ---------------------------------------------------------------
#
# Parameter: the variable name in the function definition (name).
# Argument:  the actual value you pass when calling ("Rahul").

print("\n--- 2. Parameters and arguments ---")


def greet(name):                # name is a parameter
    print(f"Hello, {name}!")


greet("Rahul")                  # "Rahul" is an argument
greet("Asha")


def add(a, b):                  # two parameters
    print(f"{a} + {b} = {a + b}")


add(3, 4)


# ---------------------------------------------------------------
# 3. Return values
# ---------------------------------------------------------------
#
# print() only SHOWS a value. return SENDS a value back to the caller
# so it can be stored or used in more calculations.
# A function with no return statement returns None.

print("\n--- 3. Return values ---")


def square(n):
    return n * n


result = square(5)
print("square(5) =", result)
print("square(3) + square(4) =", square(3) + square(4))


def no_return():
    x = 10      # does something, but returns nothing


print("no_return() gives:", no_return())     # None

# return also ends the function immediately


def check_age(age):
    if age < 0:
        return "Invalid age"
    if age < 18:
        return "Minor"
    return "Adult"


print(check_age(-1), check_age(12), check_age(30))

# Returning several values (Python packs them into a tuple)


def min_max_avg(numbers):
    return min(numbers), max(numbers), sum(numbers) / len(numbers)


low, high, average = min_max_avg([4, 8, 15, 16, 23, 42])
print(f"Min: {low}, Max: {high}, Average: {average}")


# ---------------------------------------------------------------
# 4. Docstrings and type hints
# ---------------------------------------------------------------
#
# Docstring: a string right under "def" that explains the function.
# Type hints: show what types are expected (Python does NOT enforce them).

print("\n--- 4. Docstrings and type hints ---")


def calculate_area(length: float, width: float) -> float:
    """Return the area of a rectangle.

    length: the length of the rectangle
    width:  the width of the rectangle
    """
    return length * width


print("Area:", calculate_area(5, 3))
print("Docstring:", calculate_area.__doc__.splitlines()[0])
# help(calculate_area)   # uncomment to see the full help text


# ===============================================================
# PART B: WAYS OF PASSING ARGUMENTS (METHODS OF CALLING)
# ===============================================================

# ---------------------------------------------------------------
# 5. Positional arguments: matched by ORDER
# ---------------------------------------------------------------

print("\n--- 5. Positional arguments ---")


def describe_pet(animal, name):
    print(f"I have a {animal} named {name}.")


describe_pet("dog", "Bruno")
describe_pet("Bruno", "dog")    # wrong order gives a wrong result!


# ---------------------------------------------------------------
# 6. Keyword arguments: matched by NAME, so order doesn't matter
# ---------------------------------------------------------------

print("\n--- 6. Keyword arguments ---")

describe_pet(animal="cat", name="Misty")
describe_pet(name="Misty", animal="cat")     # same result

# You can mix them, but positional arguments must come FIRST
describe_pet("parrot", name="Mithu")
# describe_pet(animal="parrot", "Mithu")     # SyntaxError


# ---------------------------------------------------------------
# 7. Default parameter values: used when no argument is given
# ---------------------------------------------------------------

print("\n--- 7. Default values ---")


def make_coffee(size="medium", sugar=1):
    print(f"Making a {size} coffee with {sugar} sugar(s).")


make_coffee()                       # uses both defaults
make_coffee("large")                # overrides size
make_coffee(sugar=0)                # overrides only sugar
make_coffee("small", 2)             # overrides both

# Parameters with defaults must come AFTER those without:
#   def f(a, b=2): ...   OK
#   def f(a=1, b): ...   SyntaxError

# WARNING: never use a mutable default like [] or {}.
# The same list is shared between every call.


def add_item_bad(item, basket=[]):
    basket.append(item)
    return basket


print(add_item_bad("apple"))
print(add_item_bad("banana"))     # surprise: apple is still there!

# The fix: use None and create a new list inside


def add_item_good(item, basket=None):
    if basket is None:
        basket = []
    basket.append(item)
    return basket


print(add_item_good("apple"))
print(add_item_good("banana"))    # a fresh list each time


# ---------------------------------------------------------------
# 8. *args: accept any number of positional arguments
# ---------------------------------------------------------------
#
# The * collects all extra positional arguments into a TUPLE.
# "args" is just a convention; *numbers works the same way.

print("\n--- 8. *args ---")


def total(*numbers):
    print("numbers is a", type(numbers).__name__, "->", numbers)
    return sum(numbers)


print("Total:", total(1, 2))
print("Total:", total(5, 10, 15, 20))
print("Total:", total())


def introduce(greeting, *names):      # normal parameter first, then *args
    for name in names:
        print(f"{greeting}, {name}!")


introduce("Good morning", "Asha", "Ben", "Chen")


# ---------------------------------------------------------------
# 9. **kwargs: accept any number of keyword arguments
# ---------------------------------------------------------------
#
# The ** collects extra keyword arguments into a DICTIONARY.

print("\n--- 9. **kwargs ---")


def build_profile(name, **details):
    print(f"Profile for {name}:")
    for key, value in details.items():
        print(f"  {key}: {value}")


build_profile("Rahul", age=25, city="Chennai", language="Python")

# Order when using everything together:
#   def f(normal, default=1, *args, **kwargs)


def show_all(a, b=2, *args, **kwargs):
    print(f"a={a}, b={b}, args={args}, kwargs={kwargs}")


show_all(1)
show_all(1, 5, 6, 7, x=8, y=9)


# ---------------------------------------------------------------
# 10. Keyword-only and positional-only parameters
# ---------------------------------------------------------------
#
# After a bare *  -> parameters MUST be passed by keyword.
# Before a /      -> parameters MUST be passed by position.

print("\n--- 10. Keyword-only and positional-only ---")


def book_ticket(movie, *, seats, vip=False):
    print(f"Booked {seats} seat(s) for {movie}. VIP: {vip}")


book_ticket("Inception", seats=2)
book_ticket("Inception", seats=4, vip=True)
# book_ticket("Inception", 2)          # TypeError: seats must be a keyword


def power(base, exponent, /):
    return base ** exponent


print("power(2, 5) =", power(2, 5))
# power(base=2, exponent=5)            # TypeError: must be positional


# ---------------------------------------------------------------
# 11. Unpacking arguments when calling
# ---------------------------------------------------------------
#
# *list   spreads a list/tuple into positional arguments
# **dict  spreads a dictionary into keyword arguments

print("\n--- 11. Unpacking when calling ---")


def full_name(first, middle, last):
    return f"{first} {middle} {last}"


parts = ["Rahul", "K", "Venkat"]
print(full_name(*parts))           # same as full_name("Rahul", "K", "Venkat")

info = {"first": "Asha", "middle": "M", "last": "Rao"}
print(full_name(**info))           # same as full_name(first="Asha", ...)

numbers = [3, 9, 1]
print("max(*numbers) =", max(*numbers))


# ===============================================================
# PART C: TYPES OF FUNCTIONS
# ===============================================================

# ---------------------------------------------------------------
# 12. Built-in functions: ready to use, no def needed
# ---------------------------------------------------------------

print("\n--- 12. Built-in functions ---")

values = [5, 2, 9, 1]
print("len:", len(values))
print("sum:", sum(values))
print("min / max:", min(values), max(values))
print("sorted:", sorted(values))
print("abs(-7):", abs(-7))
print("round(3.567, 1):", round(3.567, 1))
print("type(3.0):", type(3.0))
print("int('42') + 1:", int("42") + 1)
# Others you already used: print(), input(), range(), enumerate(), zip()


# ---------------------------------------------------------------
# 13. User-defined functions: the ones you write with def
# ---------------------------------------------------------------
#
# Every function written with def in this file is user-defined.
# Here is a slightly bigger one that calls other functions.

print("\n--- 13. User-defined functions ---")


def celsius_to_fahrenheit(c):
    return c * 9 / 5 + 32


def weather_report(city, celsius):
    fahrenheit = celsius_to_fahrenheit(celsius)    # a function calling a function
    return f"{city}: {celsius}°C / {fahrenheit:.1f}°F"


print(weather_report("Chennai", 34))
print(weather_report("London", 12))


# ---------------------------------------------------------------
# 14. Lambda functions: small one-line functions without a name
# ---------------------------------------------------------------
#
# Syntax: lambda parameters: expression
# The expression's result is returned automatically.
# Best used for short, throwaway functions (often as arguments).

print("\n--- 14. Lambda functions ---")

double = lambda x: x * 2          # same as: def double(x): return x * 2
multiply = lambda a, b: a * b

print("double(6) =", double(6))
print("multiply(3, 4) =", multiply(3, 4))

# Most common use: as a "key" for sorting
students = [("Asha", 88), ("Ben", 72), ("Chen", 95)]
by_score = sorted(students, key=lambda s: s[1])
print("Sorted by score:", by_score)

words = ["banana", "kiwi", "apple", "fig"]
print("Sorted by length:", sorted(words, key=lambda w: len(w)))


# ---------------------------------------------------------------
# 15. Recursive functions: a function that calls itself
# ---------------------------------------------------------------
#
# Every recursive function needs:
#   - a BASE CASE that stops the recursion
#   - a RECURSIVE CASE that moves towards the base case

print("\n--- 15. Recursive functions ---")


def factorial(n):
    if n <= 1:                  # base case
        return 1
    return n * factorial(n - 1)  # recursive case


print("factorial(5) =", factorial(5))   # 5 * 4 * 3 * 2 * 1 = 120


def countdown(n):
    if n == 0:
        print("Go!")
        return
    print(n, end=" ")
    countdown(n - 1)


countdown(5)


def fibonacci(n):
    if n < 2:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)


print("First 10 Fibonacci numbers:", [fibonacci(i) for i in range(10)])


# ---------------------------------------------------------------
# 16. Higher-order functions
# ---------------------------------------------------------------
#
# In Python, functions are objects: you can store them in variables,
# pass them to other functions, and return them from functions.
# A higher-order function takes or returns another function.

print("\n--- 16. Higher-order functions ---")


def shout(text):
    return text.upper() + "!"


def whisper(text):
    return text.lower() + "..."


def speak(style, message):          # style is a function
    return style(message)


print(speak(shout, "Hello"))
print(speak(whisper, "Hello"))

# Built-in higher-order functions: map, filter, sorted
nums = [1, 2, 3, 4, 5, 6]
print("map (square):", list(map(lambda n: n ** 2, nums)))
print("filter (even):", list(filter(lambda n: n % 2 == 0, nums)))

# Storing functions in a dictionary
operations = {
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
    "*": lambda a, b: a * b,
}
for symbol, operation in operations.items():
    print(f"10 {symbol} 3 = {operation(10, 3)}")


# ---------------------------------------------------------------
# 17. Nested functions and closures
# ---------------------------------------------------------------
#
# Nested function: a function defined inside another function.
# Closure: an inner function that REMEMBERS variables from the outer
# function, even after the outer function has finished.

print("\n--- 17. Nested functions and closures ---")


def outer():
    message = "I'm from the outer function"

    def inner():
        print(message)          # inner can see outer's variables

    inner()


outer()


def make_multiplier(factor):
    def multiply_by(n):
        return n * factor       # remembers "factor"
    return multiply_by          # return the function itself (no brackets)


times3 = make_multiplier(3)
times10 = make_multiplier(10)
print("times3(5) =", times3(5))
print("times10(5) =", times10(5))


# ---------------------------------------------------------------
# 18. Generator functions: use yield to produce values one at a time
# ---------------------------------------------------------------
#
# return ends the function. yield PAUSES it and hands back a value;
# the next time you ask, it continues from where it paused.
# Generators save memory because they don't build the whole list.

print("\n--- 18. Generator functions ---")


def count_up_to(limit):
    n = 1
    while n <= limit:
        yield n
        n += 1


for value in count_up_to(5):
    print(value, end=" ")
print()

gen = count_up_to(3)
print(next(gen))    # 1
print(next(gen))    # 2
print(next(gen))    # 3
# next(gen) again would raise StopIteration


# ---------------------------------------------------------------
# 19. Decorators: wrap a function to add extra behaviour
# ---------------------------------------------------------------
#
# A decorator is a function that takes a function and returns a new
# function that does something extra before/after the original.
# @decorator above a def is a shortcut for:  func = decorator(func)

print("\n--- 19. Decorators ---")


def announce(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__} with {args}")
        result = func(*args, **kwargs)
        print(f"{func.__name__} returned {result}")
        return result
    return wrapper


@announce
def subtract(a, b):
    return a - b


subtract(10, 4)


# ---------------------------------------------------------------
# 20. Methods: functions that belong to an object
# ---------------------------------------------------------------
#
# A method is a function attached to an object (or class).
# You call it with a dot:  object.method(arguments)
# Functions are called on their own: len(text)

print("\n--- 20. Methods ---")

text = "hello world"
print(len(text))              # function: text is passed as an argument
print(text.upper())           # method: called ON the text object
print(text.split())

shopping = ["milk"]
shopping.append("bread")      # list method
print(shopping)


class Dog:
    def __init__(self, name):       # special method, runs on creation
        self.name = name

    def bark(self):                 # instance method
        return f"{self.name} says Woof!"


my_dog = Dog("Bruno")
print(my_dog.bark())
# (Classes are a bigger topic; you'll cover them in OOP.)


# ===============================================================
# PART D: SCOPE
# ===============================================================

# ---------------------------------------------------------------
# 21. Local, global and nonlocal variables
# ---------------------------------------------------------------
#
# Local:    created inside a function, only exists inside it
# Global:   created outside all functions, visible everywhere
# nonlocal: lets an inner function change the outer function's variable

print("\n--- 21. Scope ---")

counter = 0                     # global variable


def show_local():
    local_var = "only inside the function"
    print("Inside:", local_var)
    print("Can read global counter:", counter)


show_local()
# print(local_var)              # NameError: not defined outside


def increment():
    global counter              # needed to CHANGE a global variable
    counter += 1


increment()
increment()
print("Counter after two calls:", counter)


def make_counter():
    count = 0

    def tick():
        nonlocal count          # change the outer function's variable
        count += 1
        return count

    return tick


tick = make_counter()
print("tick:", tick(), tick(), tick())

# Tip: avoid global when you can. Pass values in as arguments and
# return the result instead; it makes functions easier to understand.
