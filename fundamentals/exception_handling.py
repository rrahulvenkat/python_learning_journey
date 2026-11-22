# Exception Handling
#
# An exception is an error that happens while the program is running
# (for example, dividing by zero or opening a file that doesn't exist).
# If you don't handle it, the program crashes and prints a traceback.
# Exception handling lets you catch the error and decide what to do.
#
# Topics covered here:
#   1. What an unhandled exception looks like
#   2. try / except
#   3. Catching specific exceptions
#   4. Catching several exceptions
#   5. Getting the error message with "as"
#   6. else: runs when NO error happened
#   7. finally: ALWAYS runs
#   8. Raising your own exceptions with raise
#   9. Re-raising an exception
#  10. Custom exception classes
#  11. Common built-in exceptions
#  12. Practical example: safe input validation
#  13. Good practices


# ---------------------------------------------------------------
# 1. What an unhandled exception looks like
# ---------------------------------------------------------------
#
# If you uncomment the line below, Python stops and prints:
#
#   Traceback (most recent call last):
#     File "exception_handling.py", line ..., in <module>
#       print(10 / 0)
#   ZeroDivisionError: division by zero
#
# The LAST line is the most useful: the exception type and message.

# print(10 / 0)


# ---------------------------------------------------------------
# 2. try / except
# ---------------------------------------------------------------
#
# Put code that might fail inside "try".
# If an error happens, Python jumps to "except" instead of crashing.

print("--- 2. try / except ---")

try:
    result = 10 / 0
    print("This line is skipped because the line above failed.")
except ZeroDivisionError:
    print("You can't divide by zero!")

print("The program keeps running after the error was handled.")


# ---------------------------------------------------------------
# 3. Catching specific exceptions
# ---------------------------------------------------------------
#
# Always name the exception you expect. A bare "except:" catches
# EVERYTHING, which hides bugs you didn't know about.

print("\n--- 3. Specific exceptions ---")

try:
    number = int("hello")
except ValueError:
    print("'hello' is not a valid number.")

try:
    fruits = ["apple", "banana"]
    print(fruits[5])
except IndexError:
    print("That list position doesn't exist.")

try:
    person = {"name": "Rahul"}
    print(person["age"])
except KeyError:
    print("The key 'age' is not in the dictionary.")


# ---------------------------------------------------------------
# 4. Catching several exceptions
# ---------------------------------------------------------------

print("\n--- 4. Several exceptions ---")


def divide(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return "Error: division by zero"
    except TypeError:
        return "Error: both values must be numbers"


print(divide(10, 2))
print(divide(10, 0))
print(divide(10, "2"))

# Handle several exception types the same way with a tuple
for value in ["42", "abc", None]:
    try:
        print(int(value) * 2)
    except (ValueError, TypeError):
        print(f"Could not convert {value!r} to an int")


# ---------------------------------------------------------------
# 5. Getting the error message with "as"
# ---------------------------------------------------------------

print("\n--- 5. Using 'as' ---")

try:
    int("12.5")
except ValueError as error:
    print("Error type:   ", type(error).__name__)
    print("Error message:", error)


# ---------------------------------------------------------------
# 6. else: runs only if the try block had NO error
# ---------------------------------------------------------------
#
# Keep "try" small (only the risky line) and put the follow-up
# code in "else".

print("\n--- 6. else ---")

for text in ["25", "twenty"]:
    try:
        age = int(text)
    except ValueError:
        print(f"'{text}' is not a number.")
    else:
        print(f"Valid age: {age}. Next year you'll be {age + 1}.")


# ---------------------------------------------------------------
# 7. finally: ALWAYS runs, error or not
# ---------------------------------------------------------------
#
# Used for clean-up: closing files, network connections, etc.

print("\n--- 7. finally ---")


def process(value):
    try:
        print(f"Processing {value}...")
        result = 100 / value
        print("Result:", result)
    except ZeroDivisionError:
        print("Cannot divide by zero.")
    finally:
        print("Clean-up done.\n")


process(4)
process(0)

# The full structure:
#
#   try:
#       risky code
#   except SomeError:
#       runs if SomeError happened
#   else:
#       runs if NO error happened
#   finally:
#       always runs


# ---------------------------------------------------------------
# 8. Raising your own exceptions with raise
# ---------------------------------------------------------------
#
# Use raise when your function gets a value it can't work with.

print("--- 8. raise ---")


def set_age(age):
    if not isinstance(age, int):
        raise TypeError("Age must be a whole number")
    if age < 0 or age > 150:
        raise ValueError(f"Age {age} is out of range (0-150)")
    return age


for test in [25, -5, "ten"]:
    try:
        print("Age set to", set_age(test))
    except (ValueError, TypeError) as error:
        print(f"Rejected {test!r}: {error}")


# ---------------------------------------------------------------
# 9. Re-raising an exception
# ---------------------------------------------------------------
#
# Sometimes you want to log the error and still let it continue up
# to the caller. A plain "raise" inside except does that.

print("\n--- 9. Re-raising ---")


def load_setting(settings, key):
    try:
        return settings[key]
    except KeyError:
        print(f"[log] Missing setting: {key}")
        raise           # pass the same error on to the caller


try:
    load_setting({"theme": "dark"}, "language")
except KeyError as error:
    print("Caller caught it too:", error)


# ---------------------------------------------------------------
# 10. Custom exception classes
# ---------------------------------------------------------------
#
# Create your own exception by inheriting from Exception.
# This makes errors in your program clear and specific.

print("\n--- 10. Custom exceptions ---")


class InsufficientFundsError(Exception):
    """Raised when a withdrawal is bigger than the balance."""


def withdraw(balance, amount):
    if amount > balance:
        raise InsufficientFundsError(
            f"Tried to withdraw {amount}, but balance is only {balance}"
        )
    return balance - amount


try:
    print("New balance:", withdraw(500, 200))
    print("New balance:", withdraw(500, 800))
except InsufficientFundsError as error:
    print("Transaction failed:", error)


# ---------------------------------------------------------------
# 11. Common built-in exceptions
# ---------------------------------------------------------------
#
#   Exception            | Example that causes it
#   ---------------------|---------------------------------------
#   ZeroDivisionError    | 10 / 0
#   ValueError           | int("abc")
#   TypeError            | "5" + 5
#   IndexError           | [1, 2][10]
#   KeyError             | {"a": 1}["b"]
#   NameError            | print(undefined_variable)
#   AttributeError       | "text".push("x")
#   FileNotFoundError    | open("missing.txt")
#   ImportError          | import not_a_real_module
#   PermissionError      | opening a file you aren't allowed to read

print("\n--- 11. Common exceptions ---")

risky_actions = [
    lambda: 10 / 0,
    lambda: int("abc"),
    lambda: "5" + 5,
    lambda: [1, 2][10],
    lambda: {"a": 1}["b"],
    lambda: "text".push("x"),
    lambda: open("this_file_does_not_exist.txt"),
]

for action in risky_actions:
    try:
        action()
    except Exception as error:      # catching everything is OK for a demo
        print(f"{type(error).__name__:<18} -> {error}")


# ---------------------------------------------------------------
# 12. Practical example: validating input
# ---------------------------------------------------------------
#
# In a real program, the values would come from input(). Here a list
# of sample "user inputs" is used so the file runs without typing.

print("\n--- 12. Practical example ---")


def parse_port(text):
    """Convert text to a network port number (1-65535)."""
    try:
        port = int(text)
    except ValueError:
        return None, f"'{text}' is not a number"

    if not 1 <= port <= 65535:
        return None, f"{port} is outside the valid port range"

    return port, "OK"


for user_input in ["443", "abc", "70000", "22"]:
    port, message = parse_port(user_input)
    print(f"Input {user_input!r:8} -> port={port}, {message}")

# Keep asking until the user types something valid (interactive version):
#
#   while True:
#       try:
#           number = int(input("Enter a number: "))
#           break
#       except ValueError:
#           print("That's not a number, try again.")


# ---------------------------------------------------------------
# 13. Good practices
# ---------------------------------------------------------------
#
#   - Catch SPECIFIC exceptions, not a bare "except:".
#   - Keep the try block small; put only the risky line inside it.
#   - Don't silently ignore errors (except: pass). At least print
#     or log what went wrong.
#   - Use finally (or "with", see file_handling.py) for clean-up.
#   - Raise exceptions with clear messages that explain the problem.
