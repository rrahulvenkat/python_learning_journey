# my_helpers.py
#
# A small module of your own, used by modules_and_imports.py.
# Any .py file is a module: other files can import what's inside it.

PI = 3.14159
GREETING = "Hello from my_helpers!"


def circle_area(radius):
    """Return the area of a circle."""
    return PI * radius ** 2


def is_even(number):
    """Return True if the number is even."""
    return number % 2 == 0


def shout(text):
    """Return the text in uppercase with an exclamation mark."""
    return text.upper() + "!"


# This block runs ONLY when you run this file directly:
#   python3 fundamentals/my_helpers.py
# It does NOT run when another file imports this module.
if __name__ == "__main__":
    print("my_helpers.py was run directly.")
    print("circle_area(2) =", circle_area(2))
