# Operators
#
# Operators are symbols that perform an action on values (operands).
# Example: in "3 + 4", "+" is the operator and 3 and 4 are operands.
#
# Types of operators covered here:
#   1. Arithmetic      + - * / // % **
#   2. Assignment      = += -= *= /= //= %= **=
#   3. Comparison      == != > < >= <=
#   4. Logical         and or not
#   5. Identity        is, is not
#   6. Membership      in, not in
#   7. Bitwise         & | ^ ~ << >>
#   8. Operator precedence (which runs first)


# ---------------------------------------------------------------
# 1. Arithmetic operators
# ---------------------------------------------------------------

print("--- Arithmetic ---")

a = 17
b = 5

print(f"{a} + {b}  = {a + b}")     # addition
print(f"{a} - {b}  = {a - b}")     # subtraction
print(f"{a} * {b}  = {a * b}")     # multiplication
print(f"{a} / {b}  = {a / b}")     # division (always a float)
print(f"{a} // {b} = {a // b}")    # floor division (rounds down)
print(f"{a} % {b}  = {a % b}")     # modulus (remainder)
print(f"{a} ** {b} = {a ** b}")    # exponent (power)

# Floor division rounds DOWN, even for negative numbers
print("-17 // 5 =", -17 // 5)      # -4, not -3

# Modulus is handy for checking even/odd
number = 8
print(f"{number} is even:", number % 2 == 0)

# Some operators also work on strings and lists
print("Hi " + "there")             # + joins strings
print("ha" * 3)                    # * repeats a string
print([1, 2] + [3, 4])             # + joins lists
print([0] * 5)                     # * repeats a list


# ---------------------------------------------------------------
# 2. Assignment operators
# ---------------------------------------------------------------

print("\n--- Assignment ---")

x = 10                 # assign
print("x = 10   ->", x)

x += 5                 # same as x = x + 5
print("x += 5   ->", x)

x -= 3                 # same as x = x - 3
print("x -= 3   ->", x)

x *= 2                 # same as x = x * 2
print("x *= 2   ->", x)

x /= 4                 # same as x = x / 4 (x becomes a float)
print("x /= 4   ->", x)

x //= 2                # same as x = x // 2
print("x //= 2  ->", x)

x = 10
x %= 3                 # same as x = x % 3
print("x %= 3   ->", x)

x = 3
x **= 4                # same as x = x ** 4
print("x = 3, x **= 4 ->", x)


# ---------------------------------------------------------------
# 3. Comparison operators (result is always True or False)
# ---------------------------------------------------------------

print("\n--- Comparison ---")

p = 10
q = 20

print(f"{p} == {q}:", p == q)      # equal to
print(f"{p} != {q}:", p != q)      # not equal to
print(f"{p} > {q}: ", p > q)       # greater than
print(f"{p} < {q}: ", p < q)       # less than
print(f"{p} >= 10:", p >= 10)      # greater than or equal to
print(f"{p} <= 5: ", p <= 5)       # less than or equal to

# Chained comparison: checks both conditions at once
age = 25
print("18 <= age < 60:", 18 <= age < 60)

# Strings are compared alphabetically (by character code)
print('"apple" < "banana":', "apple" < "banana")
print('"Zebra" < "apple": ', "Zebra" < "apple")   # uppercase comes first


# ---------------------------------------------------------------
# 4. Logical operators
# ---------------------------------------------------------------

print("\n--- Logical ---")

is_member = True
has_coupon = False

print("and:", is_member and has_coupon)   # True only if BOTH are True
print("or: ", is_member or has_coupon)    # True if AT LEAST ONE is True
print("not:", not is_member)              # flips True <-> False

# Real-world example
temperature = 28
is_sunny = True
go_to_beach = temperature > 25 and is_sunny
print("Go to the beach?", go_to_beach)

# Short-circuiting: Python stops as soon as it knows the answer.
# "and" returns the first falsy value (or the last value).
# "or" returns the first truthy value (or the last value).
print(0 and 5)            # 0
print(3 and 5)            # 5
print("" or "default")    # default
print("name" or "default")  # name


# ---------------------------------------------------------------
# 5. Identity operators: is, is not
# ---------------------------------------------------------------

print("\n--- Identity ---")

# "==" checks if values are equal.
# "is" checks if both names point to the SAME object in memory.

list1 = [1, 2, 3]
list2 = [1, 2, 3]
list3 = list1

print("list1 == list2:", list1 == list2)   # True, same values
print("list1 is list2:", list1 is list2)   # False, different objects
print("list1 is list3:", list1 is list3)   # True, same object

list3.append(4)                 # changing list3 also changes list1
print("list1 after list3.append(4):", list1)

# Use "is" for None checks
value = None
print("value is None:", value is None)
print("value is not None:", value is not None)


# ---------------------------------------------------------------
# 6. Membership operators: in, not in
# ---------------------------------------------------------------

print("\n--- Membership ---")

fruits = ["apple", "banana", "cherry"]
print('"apple" in fruits:', "apple" in fruits)
print('"mango" not in fruits:', "mango" not in fruits)

sentence = "Python is fun"
print('"fun" in sentence:', "fun" in sentence)

person = {"name": "Rahul", "age": 25}
print('"name" in person:', "name" in person)      # checks keys
print('"Rahul" in person:', "Rahul" in person)    # False, not a key
print('"Rahul" in person.values():', "Rahul" in person.values())


# ---------------------------------------------------------------
# 7. Bitwise operators (work on the binary form of integers)
# ---------------------------------------------------------------

print("\n--- Bitwise ---")

m = 6     # binary 0110
n = 3     # binary 0011

print(f"m = {m} ({m:04b}), n = {n} ({n:04b})")
print(f"m & n  = {m & n} ({m & n:04b})")    # AND: 1 where both bits are 1
print(f"m | n  = {m | n} ({m | n:04b})")    # OR: 1 where either bit is 1
print(f"m ^ n  = {m ^ n} ({m ^ n:04b})")    # XOR: 1 where bits differ
print(f"~m     = {~m}")                     # NOT: flips bits, gives -(m+1)
print(f"m << 1 = {m << 1}")                 # shift left: multiply by 2
print(f"m >> 1 = {m >> 1}")                 # shift right: divide by 2


# ---------------------------------------------------------------
# 8. Operator precedence (highest to lowest)
# ---------------------------------------------------------------
#
#   ()                          parentheses
#   **                          exponent
#   +x, -x, ~x                  unary plus, minus, bitwise NOT
#   *, /, //, %                 multiply, divide, floor divide, modulus
#   +, -                        add, subtract
#   <<, >>                      bit shifts
#   &                           bitwise AND
#   ^                           bitwise XOR
#   |                           bitwise OR
#   ==, !=, >, <, >=, <=, is, in    comparisons, identity, membership
#   not                         logical NOT
#   and                         logical AND
#   or                          logical OR

print("\n--- Precedence ---")

print("2 + 3 * 4   =", 2 + 3 * 4)       # 14, * runs before +
print("(2 + 3) * 4 =", (2 + 3) * 4)     # 20, parentheses run first
print("2 ** 3 ** 2 =", 2 ** 3 ** 2)     # 512, ** runs right to left: 2 ** 9
print("-2 ** 2     =", -2 ** 2)         # -4, ** runs before the minus
print("(-2) ** 2   =", (-2) ** 2)       # 4

# When in doubt, add parentheses to make your intent clear
result = (10 + 5) * 2 - 8 / 4
print("(10 + 5) * 2 - 8 / 4 =", result)
