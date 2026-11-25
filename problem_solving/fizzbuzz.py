# FizzBuzz
#
# PROBLEM
# -------
# For each number from 1 to n:
#   - if it is divisible by 3 AND 5, output "FizzBuzz"
#   - if it is divisible by 3 only,  output "Fizz"
#   - if it is divisible by 5 only,  output "Buzz"
#   - otherwise, output the number itself
#
# Example (n = 15):
#   1, 2, Fizz, 4, Buzz, Fizz, 7, 8, Fizz, Buzz, 11, Fizz, 13, 14, FizzBuzz
#
# (LeetCode 412 asks for the same thing, returned as a list of strings.)
#
# KEY IDEAS
# ---------
#   - "divisible by 3" means  number % 3 == 0  (no remainder)
#   - Check the "both" case FIRST. If you check 3 first, 15 would print
#     "Fizz" and never reach the FizzBuzz branch.
#   - Divisible by 3 and 5 is the same as divisible by 15.
#
# Below are several solutions, from the most common to the most
# flexible, followed by tests that check they all agree.


# ---------------------------------------------------------------
# Solution 1: if / elif / else (the classic interview answer)
# ---------------------------------------------------------------

def fizzbuzz_classic(n):
    result = []
    for i in range(1, n + 1):
        if i % 15 == 0:             # must come first
            result.append("FizzBuzz")
        elif i % 3 == 0:
            result.append("Fizz")
        elif i % 5 == 0:
            result.append("Buzz")
        else:
            result.append(str(i))
    return result


# ---------------------------------------------------------------
# Solution 2: build the string piece by piece
# ---------------------------------------------------------------
#
# No separate "both" check is needed: a number divisible by 3 and 5
# gets "Fizz" + "Buzz" = "FizzBuzz" automatically.
# If the string is still empty, use the number instead.

def fizzbuzz_concat(n):
    result = []
    for i in range(1, n + 1):
        output = ""
        if i % 3 == 0:
            output += "Fizz"
        if i % 5 == 0:
            output += "Buzz"
        result.append(output or str(i))   # "" is falsy, so str(i) is used
    return result


# ---------------------------------------------------------------
# Solution 3: rules in a dictionary (easy to extend)
# ---------------------------------------------------------------
#
# Want "Jazz" for multiples of 7? Add one entry to the dictionary;
# no new if statements needed. Interviewers like this follow-up.

def fizzbuzz_rules(n, rules=None):
    if rules is None:
        rules = {3: "Fizz", 5: "Buzz"}
    result = []
    for i in range(1, n + 1):
        output = "".join(word for divisor, word in rules.items() if i % divisor == 0)
        result.append(output or str(i))
    return result


# ---------------------------------------------------------------
# Solution 4: one-line list comprehension
# ---------------------------------------------------------------
#
# Short, but harder to read. Good to understand, not always good to
# write in an interview.

def fizzbuzz_oneliner(n):
    return ["Fizz" * (i % 3 == 0) + "Buzz" * (i % 5 == 0) or str(i) for i in range(1, n + 1)]

# How it works: True acts like 1 and False like 0, so
#   "Fizz" * True  -> "Fizz"
#   "Fizz" * False -> ""


# ---------------------------------------------------------------
# Solution 5: generator (yields one answer at a time)
# ---------------------------------------------------------------
#
# Uses almost no memory, even for n = 1,000,000,000.

def fizzbuzz_generator(n):
    for i in range(1, n + 1):
        if i % 15 == 0:
            yield "FizzBuzz"
        elif i % 3 == 0:
            yield "Fizz"
        elif i % 5 == 0:
            yield "Buzz"
        else:
            yield str(i)


# ---------------------------------------------------------------
# COMPLEXITY
# ---------------------------------------------------------------
#
#   Solutions 1-4: Time O(n), Space O(n) for the result list
#   Solution 5:    Time O(n), Space O(1) (one value at a time)
#   Solution 3:    Time O(n * k) where k is the number of rules


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    expected_15 = [
        "1", "2", "Fizz", "4", "Buzz", "Fizz", "7", "8",
        "Fizz", "Buzz", "11", "Fizz", "13", "14", "FizzBuzz",
    ]

    solutions = [
        fizzbuzz_classic,
        fizzbuzz_concat,
        fizzbuzz_rules,
        fizzbuzz_oneliner,
        lambda n: list(fizzbuzz_generator(n)),
    ]

    for solve in solutions:
        assert solve(15) == expected_15, f"{solve.__name__} failed for n=15"
        assert solve(0) == [], f"{solve.__name__} failed for n=0"
        assert solve(1) == ["1"], f"{solve.__name__} failed for n=1"
        assert solve(100) == fizzbuzz_classic(100), f"{solve.__name__} failed for n=100"

    # Extended rules: 7 -> "Jazz"
    custom = fizzbuzz_rules(21, {3: "Fizz", 5: "Buzz", 7: "Jazz"})
    assert custom[6] == "Jazz"          # 7
    assert custom[14] == "FizzBuzz"     # 15
    assert custom[20] == "FizzJazz"     # 21

    print("All tests passed!")


if __name__ == "__main__":
    print("Classic FizzBuzz (1-15):")
    for line in fizzbuzz_classic(15):
        print(line)

    print("\nWith an extra rule, 7 -> Jazz (1-21):")
    print(", ".join(fizzbuzz_rules(21, {3: "Fizz", 5: "Buzz", 7: "Jazz"})))

    print()
    run_tests()
