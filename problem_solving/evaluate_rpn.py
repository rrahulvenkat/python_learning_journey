# Evaluate Reverse Polish Notation (LeetCode 150)
#
# PROBLEM
# -------
# Reverse Polish Notation (RPN) writes the operator AFTER its two
# numbers, so it never needs brackets or precedence rules:
#
#   normal (infix)        RPN
#   2 + 3                 2 3 +
#   (2 + 1) * 3           2 1 + 3 *
#   4 + 13 / 5            4 13 5 / +
#
# Given a list of RPN tokens, return the result. Operators are
# + - * /, and division truncates TOWARD ZERO (like C or Java).
#
#   ["2", "1", "+", "3", "*"]   ->  9
#   ["4", "13", "5", "/", "+"]  ->  6     13 / 5 = 2, then 4 + 2
#
# KEY IDEAS
# ---------
#   - Number   -> push it.
#     Operator -> pop TWO numbers, apply the operator, push the result.
#   - ORDER MATTERS: the first pop is the RIGHT-hand number.
#       ["5", "2", "-"] means 5 - 2, but you pop 2 first, then 5.
#   - Python's // rounds DOWN, not toward zero:
#       -7 // 2 == -4, but the problem wants -3.
#     Use int(a / b) instead, which truncates toward zero.
#
# WHAT'S NEW HERE
# ---------------
# The previous stack files held brackets and text. Here the stack
# holds intermediate RESULTS, the way a calculator or a programming
# language's virtual machine does. Python itself compiles your code
# to stack instructions; variation 2 shows how normal expressions get
# turned into RPN (the shunting-yard algorithm), and ties back to the
# precedence rules in fundamentals/operators.py.
#
# SECURITY CONNECTION
# -------------------
# Never pass user input to eval(). eval("2 + 3") works, but so does
# eval("__import__('os').system('rm -rf ~')"), which runs any code
# the user types. When you need to evaluate an expression from
# outside, parse it yourself and allow only the operations you
# expect. That's what safe_calculate() at the end does.


import operator


# ---------------------------------------------------------------
# Solution 1: stack with if/elif
# ---------------------------------------------------------------
#
# Trace for ["4", "13", "5", "/", "+"]:
#
#   token | action                          | stack after
#   ------|---------------------------------|------------
#   4     | push                            | [4]
#   13    | push                            | [4, 13]
#   5     | push                            | [4, 13, 5]
#   /     | pop 5 (right), pop 13 (left)    |
#         | 13 / 5 = 2, push                | [4, 2]
#   +     | pop 2, pop 4 -> 4 + 2 = 6, push | [6]
#
# The answer is the one number left on the stack.

def eval_rpn(tokens):
    stack = []
    for token in tokens:
        if token in ("+", "-", "*", "/"):
            right = stack.pop()           # popped FIRST = right-hand side
            left = stack.pop()
            if token == "+":
                stack.append(left + right)
            elif token == "-":
                stack.append(left - right)
            elif token == "*":
                stack.append(left * right)
            else:
                stack.append(int(left / right))   # truncate toward zero
        else:
            stack.append(int(token))
    return stack[0]


# ---------------------------------------------------------------
# Solution 2: a dictionary of operator functions
# ---------------------------------------------------------------
#
# The operator module has the operators as functions:
#   operator.add(2, 3) == 2 + 3
# Putting them in a dictionary replaces the if/elif chain, and adding
# a new operator (like "%" or "^") is one new line. This is the same
# "rules in a dictionary" idea as fizzbuzz.py.
#
# This version also checks for bad input instead of crashing with a
# confusing IndexError.

def truncating_divide(a, b):
    return int(a / b)

OPERATORS = {
    "+": operator.add,
    "-": operator.sub,
    "*": operator.mul,
    "/": truncating_divide,
}

def eval_rpn_dict(tokens):
    stack = []
    for token in tokens:
        if token in OPERATORS:
            if len(stack) < 2:
                raise ValueError(f"operator {token!r} needs two numbers")
            right = stack.pop()
            left = stack.pop()
            stack.append(OPERATORS[token](left, right))
        else:
            stack.append(int(token))      # raises ValueError for junk like "x"

    if len(stack) != 1:
        raise ValueError(f"expected one result, got {len(stack)} numbers left")
    return stack[0]


# ---------------------------------------------------------------
# Variation 1: why // is the wrong division here
# ---------------------------------------------------------------
#
#   a  |  b | a // b (floor) | int(a / b) (toward zero)
#   ---|----|----------------|-------------------------
#    7 |  2 |       3        |       3
#   -7 |  2 |      -4        |      -3
#    7 | -2 |      -4        |      -3
#
# They only differ when the answer is negative. This kind of
# off-by-one difference between languages is a classic source of
# bugs, so it's worth checking which rule a problem wants.


# ---------------------------------------------------------------
# Variation 2: infix to RPN (the shunting-yard algorithm)
# ---------------------------------------------------------------
#
# Turn a normal expression into RPN using a stack of OPERATORS.
# It's a short version of how real parsers handle precedence.
#
#   number           -> straight to the output
#   operator op      -> while the top of the stack is an operator with
#                       higher or equal precedence, move it to the
#                       output; then push op
#   "("              -> push
#   ")"              -> move operators to the output until "(";
#                       throw the "(" away
#   end              -> move everything left on the stack to the output
#
# "Higher or EQUAL" makes - and / work left to right: 8 - 3 - 2 is
# (8 - 3) - 2.
#
# Trace for "(2 + 1) * 3":
#
#   token | output        | operator stack
#   ------|---------------|---------------
#   (     |               | (
#   2     | 2             | (
#   +     | 2             | ( +
#   1     | 2 1           | ( +
#   )     | 2 1 +         |          pop until "("
#   *     | 2 1 +         | *
#   3     | 2 1 + 3       | *
#   end   | 2 1 + 3 *     |

PRECEDENCE = {"+": 1, "-": 1, "*": 2, "/": 2}

def tokenize(expression):
    """Split "12+(3*4)" into ["12", "+", "(", "3", "*", "4", ")"]."""
    tokens = []
    number = ""
    for ch in expression:
        if ch.isdigit():
            number += ch
            continue
        if number:
            tokens.append(number)
            number = ""
        if ch in PRECEDENCE or ch in "()":
            tokens.append(ch)
        elif not ch.isspace():
            raise ValueError(f"unexpected character {ch!r}")
    if number:
        tokens.append(number)
    return tokens


def to_rpn(expression):
    output = []
    ops = []
    for token in tokenize(expression):
        if token.isdigit():
            output.append(token)
        elif token == "(":
            ops.append(token)
        elif token == ")":
            while ops and ops[-1] != "(":
                output.append(ops.pop())
            if not ops:
                raise ValueError("unmatched ')'")
            ops.pop()                                # throw away the "("
        else:
            while (ops and ops[-1] != "("
                   and PRECEDENCE[ops[-1]] >= PRECEDENCE[token]):
                output.append(ops.pop())
            ops.append(token)

    while ops:
        if ops[-1] == "(":
            raise ValueError("unmatched '('")
        output.append(ops.pop())
    return output


# ---------------------------------------------------------------
# Variation 3: a safe calculator (instead of eval)
# ---------------------------------------------------------------
#
# Put the two halves together. Anything that isn't a whole number, an
# operator, a bracket or a space is rejected before any calculating
# happens. Negative numbers like "-3" aren't supported, to keep this
# short; write "0 - 3".

def safe_calculate(expression):
    return eval_rpn_dict(to_rpn(expression))


# ---------------------------------------------------------------
# COMPLEXITY (n = number of tokens)
# ---------------------------------------------------------------
#
#   Solution                  | Time  | Extra space
#   --------------------------|-------|-------------
#   1. Stack with if/elif     | O(n)  | O(n)
#   2. Operator dictionary    | O(n)  | O(n)
#   Shunting-yard (to_rpn)    | O(n)  | O(n)
#
# Each token is pushed once and popped at most once.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (tokens, expected)
        (["2", "1", "+", "3", "*"], 9),                      # LeetCode example 1
        (["4", "13", "5", "/", "+"], 6),                     # LeetCode example 2
        (["10", "6", "9", "3", "+", "-11", "*", "/", "*",
          "17", "+", "5", "+"], 22),                         # LeetCode example 3
        (["5", "2", "-"], 3),                                # order matters
        (["2", "5", "-"], -3),
        (["-7", "2", "/"], -3),                              # toward zero, not -4
        (["7", "-2", "/"], -3),
        (["42"], 42),                                        # just a number
    ]

    for solve in [eval_rpn, eval_rpn_dict]:
        for tokens, expected in test_cases:
            result = solve(tokens)
            assert result == expected, (
                f"{solve.__name__}({tokens}) returned {result}, expected {expected}"
            )

    # Floor division would get this wrong
    assert -7 // 2 == -4 and int(-7 / 2) == -3

    # Bad input is reported clearly
    for bad in [["+"], ["1", "2"], ["1", "x", "+"]]:
        try:
            eval_rpn_dict(bad)
            assert False, f"expected ValueError for {bad}"
        except ValueError:
            pass

    # Infix to RPN
    assert to_rpn("(2 + 1) * 3") == ["2", "1", "+", "3", "*"]
    assert to_rpn("4 + 13 / 5") == ["4", "13", "5", "/", "+"]
    assert to_rpn("8 - 3 - 2") == ["8", "3", "-", "2", "-"]   # left to right
    assert to_rpn("12+(3*4)") == ["12", "3", "4", "*", "+"]

    # The safe calculator agrees with Python on simple expressions
    for expr in ["2 + 3 * 4", "(2 + 3) * 4", "100 / 7 / 2", "8 - 3 - 2",
                 "((1 + 2) * (3 + 4)) - 5"]:
        assert safe_calculate(expr) == int(eval(expr)), expr   # eval only on OUR test strings

    # ...and refuses anything else
    for bad in ["__import__('os')", "2 ** 10", "(1 + 2", "1 + 2)"]:
        try:
            safe_calculate(bad)
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass

    print("All tests passed!")


if __name__ == "__main__":
    tokens = ["4", "13", "5", "/", "+"]
    print(f"{tokens} -> {eval_rpn(tokens)}")

    print("\nInfix to RPN:")
    for expr in ["(2 + 1) * 3", "4 + 13 / 5", "8 - 3 - 2"]:
        rpn = to_rpn(expr)
        print(f"  {expr:<14} -> {' '.join(rpn):<12} = {eval_rpn(rpn)}")

    print("\nSafe calculator:")
    for expr in ["2 + 3 * 4", "((1 + 2) * (3 + 4)) - 5",
                 "__import__('os').system('ls')"]:
        try:
            print(f"  {expr!r} = {safe_calculate(expr)}")
        except ValueError as err:
            print(f"  {expr!r} rejected: {err}")

    print()
    run_tests()
