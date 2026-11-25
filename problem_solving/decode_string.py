# Decode String (LeetCode 394)
#
# PROBLEM
# -------
# A string is encoded with the rule  k[text], meaning "text repeated
# k times". Encodings can be nested. Return the decoded string.
#
#   "3[a]2[bc]"     ->  "aaabcbc"
#   "3[a2[c]]"      ->  "accaccacc"    inner first: a2[c] = "acc"
#   "2[abc]3[cd]ef" ->  "abcabccdcdcdef"
#
# You can assume the input is well formed: brackets match, and every
# number is followed by "[".
#
# KEY IDEAS
# ---------
#   - Nested brackets mean "finish the inner part before the outer
#     part". Whenever you see "[", you start a new level and have to
#     SAVE where you were. When you see "]", you finish that level and
#     go back to the saved state. Save and restore in reverse order is
#     a stack.
#   - Numbers can have several digits: "12[a]". Build them digit by
#     digit:  number = number * 10 + int(ch)
#   - Build strings in a list and "".join() them at the end. Adding to
#     a string in a loop copies it every time.
#
# WHAT'S NEW HERE
# ---------------
# valid_parentheses.py only CHECKED the nesting. Here the stack SAVES
# WORK IN PROGRESS: each entry holds the text built so far and the
# repeat count for the level being opened. Solution 2 shows that
# recursion does the same thing, using Python's own call stack.
#
# SECURITY CONNECTION
# -------------------
#   - Decompression bombs: a tiny input can expand into a huge output.
#     "9[9[9[9[9[9[9[9[9[a]]]]]]]]]" is 28 characters and decodes to
#     387 million. A "zip bomb" works the same way, so real decoders
#     cap the output size (variation 1).
#   - Path traversal: a web server that builds file paths from user
#     input must resolve ".." correctly, or "../../etc/passwd"
#     escapes the folder it's meant to stay in. Resolving a path is a
#     stack problem (variation 2).


# ---------------------------------------------------------------
# Solution 1: stack (iterative)
# ---------------------------------------------------------------
#
# Keep two things for the CURRENT level:
#   current  -> list of pieces of text built so far at this level
#   number   -> the repeat count being read
#
#   digit -> keep building the number
#   "["   -> push (current, number), then start a fresh level
#   "]"   -> pop (previous, count), and set
#            current = previous + current * count
#   letter-> add it to current
#
# Trace for s = "3[a2[c]]":
#
#   ch | action                                | current | stack
#   ---|---------------------------------------|---------|-----------------
#   3  | number = 3                            | ""      | []
#   [  | push ("", 3), reset                   | ""      | [("", 3)]
#   a  | add                                   | "a"     | [("", 3)]
#   2  | number = 2                            | "a"     | [("", 3)]
#   [  | push ("a", 2), reset                  | ""      | [("", 3), ("a", 2)]
#   c  | add                                   | "c"     | [("", 3), ("a", 2)]
#   ]  | pop ("a", 2): "a" + "c" * 2           | "acc"   | [("", 3)]
#   ]  | pop ("", 3):  "" + "acc" * 3          | "accaccacc" | []

def decode_string(s):
    stack = []                            # (text before this level, repeat count)
    current = []
    number = 0

    for ch in s:
        if ch.isdigit():
            number = number * 10 + int(ch)        # "12" -> 1, then 12
        elif ch == "[":
            stack.append(("".join(current), number))
            current, number = [], 0               # start a fresh level
        elif ch == "]":
            previous, count = stack.pop()
            current = [previous + "".join(current) * count]
        else:
            current.append(ch)

    return "".join(current)


# ---------------------------------------------------------------
# Solution 2: recursion (the call stack does the saving)
# ---------------------------------------------------------------
#
# A helper decodes from position i until it reaches a "]" (or the
# end), and returns the decoded text plus the position it stopped at.
# On "[", it calls itself for the inner part. Each call's local
# variables are the "saved state" that solution 1 pushes by hand.
#
# Python stops recursion at about 1,000 levels by default, so very
# deep nesting raises RecursionError. The explicit stack in
# solution 1 has no such limit.

def decode_string_recursive(s):
    def decode_from(i):
        pieces = []
        number = 0
        while i < len(s):
            ch = s[i]
            if ch.isdigit():
                number = number * 10 + int(ch)
            elif ch == "[":
                inner, i = decode_from(i + 1)     # decode inside the brackets
                pieces.append(inner * number)
                number = 0
            elif ch == "]":
                return "".join(pieces), i         # this level is done
            else:
                pieces.append(ch)
            i += 1
        return "".join(pieces), i

    result, _ = decode_from(0)
    return result


# ---------------------------------------------------------------
# Variation 1: decode with an output size limit
# ---------------------------------------------------------------
#
# Work out the decoded LENGTH first, without building the string, and
# refuse to decode if it's over `max_length`. The length uses the
# same stack, but holds numbers instead of text, so checking a
# "bomb" costs almost nothing.

def decoded_length(s):
    stack = []
    length = 0
    number = 0
    for ch in s:
        if ch.isdigit():
            number = number * 10 + int(ch)
        elif ch == "[":
            stack.append((length, number))
            length, number = 0, 0
        elif ch == "]":
            previous, count = stack.pop()
            length = previous + length * count
        else:
            length += 1
    return length


def safe_decode(s, max_length=1_000_000):
    size = decoded_length(s)
    if size > max_length:
        raise ValueError(f"decoded size {size:,} is over the limit of {max_length:,}")
    return decode_string(s)


# ---------------------------------------------------------------
# Variation 2: Simplify Path (LeetCode 71)
# ---------------------------------------------------------------
#
# Turn a Unix-style absolute path into its simplest form:
#   "."   means the current folder: ignore it
#   ".."  means the parent folder: go up one level (pop)
#   "//"  counts as one "/"
#
#   "/home//user/./docs/../notes/"  ->  "/home/user/notes"
#   "/../"                          ->  "/"    can't go above the root
#
# Each folder name is pushed, and ".." pops the last one. That's the
# whole trick.

def simplify_path(path):
    stack = []
    for part in path.split("/"):
        if part == "..":
            if stack:                     # at the root, ".." does nothing
                stack.pop()
        elif part and part != ".":        # skip "" (from "//") and "."
            stack.append(part)
    return "/" + "/".join(stack)


# Path traversal check: resolve the requested path INSIDE a base
# folder, then make sure the result is still inside it.
#
#   is_inside("/srv/files", "reports/q1.txt")     -> True
#   is_inside("/srv/files", "../../etc/passwd")   -> False
#
# Real code should use pathlib's Path.resolve() and is_relative_to(),
# which also handle symbolic links. This version shows the idea.

def is_inside(base, requested):
    full = simplify_path(base + "/" + requested)
    base = simplify_path(base)
    return full == base or full.startswith(base + "/")


# ---------------------------------------------------------------
# COMPLEXITY (n = length of the input, m = length of the output)
# ---------------------------------------------------------------
#
#   Solution                  | Time       | Extra space
#   --------------------------|------------|----------------------------
#   1. Stack                  | O(n + m)   | O(n + m)
#   2. Recursion              | O(n + m)   | O(n + m), plus call stack
#   decoded_length            | O(n)       | O(d)  d = nesting depth
#   Simplify Path             | O(n)       | O(n)
#
# The output can be FAR bigger than the input, which is why the time
# depends on m. That gap is exactly what a decompression bomb exploits.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    test_cases = [
        # (s, expected)
        ("3[a]2[bc]", "aaabcbc"),               # LeetCode example 1
        ("3[a2[c]]", "accaccacc"),              # LeetCode example 2
        ("2[abc]3[cd]ef", "abcabccdcdcdef"),    # LeetCode example 3
        ("abc", "abc"),                         # no encoding
        ("", ""),
        ("10[a]", "a" * 10),                    # two-digit number
        ("2[a2[b2[c]]]", "abccbccabccbcc"),     # three levels
        ("x1[y]z", "xyz"),                      # repeat once
    ]

    for solve in [decode_string, decode_string_recursive]:
        for s, expected in test_cases:
            result = solve(s)
            assert result == expected, (
                f"{solve.__name__}({s!r}) returned {result!r}, expected {expected!r}"
            )

    # Length without decoding
    for s, expected in test_cases:
        assert decoded_length(s) == len(expected)
    assert decoded_length("9[9[9[9[9[9[9[9[9[a]]]]]]]]]") == 9 ** 9

    # The size limit
    assert safe_decode("3[a]") == "aaa"
    try:
        safe_decode("9[9[9[9[9[9[9[9[9[a]]]]]]]]]")
        assert False, "expected ValueError"
    except ValueError:
        pass

    # Recursion has a depth limit, the explicit stack doesn't
    deep = "1[" * 5_000 + "a" + "]" * 5_000
    assert decode_string(deep) == "a"
    try:
        decode_string_recursive(deep)
        assert False, "expected RecursionError"
    except RecursionError:
        pass

    # Simplify Path (LeetCode 71 examples and more)
    assert simplify_path("/home/") == "/home"
    assert simplify_path("/home//foo/") == "/home/foo"
    assert simplify_path("/home/user/Documents/../Pictures") == "/home/user/Pictures"
    assert simplify_path("/../") == "/"
    assert simplify_path("/.../a/../b/c/../d/./") == "/.../b/d"   # "..." is a real name

    # Path traversal
    assert is_inside("/srv/files", "reports/q1.txt") is True
    assert is_inside("/srv/files", "reports/../q2.txt") is True
    assert is_inside("/srv/files", "../../etc/passwd") is False
    assert is_inside("/srv/files", "../files_backup/x") is False  # similar prefix

    print("All tests passed!")


if __name__ == "__main__":
    for s in ["3[a]2[bc]", "3[a2[c]]", "2[abc]3[cd]ef"]:
        print(f"{s!r:<17} -> {decode_string(s)!r}")

    bomb = "9[9[9[9[9[9[9[9[9[a]]]]]]]]]"
    print(f"\n{bomb!r} is {len(bomb)} characters "
          f"but decodes to {decoded_length(bomb):,}")
    try:
        safe_decode(bomb)
    except ValueError as err:
        print(f"safe_decode refused it: {err}")

    print("\nSimplify Path:")
    for p in ["/home//user/./docs/../notes/", "/../", "/a/b/../../c"]:
        print(f"  {p!r:<32} -> {simplify_path(p)!r}")

    print("\nPath traversal check (base folder /srv/files):")
    for req in ["reports/q1.txt", "../../etc/passwd", "../files_backup/x"]:
        verdict = "allowed" if is_inside("/srv/files", req) else "BLOCKED"
        print(f"  {req!r:<22} -> {verdict}")

    print()
    run_tests()
