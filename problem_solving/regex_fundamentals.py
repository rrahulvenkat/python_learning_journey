# Regular Expressions: Fundamentals
#
# WHAT A REGULAR EXPRESSION IS
# ----------------------------
# A regular expression (regex) is a small pattern language for
# describing text. Instead of writing a loop to find "a word made of
# digits, then a dot, then more digits", you write  \d+\.\d+  and let
# the `re` module do the searching.
#
#   import re
#   re.findall(r"\d+", "port 22, then 443")   ->  ['22', '443']
#
# Always write patterns as RAW STRINGS: r"\d+". Without the r, Python
# treats backslashes itself first ("\b" becomes a backspace
# character), and the pattern silently changes.
#
# SECTIONS
# --------
#   1. The re functions: search, match, fullmatch, findall, finditer,
#      sub, split, compile
#   2. Literal characters and escaping
#   3. Character classes: [abc], [^abc], \d \w \s, and .
#   4. Quantifiers: * + ? {n} {n,m}, and greedy vs lazy
#   5. Anchors: ^ $ \b
#   6. Groups: capturing ( ), named (?P<name> ), non-capturing (?: )
#   7. Alternation: a|b
#   8. Flags: IGNORECASE, MULTILINE, VERBOSE
#   9. Lookahead: (?= ) and (?! )
#  10. Practice problems with tests
#
# SECURITY CONNECTION
# -------------------
# Regex is the everyday tool for pulling indicators (IPs, domains,
# hashes, emails) out of logs and reports, and it's the language of
# many detection tools: grep, Splunk, YARA rules, Snort/Suricata rules
# and WAF rules. log_parsing.py applies these sections to real log
# formats.


import re


# ---------------------------------------------------------------
# 1. The re functions
# ---------------------------------------------------------------
#
#   function          | finds                          | returns
#   ------------------|--------------------------------|---------------------
#   re.search(p, s)   | the FIRST match anywhere       | Match or None
#   re.match(p, s)    | a match at the START only      | Match or None
#   re.fullmatch(p, s)| the WHOLE string must match    | Match or None
#   re.findall(p, s)  | every match                    | list of strings
#   re.finditer(p, s) | every match                    | Match objects, one by one
#   re.sub(p, r, s)   | every match, replaced by r     | new string
#   re.split(p, s)    | split wherever p matches       | list of strings
#   re.compile(p)     | (nothing yet)                  | a reusable Pattern
#
# A Match object tells you what matched and where:
#   m.group()  the matched text      m.start(), m.end()  its position

def section_1():
    text = "Failed login from 203.0.113.9 on port 22"

    m = re.search(r"\d+", text)
    print("search     :", m.group(), "at", m.start())         # 203 at 18

    print("match      :", re.match(r"\d+", text))              # None: text starts with "F"
    print("match      :", re.match(r"Failed", text).group())

    print("fullmatch  :", re.fullmatch(r"\d+", "443"))         # whole string is digits
    print("fullmatch  :", re.fullmatch(r"\d+", "443a"))        # None

    print("findall    :", re.findall(r"\d+", text))

    for m in re.finditer(r"\d+", text):
        print(f"finditer   : {m.group():>3} at {m.start()}-{m.end()}")

    print("sub        :", re.sub(r"\d", "#", "pin 1234"))      # pin ####
    print("split      :", re.split(r"\s*[,;]\s*", "a, b;c ,d"))

    # compile once when you use the same pattern many times (in a loop)
    digits = re.compile(r"\d+")
    print("compiled   :", digits.findall("10 20 30"))


# ---------------------------------------------------------------
# 2. Literal characters and escaping
# ---------------------------------------------------------------
#
# Most characters match themselves. These 14 have special meanings
# and must be escaped with a backslash to match literally:
#     . ^ $ * + ? { } [ ] \ | ( )
#
#   r"1.1"   matches "1.1" but ALSO "1x1" and "121" (. means any char)
#   r"1\.1"  matches only "1.1"
#
# re.escape() escapes a whole string for you. Use it whenever you put
# user input into a pattern, or the input can change the pattern.

def section_2():
    print(re.findall(r"1.1", "1.1 1x1 121"))            # all three!
    print(re.findall(r"1\.1", "1.1 1x1 121"))           # just '1.1'
    print(re.escape("example.com"))                     # example\.com
    domain = "evil.com"
    print(re.findall(re.escape(domain), "evil.com evilXcom"))


# ---------------------------------------------------------------
# 3. Character classes
# ---------------------------------------------------------------
#
#   [abc]      one of a, b or c           [a-z]   a range
#   [^abc]     anything EXCEPT a, b, c    [0-9a-fA-F]  a hex digit
#   \d         a digit         (same as [0-9] for ASCII)
#   \w         a word char     letters, digits, underscore
#   \s         whitespace      space, tab, newline
#   \D \W \S   the opposites
#   .          any character except a newline
#
# Inside [ ], most special characters are literal: [.] is a dot.

def section_3():
    s = "user_1 logged in at 09:41 from host-7"
    print(re.findall(r"\d", s))
    print(re.findall(r"[0-9a-f]", "Ab3Z9f"))            # lower-case hex only
    print(re.findall(r"[^a-z ]", "abc 123!"))           # not lower-case, not space
    print(re.findall(r"\w+", s))                        # "words" (host and 7 split on "-")
    print(re.findall(r"\S+", s))                        # runs of non-space


# ---------------------------------------------------------------
# 4. Quantifiers, greedy vs lazy
# ---------------------------------------------------------------
#
#   *      0 or more        +      1 or more        ?   0 or 1
#   {3}    exactly 3        {2,4}  2 to 4           {2,} 2 or more
#
# Quantifiers are GREEDY: they take as much as they can. Add ? to
# make them LAZY (as little as possible):
#
#   text:  <b>bold</b> and <i>italic</i>
#   <.+>   matches the WHOLE thing: "<b>bold</b> and <i>italic</i>"
#   <.+?>  matches each tag:        "<b>", "</b>", "<i>", "</i>"

def section_4():
    print(re.findall(r"\d{3}", "1 22 333 4444"))        # '333', '444' (from 4444)
    print(re.findall(r"\b\d{2,3}\b", "1 22 333 4444"))  # whole numbers of 2-3 digits
    print(re.findall(r"colou?r", "color colour"))
    html = "<b>bold</b> and <i>italic</i>"
    print("greedy:", re.findall(r"<.+>", html))
    print("lazy:  ", re.findall(r"<.+?>", html))


# ---------------------------------------------------------------
# 5. Anchors (match a POSITION, not a character)
# ---------------------------------------------------------------
#
#   ^     start of the string (or of each line with MULTILINE)
#   $     end of the string   (or of each line with MULTILINE)
#   \b    a word boundary: between a \w and a non-\w character
#
#   r"cat"      finds "cat" inside "concatenate"
#   r"\bcat\b"  only finds the whole word "cat"
#
# For VALIDATION, use re.fullmatch (or ^ ... $). Without anchors,
# r"\d+" "validates" "abc123xyz" because it finds 123 somewhere inside.

def section_5():
    print(re.findall(r"cat", "cat concatenate"))
    print(re.findall(r"\bcat\b", "cat concatenate"))
    print("search finds digits in 'abc123xyz':", bool(re.search(r"\d+", "abc123xyz")))
    print("fullmatch says it's all digits:   ", bool(re.fullmatch(r"\d+", "abc123xyz")))


# ---------------------------------------------------------------
# 6. Groups
# ---------------------------------------------------------------
#
#   ( ... )            capturing group: m.group(1), m.group(2), ...
#   (?P<name> ... )    named group:     m.group("name"), m.groupdict()
#   (?: ... )          non-capturing:   groups for a quantifier, saves nothing
#   \1  or (?P=name)   backreference:   "the same text as group 1 again"
#
# With groups, findall returns the GROUPS instead of the whole match:
#   one group  -> list of strings      several groups -> list of tuples

def section_6():
    m = re.search(r"(\d+):(\d+)", "time 09:41")
    print("groups:", m.group(0), m.group(1), m.group(2))

    m = re.search(r"(?P<user>\w+)@(?P<domain>[\w.]+)", "mail alice@example.com now")
    print("named: ", m.group("user"), m.group("domain"), m.groupdict())

    print("findall with groups:", re.findall(r"(\w+)=(\d+)", "a=1 b=22 c=x"))
    print("non-capturing:      ", re.findall(r"(?:ab)+", "ababab xab"))
    print("backreference:      ", re.findall(r"\b(\w+) \1\b", "the the cat sat sat"))


# ---------------------------------------------------------------
# 7. Alternation
# ---------------------------------------------------------------
#
#   cat|dog          "cat" or "dog"
#   (GET|POST) /     group it, or | splits the WHOLE pattern
#
#   r"GET|POST /" means "GET" OR "POST /", which is rarely intended.

def section_7():
    print(re.findall(r"cat|dog", "cat, dog, bird"))
    lines = ["GET /index", "POST /login", "DELETE /user", "GET"]
    print([l for l in lines if re.match(r"(GET|POST) /", l)])
    print([l for l in lines if re.match(r"GET|POST /", l)])   # the bug: matches "GET"


# ---------------------------------------------------------------
# 8. Flags
# ---------------------------------------------------------------
#
#   re.IGNORECASE (re.I)   case-insensitive
#   re.MULTILINE  (re.M)   ^ and $ match at every line
#   re.VERBOSE    (re.X)   spaces and # comments allowed in the pattern
#
# Combine with |:  re.I | re.M

def section_8():
    print(re.findall(r"error", "Error ERROR error", re.I))

    log = "INFO ok\nERROR disk\nINFO ok\nERROR net"
    print(re.findall(r"^ERROR (\w+)", log))             # [] : ^ only means the very start
    print(re.findall(r"^ERROR (\w+)", log, re.M))       # every line

    time_pattern = re.compile(r"""
        (?P<hour>[01]\d|2[0-3])     # 00-23
        :
        (?P<minute>[0-5]\d)         # 00-59
    """, re.X)
    print(time_pattern.fullmatch("23:59").groupdict())
    print(time_pattern.fullmatch("24:00"))


# ---------------------------------------------------------------
# 9. Lookahead and lookbehind
# ---------------------------------------------------------------
#
#   (?=...)   "followed by ..." without consuming it
#   (?!...)   "NOT followed by ..."
#   (?<=...)  "preceded by ..."
#   (?<!...)  "NOT preceded by ..."
#
# Several lookaheads at the start of a pattern each check a rule
# independently, which is handy for password policies:
#
#   ^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{12,}$
#     has a lower-case letter, an upper-case letter, a digit, a
#     symbol, and is at least 12 characters long.

PASSWORD_RULES = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{12,}$")

def section_9():
    print(re.findall(r"\d+(?=px)", "10px 20em 30px"))        # numbers followed by px
    print(re.findall(r"(?<=\$)\d+", "cost $40, qty 3"))      # numbers after a $
    print(re.findall(r"\b\d+\b(?!%)", "50% of 200 users"))   # numbers NOT followed by %
    for pw in ["password", "Password123", "Correct-Horse-9-Battery"]:
        print(f"{pw!r:<26} meets policy? {bool(PASSWORD_RULES.match(pw))}")


# ---------------------------------------------------------------
# 10. Practice problems
# ---------------------------------------------------------------
#
# Each function solves one small problem with a regex. The tests at
# the bottom check them. Try writing each one yourself first.

# a) Is this a valid username? 3-16 characters: letters, digits,
#    underscore or hyphen, and it must START with a letter.
def is_valid_username(name):
    return re.fullmatch(r"[A-Za-z][\w-]{2,15}", name, re.ASCII) is not None


# b) Find every hashtag in a post, without the "#".
def hashtags(text):
    return re.findall(r"#(\w+)", text)


# c) Turn "2026-11-27" into "27/11/2026" (use groups in the replacement).
def reformat_date(text):
    return re.sub(r"(\d{4})-(\d{2})-(\d{2})", r"\3/\2/\1", text)


# d) Collapse runs of whitespace into one space, and trim the ends.
def normalise_spaces(text):
    return re.sub(r"\s+", " ", text).strip()


# e) Find doubled words ("the the"), ignoring case.
def doubled_words(text):
    return [m.group(1) for m in re.finditer(r"\b(\w+)\s+\1\b", text, re.I)]


# f) Split CamelCase into words: "parseHTTPResponse" -> ["parse", "HTTP", "Response"]
#    Order of the alternatives matters:
#      [A-Z]+(?=[A-Z][a-z])   an acronym followed by a new word ("HTTP" before "Response")
#      [A-Z]?[a-z]+           a normal word
#      [A-Z]+                 an acronym at the end ("ID")
#      \d+                    numbers
def split_camel_case(name):
    return re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", name)


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    # Behaviour worth remembering
    assert re.match(r"\d+", "a1") is None
    assert re.search(r"\d+", "a1").group() == "1"
    assert re.findall(r"<.+?>", "<a><b>") == ["<a>", "<b>"]
    assert re.findall(r"<.+>", "<a><b>") == ["<a><b>"]
    assert re.findall(r"(\w)=(\d)", "a=1 b=2") == [("a", "1"), ("b", "2")]
    assert re.findall(r"^x", "x\nx") == ["x"]
    assert re.findall(r"^x", "x\nx", re.M) == ["x", "x"]
    assert re.findall(r"GET|POST /", "GET /a") == ["GET"]    # alternation trap
    assert "\b" != r"\b"                                     # why raw strings matter

    # Password policy
    assert PASSWORD_RULES.match("Correct-Horse-9-Battery")
    assert not PASSWORD_RULES.match("Password123")           # no symbol, too short
    assert not PASSWORD_RULES.match("ALLUPPER-123-XYZ")      # no lower case

    # a) usernames
    for good in ["bob", "alice_01", "Zed-the-3rd", "a" * 16]:
        assert is_valid_username(good), good
    for bad in ["al", "1alice", "_bob", "a" * 17, "bob smith", "bob!", "", "bób"]:
        assert not is_valid_username(bad), bad

    # b) hashtags
    assert hashtags("Patch now #infosec #CVE_2026 #") == ["infosec", "CVE_2026"]

    # c) dates
    assert reformat_date("from 2026-11-27 to 2026-12-01") == "from 27/11/2026 to 01/12/2026"

    # d) whitespace
    assert normalise_spaces("  too   many \t spaces\n ") == "too many spaces"

    # e) doubled words
    assert doubled_words("This is is a test. The the end") == ["is", "The"]
    assert doubled_words("no repeats here") == []

    # f) camel case
    assert split_camel_case("parseHTTPResponse") == ["parse", "HTTP", "Response"]
    assert split_camel_case("getUserID") == ["get", "User", "ID"]
    assert split_camel_case("simple") == ["simple"]
    assert split_camel_case("base64Encode") == ["base", "64", "Encode"]

    print("All tests passed!")


if __name__ == "__main__":
    for number, section in enumerate([section_1, section_2, section_3, section_4, section_5,
                                      section_6, section_7, section_8, section_9], start=1):
        print(f"\n--- {number}. {section.__name__} ---")
        section()

    print()
    run_tests()
