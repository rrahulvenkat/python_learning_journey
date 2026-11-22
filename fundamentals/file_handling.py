# File Handling
#
# Programs often need to save data or read it back later. Python can
# read and write files with the built-in open() function.
#
# Topics covered here:
#   1. Opening a file: open() and file modes
#   2. Writing to a file
#   3. Reading a file (read, readline, readlines, looping)
#   4. Appending to a file
#   5. The "with" statement (closes the file automatically)
#   6. Handling file errors
#   7. Checking, renaming and deleting files (os and pathlib)
#   8. Working with CSV files
#   9. Working with JSON files
#  10. Practical example: analysing a log file
#
# This script creates its sample files in a "sample_files" folder next
# to this file, and deletes them again at the end.

import csv
import json
import os
from pathlib import Path

# Folder for the sample files: same place as this script
SAMPLE_DIR = Path(__file__).parent / "sample_files"
SAMPLE_DIR.mkdir(exist_ok=True)

notes_file = SAMPLE_DIR / "notes.txt"


# ---------------------------------------------------------------
# 1. File modes
# ---------------------------------------------------------------
#
#   open(filename, mode)
#
#   Mode | Meaning
#   -----|--------------------------------------------------------
#   "r"  | read (default). Error if the file doesn't exist
#   "w"  | write. Creates the file, or ERASES it if it exists
#   "a"  | append. Adds to the end; creates the file if needed
#   "x"  | create. Error if the file already exists
#   "r+" | read and write
#   "b"  | binary mode, added to others: "rb", "wb" (images, etc.)


# ---------------------------------------------------------------
# 2. Writing to a file
# ---------------------------------------------------------------

print("--- 2. Writing ---")

# The basic (manual) way: open, write, close
file = open(notes_file, "w")
file.write("Python is fun.\n")          # write() does NOT add a new line
file.write("Files store data.\n")
file.close()                            # always close the file!

# writelines() writes a list of strings
file = open(notes_file, "a")
file.writelines(["Line three\n", "Line four\n"])
file.close()

print(f"Wrote to {notes_file.name}")


# ---------------------------------------------------------------
# 3. Reading a file
# ---------------------------------------------------------------

print("\n--- 3. Reading ---")

# read(): the whole file as ONE string
file = open(notes_file, "r")
content = file.read()
file.close()
print("read():")
print(content)

# readline(): one line at a time
file = open(notes_file)                 # "r" is the default mode
first = file.readline()
second = file.readline()
file.close()
print("readline():", first.strip(), "|", second.strip())

# readlines(): a LIST of lines
file = open(notes_file)
lines = file.readlines()
file.close()
print("readlines():", lines)

# Looping over the file: the best way for big files (one line in memory)
print("Looping:")
file = open(notes_file)
for line_number, line in enumerate(file, start=1):
    print(f"  {line_number}: {line.strip()}")   # strip() removes the "\n"
file.close()


# ---------------------------------------------------------------
# 4. Appending to a file
# ---------------------------------------------------------------

print("\n--- 4. Appending ---")

file = open(notes_file, "a")
file.write("This line was appended.\n")
file.close()

file = open(notes_file)
print("Last line now:", file.readlines()[-1].strip())
file.close()


# ---------------------------------------------------------------
# 5. The "with" statement (recommended)
# ---------------------------------------------------------------
#
# "with" closes the file automatically when the block ends, even if
# an error happens. Use it instead of calling close() yourself.

print("\n--- 5. with statement ---")

with open(notes_file, "w") as file:
    file.write("Rewritten using 'with'.\n")
    file.write("No need to call close().\n")

print("Is the file closed now?", file.closed)

with open(notes_file) as file:
    for line in file:
        print(" ", line.strip())

# Specify encoding to avoid surprises with special characters
with open(notes_file, "a", encoding="utf-8") as file:
    file.write("Unicode works too: café, ₹, 😀\n")

with open(notes_file, encoding="utf-8") as file:
    print(" ", file.readlines()[-1].strip())

# print() can write to a file as well
with open(notes_file, "a", encoding="utf-8") as file:
    print("Written with print()", file=file)


# ---------------------------------------------------------------
# 6. Handling file errors
# ---------------------------------------------------------------

print("\n--- 6. File errors ---")

try:
    with open(SAMPLE_DIR / "missing.txt") as file:
        print(file.read())
except FileNotFoundError:
    print("missing.txt does not exist.")

try:
    with open(notes_file, "x") as file:      # "x" fails if file exists
        file.write("new")
except FileExistsError:
    print("notes.txt already exists, so mode 'x' refused to overwrite it.")

# Other ones you may see: PermissionError, IsADirectoryError


# ---------------------------------------------------------------
# 7. Checking, renaming and deleting files
# ---------------------------------------------------------------

print("\n--- 7. os and pathlib ---")

# Using the os module
print("Exists (os):", os.path.exists(notes_file))
print("Size in bytes:", os.path.getsize(notes_file))

# Using pathlib (more modern, recommended)
path = Path(notes_file)
print("Name:", path.name)            # notes.txt
print("Stem:", path.stem)            # notes
print("Suffix:", path.suffix)        # .txt
print("Exists (pathlib):", path.exists())

# pathlib also has shortcuts for small files
temp = SAMPLE_DIR / "temp.txt"
temp.write_text("Quick write with pathlib\n")
print("read_text():", temp.read_text().strip())

# Rename and delete
renamed = SAMPLE_DIR / "temp_renamed.txt"
temp.rename(renamed)
print("After rename, exists?", renamed.exists())
renamed.unlink()                     # delete the file (same as os.remove)
print("After delete, exists?", renamed.exists())

# List files in a folder
print("Files in sample_files:", [p.name for p in SAMPLE_DIR.iterdir()])


# ---------------------------------------------------------------
# 8. CSV files (comma-separated values, like a spreadsheet)
# ---------------------------------------------------------------

print("\n--- 8. CSV ---")

csv_file = SAMPLE_DIR / "students.csv"

# Writing CSV rows
students = [
    ["name", "age", "grade"],
    ["Asha", 20, "A"],
    ["Ben", 22, "B"],
    ["Chen", 21, "A"],
]
with open(csv_file, "w", newline="") as file:   # newline="" avoids blank rows on Windows
    writer = csv.writer(file)
    writer.writerows(students)

# Reading CSV rows as lists
with open(csv_file, newline="") as file:
    reader = csv.reader(file)
    for row in reader:
        print(row)

# Reading CSV rows as dictionaries (uses the header row as keys)
with open(csv_file, newline="") as file:
    reader = csv.DictReader(file)
    a_students = [row["name"] for row in reader if row["grade"] == "A"]
print("Grade A students:", a_students)


# ---------------------------------------------------------------
# 9. JSON files (structured data, used by most web APIs)
# ---------------------------------------------------------------

print("\n--- 9. JSON ---")

json_file = SAMPLE_DIR / "config.json"

config = {
    "app": "Password Analyzer",
    "version": 1.2,
    "debug": False,
    "allowed_users": ["rahul", "admin"],
}

# Python dict -> JSON file
with open(json_file, "w") as file:
    json.dump(config, file, indent=4)

# JSON file -> Python dict
with open(json_file) as file:
    loaded = json.load(file)

print("Loaded type:", type(loaded).__name__)
print("App:", loaded["app"])
print("Users:", loaded["allowed_users"])

# dumps/loads work with strings instead of files
text = json.dumps({"ok": True, "count": 3})
print("As JSON text:", text)
print("Back to dict:", json.loads(text))


# ---------------------------------------------------------------
# 10. Practical example: analysing a log file
# ---------------------------------------------------------------

print("\n--- 10. Log analysis ---")

log_file = SAMPLE_DIR / "auth.log"

log_lines = """\
2026-11-22 10:01:12 LOGIN SUCCESS user=rahul ip=10.0.0.5
2026-11-22 10:03:45 LOGIN FAILED user=admin ip=192.168.1.50
2026-11-22 10:03:50 LOGIN FAILED user=admin ip=192.168.1.50
2026-11-22 10:04:02 LOGIN FAILED user=root ip=192.168.1.50
2026-11-22 10:10:30 LOGIN SUCCESS user=asha ip=10.0.0.8
2026-11-22 10:12:11 LOGIN FAILED user=guest ip=172.16.0.3
"""
with open(log_file, "w") as file:
    file.write(log_lines)

failed_by_ip = {}
with open(log_file) as file:
    for line in file:
        if "FAILED" in line:
            ip = line.split("ip=")[1].strip()
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

print("Failed logins per IP:")
for ip, count in failed_by_ip.items():
    flag = "  <-- suspicious" if count >= 3 else ""
    print(f"  {ip:<15} {count}{flag}")

# Save a report
report_file = SAMPLE_DIR / "report.txt"
with open(report_file, "w") as file:
    for ip, count in failed_by_ip.items():
        file.write(f"{ip},{count}\n")
print(f"Report saved to {report_file.name}")


# ---------------------------------------------------------------
# Clean up the sample files
# ---------------------------------------------------------------

for sample in SAMPLE_DIR.iterdir():
    sample.unlink()
SAMPLE_DIR.rmdir()
print("\nSample files cleaned up.")
