import os
import subprocess
import json
import sqlite3
import xml.etree.ElementTree as ET
import pickle
import random

# CWE-787: Out-of-Bounds Write
def cwe_787_example():
    arr = [1, 2, 3]
    try:
        arr[5] = 10  # Out-of-bounds write
    except IndexError as e:
        print("CWE-787: Out-of-bounds write caught:", e)

# CWE-89: SQL Injection
def cwe_89_example(user_input):
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    cursor.execute("INSERT INTO users (name) VALUES ('admin')")
    connection.commit()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"  # Vulnerable query
    try:
        cursor.execute(query)
        print("CWE-89: Query result:", cursor.fetchall())
    except sqlite3.OperationalError as e:
        print("SQL error:", e)

# CWE-78: OS Command Injection
def cwe_78_example(user_input):
    try:
        subprocess.run(user_input, shell=True)  # Dangerous shell execution
    except Exception as e:
        print("CWE-78: Command execution failed:", e)

# CWE-20: Improper Input Validation
def cwe_20_example(user_input):
    try:
        number = int(user_input)
        print("CWE-20: Valid number:", number)
    except ValueError:
        print("CWE-20: Invalid input.")

# CWE-125: Out-of-Bounds Read
def cwe_125_example():
    arr = [1, 2, 3]
    try:
        print("CWE-125: Out-of-bounds read:", arr[5])  # Reading out-of-bounds
    except IndexError as e:
        print("CWE-125: Out-of-bounds read caught:", e)

# CWE-79: Cross-Site Scripting (XSS)
def cwe_79_example(user_input):
    print(f"CWE-79: Vulnerable HTML: <div>{user_input}</div>")  # Vulnerable to XSS

# CWE-416: Use After Free (simulated)
def cwe_416_example():
    class Dummy:
        def __init__(self, value):
            self.value = value
    obj = Dummy(42)
    del obj  # Free the object
    try:
        print(obj.value)  # Use after free
    except NameError as e:
        print("CWE-416: Use after free caught:", e)

# CWE-22: Path Traversal
def cwe_22_example(user_input):
    base_path = "/safe/directory/"
    file_path = os.path.join(base_path, user_input)
    try:
        with open(file_path, "r") as file:
            print("CWE-22: File content:", file.read())
    except FileNotFoundError as e:
        print("CWE-22: File not found:", e)

# CWE-352: Cross-Site Request Forgery (CSRF) (simulated)
def cwe_352_example():
    print("CWE-352: Simulated CSRF vulnerability. No protection against forged requests.")

# CWE-434: Unrestricted File Upload
def cwe_434_example(filename, file_content):
    try:
        with open(filename, "w") as file:
            file.write(file_content)
        print(f"CWE-434: File {filename} uploaded successfully.")
    except Exception as e:
        print("CWE-434: File upload failed:", e)

# CWE-611: Improper Restriction of XML External Entity (XXE)
def cwe_611_example(xml_input):
    try:
        tree = ET.ElementTree(ET.fromstring(xml_input))
        print("CWE-611: Parsed XML:", tree)
    except ET.ParseError as e:
        print("CWE-611: XML parsing failed:", e)

# CWE-502: Deserialization of Untrusted Data
def cwe_502_example(pickled_data):
    try:
        data = pickle.loads(pickled_data)  # Untrusted deserialization
        print("CWE-502: Deserialized data:", data)
    except pickle.UnpicklingError as e:
        print("CWE-502: Deserialization failed:", e)

# CWE-77: Command Injection
def cwe_77_example(user_input):
    try:
        os.system(user_input)  # Dangerous command execution
    except Exception as e:
        print("CWE-77: Command execution failed:", e)

# CWE-306: Missing Authentication for Critical Function
def cwe_306_example():
    print("CWE-306: Critical function accessed without authentication.")

# CWE-502: Insecure Deserialization (repeated for illustrative purposes)
def cwe_502_example(pickled_data):
    try:
        data = pickle.loads(pickled_data)
        print("CWE-502: Deserialized data:", data)
    except pickle.UnpicklingError as e:
        print("CWE-502: Deserialization failed:", e)

# CWE-862: Missing Authorization
def cwe_862_example():
    print("CWE-862: Accessing a restricted resource without proper authorization.")

# CWE-400: Uncontrolled Resource Consumption
def cwe_400_example():
    try:
        large_list = [0] * 1000000000  # Consuming a large amount of memory
        print("CWE-400: Resource consumption complete.")
    except MemoryError as e:
        print("CWE-400: Memory error caught:", e)

# CWE-190: Integer Overflow or Wraparound
def cwe_190_example():
    large_number = 2**31
    try:
        result = large_number + large_number  # Overflow
        print("CWE-190: Integer overflow result:", result)
    except OverflowError as e:
        print("CWE-190: Overflow error caught:", e)

# CWE-22: Path Traversal (repeated for illustrative purposes)
def cwe_22_example(user_input):
    base_path = "/safe/directory/"
    file_path = os.path.join(base_path, user_input)
    try:
        with open(file_path, "r") as file:
            print("CWE-22: File content:", file.read())
    except FileNotFoundError as e:
        print("CWE-22: File not found:", e)

# CWE-532: Information Exposure Through Log Files
def cwe_532_example():
    sensitive_info = "User password: 12345"
    print(f"CWE-532: Logging sensitive information: {sensitive_info}")

# CWE-269: Improper Privilege Management
def cwe_269_example():
    print("CWE-269: Accessing privileged operation without proper rights.")

# CWE-798: Use of Hard-coded Credentials
def cwe_798_example():
    username = "admin"
    password = "password123"  # Hard-coded credentials
    print(f"CWE-798: Using hard-coded credentials: {username}/{password}")

# Main function to run all examples
if __name__ == "__main__":
    print("Demonstrating the CWE Top 25 vulnerabilities of 2023:\n")
    
    # Run each vulnerability example
    cwe_787_example()
    cwe_89_example("admin' OR '1'='1")
    cwe_78_example("ls -la; echo Vulnerable to command injection")
    cwe_20_example("not_a_number")
    cwe_125_example()
    cwe_79_example("<script>alert('XSS');</script>")
    cwe_416_example()
    cwe_22_example("../etc/passwd")
    cwe_352_example()
    cwe_434_example("malicious_file.txt", "malicious content")
    cwe_611_example("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>")
    cwe_502_example(pickle.dumps({"key": "value"}))
    cwe_77_example("rm -rf /")
    cwe_306_example()
    cwe_862_example()
    cwe_400_example()
    cwe_190_example()
    cwe_532_example()
    cwe_269_example()
    cwe_798_example()

    print("\nEnd of demonstration.")
