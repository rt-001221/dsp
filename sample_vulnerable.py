# sample_vulnerable.py

import os
import subprocess
import hashlib

password = "123456"  # Hardcoded password
api_key = "ABCDEF123456"  # Hardcoded API key

def insecure_eval(user_input):
    return eval(user_input)  # Use of eval

def sql_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"  # SQL Injection Risk
    print(query)

def command_injection(user_input):
    os.system("ping " + user_input)  # Command Injection Risk

def weak_crypto(data):
    h = hashlib.md5(data.encode())  # Weak Crypto
    return h.hexdigest()

def get_input():
    value = input("Enter value: ")  # Unvalidated Input
    print(value)  # Debug Code

from math import *