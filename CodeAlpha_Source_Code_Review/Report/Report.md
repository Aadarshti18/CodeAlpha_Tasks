# Secure Coding Review Report

## Author

**Aadarsh Tiwari**

## Task Name

**Task 3 – Secure Coding Review**

## Programming Language Used

**Python**

---

## Introduction

Secure coding refers to writing software in a way that protects it from security threats such as unauthorized access, data theft, and misuse. Many security issues arise due to poor coding practices like storing passwords in plain text, not validating user input, or hardcoding sensitive information.

In this task, a simple Python login program is reviewed to identify security vulnerabilities. After identifying the issues, a secure version of the same program is implemented by following secure coding best practices.

---

## Objective of the Task

The main objectives of this secure coding review are:

* To analyze an insecure Python login program
* To identify security vulnerabilities in the code
* To understand how attackers can exploit these vulnerabilities
* To apply secure coding techniques to fix the issues
* To improve overall application security

---

## Application Reviewed

**Application Name:** Simple Login Authentication System
**Description:** A basic console-based login system that takes username and password as input and validates them.

---

## Insecure Code Overview

The original login program checks the username and password directly using hardcoded values. The credentials are stored in plain text, and no input validation or encryption is applied.

This makes the application highly vulnerable to attacks.

---

## Vulnerabilities Identified

### 1. Hardcoded Credentials

**Description:**
The username and password are directly written inside the source code.

**Why it is risky:**

* If the source code is exposed, anyone can see the credentials
* Attackers can easily gain unauthorized access

**Impact:**

* Unauthorized login
* Data breach

---

### 2. Plain Text Password Storage

**Description:**
Passwords are stored and compared in plain text format.

**Why it is risky:**

* Plain text passwords can be read easily
* If the system is compromised, passwords are exposed

**Impact:**

* Password leakage
* Account compromise

---

### 3. No Input Validation

**Description:**
The program does not check whether the input fields are empty or invalid.

**Why it is risky:**

* Allows brute-force and guessing attacks
* Makes the application unstable

**Impact:**

* Increased attack surface
* Poor user experience

---

## Secure Coding Improvements Implemented

### 1. Password Hashing

* Passwords are converted into a hashed format using the SHA-256 algorithm
* Hashed passwords cannot be easily reversed

### 2. Removal of Plain Text Credentials

* Passwords are no longer stored or compared in plain text

### 3. Input Validation

* The program checks whether username or password fields are empty
* Prevents invalid input from being processed

---

## Secure Code Overview

The improved version of the program uses password hashing and basic input validation to ensure better security. This significantly reduces the risk of unauthorized access and protects user credentials.

---

## Tools & Technologies Used

* Python Programming Language
* hashlib (for password hashing)
* Visual Studio Code
* Manual Code Review

---

## Conclusion

This secure coding review demonstrates how small coding mistakes can lead to serious security vulnerabilities. By applying secure coding practices such as password hashing and input validation, the security of the application is significantly improved.

The task helped in understanding the importance of writing secure code and following best practices during software development.

---

## Final Outcome

* Insecure code successfully reviewed
* Security vulnerabilities identified
* Secure coding techniques applied
* Task completed as per requirements


