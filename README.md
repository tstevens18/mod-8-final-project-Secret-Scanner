Purpose:

My application is designed to help identify hardcoded secrets inside project files or directories using regex-based scanning. Hardcoded secrets create major security risks because they can expose credentials, tokens, or private keys directly in source code. My application provides a simple command-line tool that detects these issues early so they can be removed before deployment or version-control commits.

Detection Logic:

My application scans each file line by line and applies a set of regular expression patterns that represent common secret types. These patterns allow my application to locate sensitive values based on structure rather than exact wording, which helps catch a variety of formats.

The detection logic focuses on the following categories:

AWS Keys
My application detects AWS Access Key IDs by checking for the required format of “AKIA” followed by sixteen uppercase alphanumeric characters. It also detects AWS Secret Access Keys by searching for the phrase “aws_secret_access_key” near a 40-character base64-like string.

Generic API Keys
My application looks for several variations of API key variables, such as “api_key,” “api-key,” or “apikey,” and checks whether they are assigned long alphanumeric tokens that resemble real keys.

Hardcoded Passwords
My application identifies passwords stored directly in the code by examining assignments such as “password,” “passwd,” or “pwd” where the value appears inside quotes.

JWT Tokens
My application locates JSON Web Tokens by detecting their standard structure of three encoded segments separated by periods, commonly seen in authentication systems.

Private Key Blocks
My application recognizes PEM-formatted private keys by detecting headers such as “-----BEGIN PRIVATE KEY-----,” which typically indicate embedded RSA or similar private keys.

When any pattern matches, my application records the filename, line number, matched pattern, and the matched string, then displays the results in a formatted report.

Usage:

My application is run entirely through the command line using argparse to manage input options. It can scan either a single file or an entire directory.

Scan a single file:
python secret_scanner.py secrets.txt

Scan a directory:
python secret_scanner.py path/to/folder

Scan all files (no extension filter):
python secret_scanner.py path/to/folder -e

Scan specific file types:
python secret_scanner.py project -e .py .env .txt

Enable detailed debug logging:
python secret_scanner.py project --log-level DEBUG


After running, my application prints a report showing each detected secret, including its file location and line number. If nothing is found, it outputs a confirmation message stating that no potential secrets were detected.

Limitations:

Although my application uses structured regex patterns, regex-based scanning cannot detect every possible secret. Some secrets may use uncommon formats, appear in binary files, or be intentionally obfuscated. In addition, certain values may trigger false positives if they resemble real secret formats. The purpose of this tool is to assist with early detection, not to guarantee complete security coverage.

How to Run the Tool:

To run my application, install Python 3, save the secret_scanner.py file in your project folder, and use a terminal or command prompt to execute scan commands. Provide a file or directory path as input, and my application will automatically begin scanning and display results once complete.
