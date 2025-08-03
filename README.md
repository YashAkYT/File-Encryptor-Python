# File-Encryptor-Python

A simple command-line tool to securely encrypt and decrypt files using a master password. Your files are protected with strong encryption, and only you can decrypt them with your password.

## Installation

### 1. Clone the Repository

```sh
git clone https://github.com/YashAkYT/File-Encryptor-Python.git
cd File-Encryptor-Python
```

### 2. Windows

Simply run the batch file:

```sh
run.bat
```

This will set up a Python virtual environment, install dependencies, and launch the app.

### 3. Mac & Linux

1. Make sure you have Python 3.8+ installed.
2. Install dependencies:

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Run the app:

```sh
python3 main.py
```

## ⚠️ Warning

**Do not delete `salt.db` or `auth_test_file.bin`.**  
Deleting these files will reset the app and make it impossible to decrypt any files previously encrypted with your master password. Always keep backups of these files if you want to retain access to your encrypted data.