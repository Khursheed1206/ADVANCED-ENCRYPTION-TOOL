# ADVANCED-ENCRYPTION-TOOL

*COMPANY*:CODTECH IT SOLUTIONS

*NAME*: KHURSHEED JAHAN

*INTERN ID*: CT04DF2054

*DOMAIN*: CYBER SECURITY AND ETHICAL HACKING

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH


##DESCRIPTION##
*ADVANCED FILE EMCRPTION TOOL*:
The Advanced File Encryption Tool is a secure desktop application built using Python, designed to allow users to encrypt and decrypt files using the AES-256 encryption algorithm. This ensures robust data protection for sensitive files, making it an ideal utility for users who prioritize data confidentiality and file-level security.

*PLATFORM AND ENVIRONMENT*:
The project was developed on the Windows operating system using PyCharm as the integrated development environment (IDE). PyCharm provided code auto-completion, debugging features, and project structuring that helped streamline the development process.
A virtual environment (.venv) was set up within the PyCharm project to manage Python packages and dependencies independently from the system Python installation. This ensures consistency and reproducibility across different systems.

*TOOLS AND LIBRARIES*:
Python 3.x – The core programming language used to build the entire application.

Tkinter – Python’s built-in GUI library was used to create a simple and user-friendly interface for encrypting and decrypting files.

cryptography – A powerful third-party library used to implement AES-256 encryption and decryption. It provides cryptographic recipes and primitives that ensure data is handled securely.

os & filedialog – Used to navigate the file system and select files for processing.

*ENCRYPTION AND DECRYPTION PROCESS*:
The application uses AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode with a 256-bit key, which is derived securely from a user-provided password using PBKDF2HMAC (Password-Based Key Derivation Function 2).

Encryption:
Users select a file via the GUI.
They enter a password, which is used to generate a cryptographic key.
A random salt and initialization vector (IV) are generated and prepended to the encrypted file.
The file content is padded using PKCS7, encrypted using AES-256, and saved as a new file with the .enc extension.

Decryption:
Users select the .enc file and enter the same password.
The tool extracts the salt and IV, regenerates the key, and decrypts the content.
After removing padding, the original file is saved in its original format (e.g., .txt, .pdf, .png).
Error handling is built into the UI to alert users of incorrect passwords, invalid file formats, or decryption issues.

User Interface:
The graphical interface allows even non-technical users to:
Select files for encryption or decryption using file dialog.
Enter passwords in a masked input field.
Get clear success or error messages through pop-up alerts.
Buttons are labeled intuitively as "Encrypt File" and "Decrypt File", making the tool extremely accessible.

*PROJECT STRUCTURE:*

project/
├── main.py            # Entry point to run the application
├── ui.py              # Contains GUI logic
├── encryption.py      # AES logic for encryption/decryption
├── requirements.txt   # Dependencies
└── .venv/             # Virtual environment (excluded from sharing)
