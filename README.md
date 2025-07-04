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


*USES OF THE ADVANCED FILE ENCRYPTION TOOL:*
1. Personal Data Protection
Encrypt sensitive files like ID proofs, medical records, or financial documents to prevent unauthorized access.

2. Secure File Sharing
Share confidential files safely over email or cloud by encrypting them first and sharing the password separately.

3. Academic Use
Students and teachers can encrypt exam papers, research data, and reports to maintain privacy and integrity.

4. Business & Legal
Companies and law firms can secure contracts, client records, and internal documents with strong AES-256 encryption.

5. IT & Developer Use
Protect config files, API keys, or deployment scripts by encrypting them before storing or uploading.

6. Backup Security
Encrypt backup files before saving them to external drives or cloud to ensure data remains protected even if lost or leaked.

##*output:*##

![Image](https://github.com/user-attachments/assets/0db82d26-c347-4451-8e3d-f03696edf024)

![Image](https://github.com/user-attachments/assets/4a91d9a8-272d-4c1e-b0ba-73ad0b6dd042)

![Image](https://github.com/user-attachments/assets/4b609b2e-272c-4a9b-b1f4-0d9d573acffb)

![Image](https://github.com/user-attachments/assets/ea60474a-e2f3-4890-b5cc-c662f603506e)


