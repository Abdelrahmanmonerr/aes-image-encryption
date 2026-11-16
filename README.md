# AES Image Encryption (SCE 422e)

Python application for encrypting and decrypting images with AES in ECB, CBC and CTR modes
(OFB included as a bonus), with a GUI built using customtkinter.

## Setup
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```
python gui_app.py
```

## Files
- `aes_core.py`: key generation, encryption and decryption logic (pycryptodome)
- `gui_app.py`: GUI application
- `test_core.py`: command-line test (encrypt then decrypt all modes)
- `images/`: the two test plaintext images
