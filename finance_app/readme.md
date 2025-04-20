# MyFinance Inc. Secure System

This is a secure Django-based application for managing investment portfolios, demonstrating encryption, key rotation, user authentication, and more.

## Requirements

- Python 3.12+ (required due to quantcrypt limitations)
- A supported OS (Windows, macOS, or Linux)

## Installation & Setup

1. **Create and activate a virtual environment**  
   ```bash
   python -m venv venv

   # Activate the virtual environment (for macOS/Linux)
   source venv/bin/activate

   # Activate the virtual environment (for Windows)
   venv\Scripts\activate


2. **Install the Dependencies**
   From the project root (where `manage.py` and `requirements.txt` reside), install dependencies:
   ```bash
   pip install -r requirements.txt

2. **Run test scripts**
   ```bash
   python manage.py test --keepdb
   
3. **Load Webpage**
   ```bash
   python runsslserver.py

   Visit https://127.0.0.1:8000 

4. **Login to the Users**
   USERNAME:PASSWORD
   admin:Secure_P@$$word123
   advisor:Secure_P@$$word123
   user:Secure_P@$$word123