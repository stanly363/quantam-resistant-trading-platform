'''
# MyFinance Inc. - Post-Quantum Secure Portfolio Manager 📈

MyFinance Inc. is a full-stack, secure web application built with **Django** for managing investment portfolios. It is designed with a security-first approach, featuring an implementation of **post-quantum cryptography** to ensure long-term data protection against emerging threats.

## Key Features ✨

* **Live Market Data**: Integrates with financial APIs to pull and display real-time prices for stocks, ETFs, and cryptocurrencies.

* **Performance Visualization**: Tracks your portfolio's performance over time with dynamic, interactive graphs and charts that visualize asset allocation and value growth.

* **Secure Portfolio Management**: Create, update, and manage multiple investment portfolios with detailed views of your holdings.

* **Advanced Security**: Employs cutting-edge security practices, including post-quantum cryptography and multi-factor authentication.

## Security Focus 🛡️

This project's primary goal is to demonstrate robust security in a financial application.

* **Post-Quantum Cryptography (PQC)**: Uses the **NIST-standard CRYSTALS-Kyber** algorithm via the `quantcrypt` library to encrypt sensitive user data, ensuring it remains secure even against future quantum computing attacks.

* **Multi-Factor Authentication (MFA)**: Secures user accounts with Time-Based One-Time Passwords (TOTP), compatible with apps like Google Authenticator.

* **Secure Development Lifecycle**: Adheres to best practices, including the use of environment variables for secrets, secure headers, and protection against common web vulnerabilities (OWASP Top 10).

## Technology Stack

* **Backend**: Python, Django

* **Database**: PostgreSQL (or other SQL database)

* **Security**: `django-sslserver`, `python-quantcrypt`

* **Frontend**: HTML, CSS, JavaScript (with a charting library like Chart.js)

## Requirements

* Python 3.12+

* A supported OS (Windows, macOS, or Linux)

## Installation & Setup

Follow these steps to get the application running locally.

### 1. Clone the Repository

```
git clone [https://github.com/your-username/MyFinance-Inc-Secure-System.git](https://github.com/your-username/MyFinance-Inc-Secure-System.git)
cd MyFinance-Inc-Secure-System

```

### 2. Create and Activate a Virtual Environment

```
# Create the environment
python -m venv venv

# Activate on macOS/Linux
source v'en'v/bin/activate

# Activate on Windows
venv\Scripts\activate

```

### 3. Install Dependencies

Install all required packages from the `requirements.txt` file.

```
pip install -r requirements.txt

```

### 4. Configure Environment Variables

Create a `.env` file in the project root. You can copy the provided `.env.example` file to get started.

```
cp .env.example .env

```

Now, **edit the `.env` file** to include your database connection details, a Django `SECRET_KEY`, and your SMTP server details for password reset emails.

### 5. Run Database Migrations

Apply the database schema and prepare the database for use.

```
python manage.py migrate

```

### 6. Create a Superuser

This command creates an administrative account that can access the Django admin panel.

```
python manage.py createsuperuser

```

You will be prompted to create a username, email, and password.

## Usage

### 1. Run the Secure Development Server

This project uses `django-sslserver` to run the development server over HTTPS.

```
python manage.py runsslserver

```

### 2. Access the Application

Once the server is running, visit **`https://127.0.0.1:8000`** in your web browser.

You can now:

* Register a new standard user account.

* Log in and begin creating and managing your investment portfolios.

* Access the Django admin panel at `/admin` using your **superuser** credentials.

## Running Tests

To run the application's test suite and ensure everything is working correctly, use the following command:

```
python manage.py test --keepdb

```
