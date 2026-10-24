# PhishShift - Message Risk Scanner

## Project Description
PhishShift is an educational web application that checks
messages for possible phishing indicators.

## Objectives
- Accept SMS, email, and chat message text.
- Identify suspicious wording and links.
- Apply a demonstration machine-learning model.
- Display a risk score and warning reasons.
- Store recent scans using SQLite.

## Technologies
- Python
- Flask
- HTML
- CSS
- Bootstrap
- JavaScript
- Scikit-learn
- Pandas
- Joblib
- SQLite
- VS Code

## Installation

1. Install Python.
2. Open this folder in VS Code.
3. Open the terminal.
4. Create a virtual environment:

   python -m venv .venv

5. Activate it in Windows PowerShell:

   .\.venv\Scripts\Activate.ps1

6. Install dependencies:

   python -m pip install -r requirements.txt

7. Run the application:

   python app.py

8. Open http://127.0.0.1:5000

## Testing

Run:

python -m unittest discover -s tests -v

## Limitations
The built-in dataset is small and synthetic.
The model may misclassify messages. A low score does not
prove that a message or website is safe.

Do not enter real passwords, OTPs, financial details,
or confidential messages.