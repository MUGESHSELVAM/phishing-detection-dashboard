# CyberShield – Phishing Detection Dashboard

A Flask-based phishing detection system with:
- Login authentication
- Rule-based phishing detection
- DNS domain validation
- File-based scan history
- SOC-style dashboard UI

## How to Run
```bash
pip install flask flask-cors
python app.py


Structured Repositories


phishing-url-detector/
│
├── app.py                     # Main Flask application
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── scan_history.json          # Stores scan results / history
├── .gitignore                 # Git ignore rules
│
├── models/
│   └── phishing_model.pkl     # Trained ML model
│
├── utils/
│   ├── feature_extractor.py   # URL feature extraction logic
│   └── __pycache__/           # Python cache files
│
├── templates/
│   └── index.html             # Frontend HTML (Flask template)
│
├── static/
│   ├── style.css              # CSS styles
│   └── script.js              # Frontend JavaScript
│
├── venv/                      # Virtual environment (not pushed to Git)
│   ├── Include/
│   ├── Lib/
│   ├── Scripts/
│   └── pyvenv.cfg
│
└── .gitignore                 # Ensure venv/, __pycache__/ ignored
