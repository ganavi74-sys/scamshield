# ScamShield - AI-Assisted Scam & Phishing Detection

ScamShield is a web-based application designed to identify potentially fraudulent messages and help users recognize common online scams.

It combines **rule-based detection** with an experimental **Machine Learning model** to analyze suspicious text and provide risk assessments.

## Features

- **Message Analysis:** Analyze SMS messages, WhatsApp messages, emails, and other text.
- **Rule-Based Detection:** Identify suspicious patterns such as urgency, requests for sensitive information, financial references, and suspicious links.
- **Machine Learning Integration:** Uses a TF-IDF vectorizer and Logistic Regression classifier to provide an additional scam prediction.
- **Risk Assessment:** Displays a risk score and risk level (SAFE, LOW, MEDIUM, or HIGH).
- **Explanations:** Shows detected indicators and recommendations.
- **Analysis History:** Keeps recent analysis results in the browser.
- **Flask API:** Provides a backend endpoint for message analysis.

## Technologies Used

- Python
- Flask
- Flask-CORS
- Scikit-learn
- TF-IDF Vectorization
- Logistic Regression
- Joblib
- HTML, CSS, and JavaScript

## Project Structure

```text
ScamShield/
│
├── backend/
│   ├── app.py
│   ├── routes/
│   └── services/
│
├── frontend/
│   └── index.html
│
├── ml/
│   ├── training_data.csv
│   ├── evaluation_data.csv
│   ├── train_model.py
│   ├── test_model.py
│   ├── evaluate_model.py
│   └── scam_model.joblib
│
├── database/
├── requirements.txt
└── test_api.py
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone <https://github.com/ganavi74-sys/scamshield.git>
cd ScamShield
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment (Windows PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Start the backend

From the project root:

```powershell
python .\backend\app.py
```

The backend runs at:

`http://127.0.0.1:5000`

### 6. Start the frontend

Open a second terminal:

```powershell
cd frontend
python -m http.server 5500
```

Open the application in your browser:

`http://127.0.0.1:5500/`

## Testing

Run these commands from the project root.

### Rule-based detector tests

```powershell
python .\backend\test_scam_detector.py
```

### Machine Learning sample tests

```powershell
python .\ml\test_model.py
```

### Independent evaluation

```powershell
python .\ml\evaluate_model.py
```

### API integration test

Keep the Flask backend running in another terminal, then execute:

```powershell
python .\test_api.py
```

## Machine Learning Approach

The machine learning component uses:

- **TF-IDF:** Converts text messages into numerical features.
- **Logistic Regression:** Classifies messages into SAFE or SCAM categories.
- **Joblib:** Saves and loads the trained model.

The model is trained using a manually prepared dataset. A separate evaluation dataset is used to test its predictions.

## Evaluation and Limitations

In the current independent evaluation, the model correctly classified all 12 clear test messages in the small evaluation dataset.

This result is preliminary and does **not** represent guaranteed real-world accuracy.

Borderline messages are evaluated separately because some messages require additional context to determine whether they are fraudulent.

ScamShield is an educational project and a prototype. Its predictions should be treated as guidance, not as a guarantee that a message is safe or fraudulent. It is not a replacement for security software or professional investigation.

## Future Improvements

- Expand the training and evaluation datasets.
- Improve detection of borderline and context-dependent messages.
- Reduce false positives and false negatives.
- Improve model performance using larger and more diverse datasets.
- Add further security analysis features.

## Project Purpose

ScamShield was developed as a learning project to explore Python, web development, machine learning, and cybersecurity concepts through a practical scam-detection application.