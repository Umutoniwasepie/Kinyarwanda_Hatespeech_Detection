# Kinyarwanda Hate Speech Detection App

A machine learning-powered app that detects **hate**, **offensive**, or **normal** speech in **Kinyarwanda** social media text using logistic regression. Also includes a **Chrome extension** (Developer Mode) for real-time classification.

---

## 🚀 Features

- ✅ Detects `hate`, `offensive`, or `normal` content in Kinyarwanda
- 🧠 Trained with Logistic Regression + TF-IDF
- 📊 Balanced dataset for fair classification
- 🌐 Web interface for testing input text
- 🧩 Chrome extension for live web integration

---

## 📁 Project Structure

```
project/
│
├── app.py #Flask app
|── README.md
|── Procfile
├── requirements.txt
├── .
|── static/css
|    ├── dashboard.css
|    ├── index.css
|    ├── login.css
|    ├── register.css
|    ├── moderator_dashboard.css
|    ├── verify.css
|    ├── forgot_password.css
|    ├── reset_password.css
├── templates/
|    ├── dashboard.html
|    ├── index.html
|    ├── login.html
|    ├── register.html
|    ├── moderator_dashboard.html
|    ├── verify.html
|    ├── forgot_password.html
|    ├── reset_password.html
├── model/
│   ├── hate_speech_model.ipynb  # Model Notebook
|   ├── kinyarwanda_hatespeech_noisy.csv
|   ├── final_dataset.tsv
|   ├── label_encoder.pkl
|   ├── model.pkl     # Trained logistic regression model
|   ├── tfidf.pkl     # TF-IDF vectorizer used during training
├── RHD_extension/    # Chrome extension source files
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── icon.png
│   └── content.js
│   ├── background.js
```

---

## 🛠️ Installation (Web App)

### Step 1: Clone the Repository

```bash
git clone https://github.com/Olamieee/kinyarwanda-hate-speech-app.git
cd kinyarwanda-hate-speech-app
```

### Step 2: Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 (Optional): Train the Model

Open the notebook:

```bash
jupyter notebook hate_speech_model.ipynb
```

This will:
- Merge + clean datasets
- Vectorize text
- Train logistic regression
- Export `model.pkl` & `tfidf.pkl`

### Step 5: Run the App

#### Run with Flask

```bash
python app.py
```

Visit the app at `http://localhost:5000` (default Flask port).

---

## 🧩 Chrome Extension (Developer Mode Only)

### Step 1: Load Unpacked Extension

1. Go to `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load Unpacked**
4. Select the `RHD_extension/` folder

### Step 2: Use the Extension

- Highlight Kinyarwanda text
- Click the extension icon in Chrome toolbar
- Click **Analyze**
- Classification result will display below

> Note: Extension communicates either with local server via `localhost` or deployed server via the url. Ensure the web app is running before using the extension.

---

## 🔍 Model Summary

- **Algorithm**: Logistic Regression (sklearn)
- **Feature Extraction**: TF-IDF (1–3 grams)
- **Accuracy**: ~95% on test data
- **Classes**: `hate`, `offensive`, `normal`

---

## Demo Video
Watch the 5-minute demo [here](video-link).

## Deployed App
Access the live tool: [Website URL](https://kinyarwanda-hatespeech-detection.onrender.com/)

---

🧪 Testing Instructions

Use different inputs:
- Normal text
- Obvious hate speech
- Sarcastic or indirect phrases
- Long text paragraphs
- Empty input or gibberish

---

## 🧪 Example Usage (Manual)

```python
import joblib

model = joblib.load("model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")

def predict(text):
    X = vectorizer.transform([text])
    return model.predict(X)[0]
```

---

## 🛡️ License

This project is licensed under the **MIT License**.

---
