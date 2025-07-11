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
Watch the 5-minute demo [here](https://screenrec.com/share/lrk6diKSvR).

## Deployed App
Access the live tool: [Website URL](https://kinyarwanda-hatespeech-detection.onrender.com/)

---

## 🧪 Testing Instructions

Use different inputs:
- Normal text
- Obvious hate speech
- Sarcastic or indirect phrases
- Long text paragraphs
- Empty input or gibberish
  
## Some testing results
<img width="634" height="400" alt="Screenshot 2025-07-11 230254" src="https://github.com/user-attachments/assets/a2e9894d-c029-47b9-a74e-7ead38a80f27" />

<img width="634" height="487" alt="Screenshot 2025-07-11 230315" src="https://github.com/user-attachments/assets/2204a4a8-91bb-45e1-a710-0c8d980609eb" />

<img width="1343" height="625" alt="Screenshot 2025-07-11 230430" src="https://github.com/user-attachments/assets/aab22242-4cb4-489d-b88b-e2fc8eda317e" />

# 📊 Results Analysis

Our initial project proposal aimed to create a hate speech detection system that is accurate, accessible, and practical for both users and moderators. We successfully met most of the defined objectives, as described below:

## ✅ Achieved Objectives

| Objective                              | Status    | Notes                                                                                     |
|--------------------------------------|-----------|-------------------------------------------------------------------------------------------|
| Develop a functional web platform for users       | ✅ Achieved | Users can input any text and receive instant feedback on whether it is hate speech or not. |
| Build a moderator dashboard           | ✅ Achieved | Moderators can review flagged content.             |
| Integrate real-time Chrome extension  | ✅ Achieved | Users can highlight text on any website and instantly analyze it via the extension.       |
| Deploy and test machine learning model| ✅ Achieved | The hate speech classifier returns results in a short time on average.                   |
| Test the system under different input types and environments | ✅ Achieved | Testing included normal text, hate speech, and sarcastic cases. |

## ⚠️ Missed / Partially Achieved Objectives

| Objective                  | Status               | Explanation                                                                                                          |
|----------------------------|----------------------|----------------------------------------------------------------------------------------------------------------------|
| Sarcasm detection | ❌ Not achieved      | It's still tricky when It comes to sarcastic/joke/edge cases. The model is flagging sarcasm as hate speech, and the next step is working on improving that particular functionality. |


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
