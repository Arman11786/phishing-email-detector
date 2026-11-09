# AI Phishing Email Detector

A small web app that checks email text and tells you whether it looks like **phishing** or **legitimate**, and explains why.

Built as my final year project for my BSc (Hons) Cyber Security degree.

## How it works

It uses a hybrid approach, so a decision is never just a yes or no:

1. **TF-IDF** turns the email text into numbers, giving more weight to words that help tell phishing and normal emails apart.
2. **Logistic Regression** (scikit-learn) predicts the probability that the email is phishing.
3. **Rule-based checks** look for common phishing signs the model can miss:
   - urgent or pressuring wording
   - requests for passwords, logins, OTPs or verification codes
   - financial and payment wording
   - account threats (suspended, locked, disabled)
   - links and risky attachment types (.zip, .exe, .js and others)
   - lots of exclamation marks
4. **Final risk score** combines the model probability with the rule-based indicators, and lowers it slightly for normal business wording to cut false alarms. A score of 50% or more is labelled phishing.

The app has three tabs: **Email Analysis**, **Model Testing** (metrics and confusion matrix) and **System Explanation**.

## Results

Evaluated on a held-out 25% test split (stratified) of the dataset:

| Metric    | Score  |
|-----------|--------|
| Accuracy  | 95.00% |
| Precision | 100.00% |
| Recall    | 90.00% |
| F1 score  | 94.74% |

Dataset: 80 short emails, 40 phishing and 40 legitimate.

## Limitations

- The dataset is very small and the emails are short, so these scores are a prototype result and not proof of real-world performance.
- The rule-based checks are keyword based, so a carefully worded phishing email could get past them.
- It only reads email text. It does not check headers, sender addresses or where links actually go.

Missing a phishing email is worse than a false alarm, so recall is the main number to improve. The next step would be a much larger and more varied dataset.

## How to run

1. Install Python 3 and the requirements:
   ```
   pip install -r requirements.txt
   ```
2. Keep `emails.csv` in the same folder as `app.py`.
3. In a terminal in that folder, run:
   ```
   python3 -m streamlit run app.py
   ```
4. Your browser opens the app automatically.

## Files

- `app.py`: the app, model training and rule-based checks
- `emails.csv`: the dataset (`text`, `label` where 1 = phishing and 0 = legitimate)
- `requirements.txt`: Python packages needed

## Built with

Python, Streamlit, scikit-learn, pandas
