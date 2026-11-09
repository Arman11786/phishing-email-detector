import re
import pandas as pd
import streamlit as st

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


@st.cache_resource

def train_model():
    
    data = pd.read_csv ("emails.csv")

    data = data.dropna (subset=["text", "label"])

    email_texts = data ["text"]

    email_labels = data ["label"]

    vectorizer = TfidfVectorizer(stop_words="english", lowercase=True, max_features=3000)

    email_features = vectorizer.fit_transform(email_texts)

    X_train, X_test, y_train, y_test = train_test_split(

        email_features,

        email_labels,

        test_size=0.25,

        random_state=42,

        stratify=email_labels

    )


    model = LogisticRegression(max_iter=1000)

    model.fit(X_train, y_train)

    test_predictions = model.predict(X_test)

    parameters = {

        "accuracy": accuracy_score(y_test, test_predictions),

        "precision": precision_score(y_test, test_predictions, zero_division=0),

        "recall": recall_score(y_test, test_predictions, zero_division=0),

        "f1": f1_score(y_test, test_predictions, zero_division=0),

        "confusion_matrix": confusion_matrix(y_test, test_predictions),

        "dataset_size": len(data),

        "phishing_count": int((data["label"] == 1).sum()),

        "legitimate_count": int((data["label"] == 0).sum())

    }

    return model, vectorizer, parameters


def check_words(text, word_list):

    for word in word_list:
        if word in text:

            return True

    return False


def detect_phishing_indicators(email_text):

    text = email_text.lower()

    indicators = []

    risk_adjustment = 0.0

    urgent_words = ["urgent", "immediately", "asap", "now", "warning", "final warning"]

    credential_words = ["login", "password", "verify", "confirm", "credentials", "sign in", "otp", "one time password", "code", "verification code"]

    financial_words = ["bank", "payment", "invoice", "transfer", "billing", "refund", "transaction", "money", "send money", "pay", "card", "account number"]

    account_words = ["account", "suspended", "limited", "locked", "disabled", "deactivated"]



    if check_words(text, urgent_words):
        indicators.append("Uses urgent / pressuring language")
        risk_adjustment += 0.10

    if check_words(text, credential_words):
        indicators.append("Requesting: login, password, OTP or verification details")
        risk_adjustment += 0.12

    if check_words(text, financial_words):
        indicators.append("Mentions: financial, payment or money related information")
        risk_adjustment += 0.10

    if "otp" in text or "one time password" in text or "verification code" in text:
        indicators.append("Requests OTP / verification code")
        risk_adjustment += 0.25

    if check_words(text, account_words):
        indicators.append("Mentions: account threats or restricted access")
        risk_adjustment += 0.10

    if re.search(r"http|https|www\.|click here|bit\.ly|tinyurl", text):
        indicators.append("Contains a suspicious url link / link phrase")
        risk_adjustment += 0.10

    if re.search(r"\.(zip|exe|scr|js|rar|docm|xlsm|bat|cmd)", text):
        indicators.append("Mentions a risky type of attachment")
        risk_adjustment += 0.08

    if text.count("!") >= 2:
        indicators.append("Contains a lot of punctuation, which might create an urgency")
        risk_adjustment += 0.05


    return indicators, risk_adjustment


def detect_safe_indicators(email_text):

    text = email_text.lower()

    safe_indicators = []

    meeting_words = ["meeting", "agenda", "schedule", "minutes", "appointment"]

    business_words = ["client", "customer", "supplier", "team", "department", "proposal"]

    document_words = ["attached", "review", "comments", "approved", "confirmed", "report"]

    date_words = ["monday", "tuesday", "wednesday", "thursday", "friday", "tomorrow"]

    if check_words(text, meeting_words):
        safe_indicators.append("Meeting / scheduling language detected")

    if check_words(text, business_words):
        safe_indicators.append("Normal business communication detected")

    if check_words(text, document_words):
        safe_indicators.append("Document / review related wording detected")

    if check_words(text, date_words):
        safe_indicators.append("Date / planning language detected")



    return safe_indicators




def analyse_email(user_email, model, vectorizer):

    user_features = vectorizer.transform([user_email])

    prediction_probabilities = model.predict_proba(user_features)

    ml_probability = prediction_probabilities[0][1]

    phishing_indicators, risk_adjustment = detect_phishing_indicators(user_email)

    safe_indicators = detect_safe_indicators(user_email)

    final_risk = ml_probability + risk_adjustment

    if len(phishing_indicators) == 0:
        final_risk -= 0.15

    final_risk -= len(safe_indicators) * 0.05

    final_risk = max(0.0, min(1.0, final_risk))

    if final_risk >= 0.50:

        final_label = "Phishing"

    else:

        final_label = "Legitimate"

    result = {

        "prediction": final_label,

        "ml_probability": ml_probability,

        "final_risk": final_risk,

        "phishing_indicators": phishing_indicators,

        "safe_indicators": safe_indicators


    }



    return result


def show_email_analysis_tab(model, vectorizer):

    st.markdown("<br>", unsafe_allow_html=True)

    st.header("Email Analysis")

    st.write("")

    user_email = st.text_area("Paste text below:", height=230, width=500)


    if st.button("Analyse Email"):

        if user_email.strip() == "":

            st.warning("Please enter some text.")

        else:

            result = analyse_email(user_email, model, vectorizer)

            st.write("")
            st.write("")

            st.subheader("Analysis Result")

            st.write("")

            col1, col2, col3 = st.columns(3)

            col1.metric("Prediction", result["prediction"])

            col2.metric("ML Phishing Probability", f"{result['ml_probability'] * 100:.2f}%")

            col3.metric("Final Risk Score", f"{result['final_risk'] * 100:.2f}%")

            if result["prediction"] == "Phishing":

                st.error("This Email is likely to be Phishing.")


            else:


                st.success("This Email is most likely legitimate.")


            st.subheader("Phishing Indicators Found")

            if result["phishing_indicators"]:
                for item in result["phishing_indicators"]:
                    st.write(f"- {item}")


            else:


                st.write("No strong Phishing indicators detected.")



            st.subheader("Legitimate Indicators Found")

            if result["safe_indicators"]:
                for item in result["safe_indicators"]:
                    st.write(f"- {item}")


            else:


                st.write("No clear legitimate indicators detected.")




def show_model_testing_tab(parameters):

    st.header("Model Testing Results")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Accuracy", f"{parameters['accuracy'] * 100:.2f}%")

    col2.metric("Precision", f"{parameters['precision'] * 100:.2f}%")

    col3.metric("Recall", f"{parameters['recall'] * 100:.2f}%")

    col4.metric("F1 Score", f"{parameters['f1'] * 100:.2f}%")



    st.subheader("Dataset Summary")

    st.write(f"Total Emails: {parameters['dataset_size']}")

    st.write(f"Phishing Emails: {parameters['phishing_count']}")

    st.write(f"Legitimate Emails: {parameters['legitimate_count']}")


    st.subheader("Confusion Matrix")

    st.write(

        "The confusion matrix below shows how the model tested the split of 25%, on the dataset. "
        "Results do not change when a user types or pastes new Email, because new Email input is analysed separately. "
        "It is also not saved into either training or testing dataset."
    )

    confusion_matrix_table = pd.DataFrame(
        
        parameters["confusion_matrix"],

        index=["Actual Legitimate", "Actual Phishing"],

        columns=["Predicted Legitimate", "Predicted Phishing"]


    )



    st.dataframe(confusion_matrix_table, use_container_width=True)

    st.write(

        "The top left value shows Legitimate Emails, which are predicted to Legitimate. "
        "The bottom right value shows Phishing Emails, which are predicted to Phishing. "
        "The other two values display incorrect predictions."


    )



def show_system_explanation_tab():

    st.header("System Explanation")

    st.write(

        "The system uses a hybrid Phishing Detection method. "
        "Innitially, the email text is converted into numerical features; using TF-IDF. "
        "TF-IDF helps the model in identifying important words in the text."

    )

    st.write(

        "Logistic Regression is then used to class the Email to Phishing or Legitimate. "
        "This model was chosen because, Phishing detection is a binary classification issue."

    )

    st.write(

        "Rule Based checks are also used in identifying clear Phishing signs, such as: urgent wording, "
        "password requests, suspicious links, OTP requests, financial words, account related threats, "
        "risky attachments and overpunctuation."

    )

    st.write(

        "The Final Risk Score combines both Machine Learning probability and Rule Based indicators. "
        "Safe indicators can reduce the score less, in order to avoid false positives."

    )


st.set_page_config(page_title="AI Phishing Email Detector", layout="wide")

st.title("AI Phishing Email Detector")

st.write("The system analyses text from Emails using TF-IDF, Logistic Regression and a Rule Based Phishing checker.")

st.write("")
st.write("")

model, vectorizer, parameters = train_model()

tab1, tab2, tab3 = st.tabs(["Email Analysis", "Model Testing", "System Explanation"])


with tab1:
    show_email_analysis_tab(model, vectorizer)


with tab2:
    show_model_testing_tab(parameters)
    

with tab3:
    show_system_explanation_tab()