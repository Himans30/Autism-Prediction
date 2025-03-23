# Autism Prediction System

## 📌 Project Description
The **Autism Prediction System** is a web-based application that allows users to predict the risk of autism based on input features. It includes user authentication, an admin panel for managing users and logs, and a prediction model trained with machine learning.

## 🚀 Features
- **User Authentication**: Secure login and registration system with password hashing.
- **Autism Prediction**: Users can input relevant data to receive predictions.
- **Admin Panel**: Manage users and view prediction logs.
- **Database Logging**: Stores prediction results along with timestamps.
- **Modern UI**: Styled interface with Streamlit for ease of use.

## 📂 Project Structure
```
📁 autism-prediction-system
│-- 📄 main.py                 # Main application script
│-- 📄 best_model.pkl          # Trained ML model
│-- 📄 encoders.pkl            # Encoders for categorical variables
│-- 📄 users.db                # SQLite database
│-- 📄 requirements.txt        # Required dependencies
│-- 📄 README.md               # Project documentation
```

## 🛠️ Installation
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/autism-prediction.git
cd autism-prediction
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Application
```bash
streamlit run main.py
```

## ⚙️ Dependencies
Ensure you have the following installed:
```txt
streamlit
bcrypt
sqlite3
pandas
scikit-learn
pickle-mixin
```

## 📊 How It Works
1. Users register and log in.
2. Input relevant data (scores, age, gender, etc.).
3. Click "Predict" to get autism risk assessment.
4. Admins can manage users and view logs.

## 👨‍💻 Contributing
Feel free to fork the repo and submit pull requests for improvements!

## 📞 Contact
For queries, reach out at my Linkedin [https://www.linkedin.com/in/himanshuyadav30/]).

