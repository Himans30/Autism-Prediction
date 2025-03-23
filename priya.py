import bcrypt
import sqlite3
import pickle
import pandas as pd
import streamlit as st


# Load trained model & encoders
with open("best_model.pkl", "rb") as f:
    best_model = pickle.load(f)

with open("encoders.pkl", "rb") as f:
    encoders = pickle.load(f)

# Initialize SQLite
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
''')
conn.commit()

# Create logs table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        prediction_result TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
conn.commit()

# Session state
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""
if "role" not in st.session_state:
    st.session_state["role"] = ""

# Register User
def register_user(username, password, role="user"):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

# Authenticate User
def authenticate(username, password):
    cursor.execute("SELECT password, role FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode(), user[0]):
        st.session_state["authenticated"] = True
        st.session_state["username"] = username
        st.session_state["role"] = user[1]
        st.rerun()
    else:
        st.error("❌ Invalid username or password.")

# Logout User
def logout():
    st.session_state["authenticated"] = False
    st.session_state["username"] = ""
    st.session_state["role"] = ""
    st.rerun()

# Sidebar Navigation
st.sidebar.title("Navigation")
menu_options = ["Home", "Sign In", "Sign Up", "Autism Prediction", "About Us", "Contact Us"]

if st.session_state.get("authenticated", False):
    if st.session_state.get("role") == "admin":
        menu_options.append("Admin Panel")
    menu_options.append("Logout")

selected = st.sidebar.radio("WELCOME", menu_options)

# Home Page
if selected == "Home":
    st.title("🏡 Welcome to Autism Prediction System")

# Sign In Page
elif selected == "Sign In":
    st.title("🔐 Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        authenticate(username, password)

# Sign Up Page
elif selected == "Sign Up":
    st.title("📝 Sign Up")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    if st.button("Register"):
        if register_user(new_username, new_password):
            st.success("✅ Account created successfully! Please sign in.")
        else:
            st.error("❌ Username already exists.")

# Autism Prediction Page
elif selected == "Autism Prediction":
    if not st.session_state.get("authenticated", False):
        st.warning("⚠️ Please sign in to access this feature.")
    else:
        st.title("🧠 Autism Prediction")
        input_data = {
            'A1_Score': st.number_input('A1 Score', min_value=0, max_value=1, value=0),
            'A2_Score': st.number_input('A2 Score', min_value=0, max_value=1, value=0),
            'A3_Score': st.number_input('A3 Score', min_value=0, max_value=1, value=0),
            'A4_Score': st.number_input('A4 Score', min_value=0, max_value=1, value=0),
            'A5_Score': st.number_input('A5 Score', min_value=0, max_value=1, value=0),
            'A6_Score': st.number_input('A6 Score', min_value=0, max_value=1, value=0),
            'A7_Score': st.number_input('A7 Score', min_value=0, max_value=1, value=0),
            'A8_Score': st.number_input('A8 Score', min_value=0, max_value=1, value=0),
            'A9_Score': st.number_input('A9 Score', min_value=0, max_value=1, value=0),
            'A10_Score': st.number_input('A10 Score', min_value=0, max_value=1, value=0),
            'age': st.number_input('Age', min_value=1, max_value=100, value=25),
            'gender': st.selectbox('Gender', ['m', 'f']),
            'ethnicity': st.selectbox('Ethnicity', ['White-European', 'Asian', 'Black', 'Hispanic', 'Other']),
            'jaundice': st.selectbox('Jaundice', ['yes', 'no']),
            'austim': st.selectbox('Autism in Family', ['yes', 'no']),
            'contry_of_res': st.text_input('Country of Residence', 'United States'),
            'used_app_before': st.selectbox('Used Screening App Before', ['yes', 'no']),
            'result': st.number_input('Screening Test Score', min_value=0, max_value=10, value=5),
            'relation': st.selectbox('Relation', ['Self', 'Family Member', 'Others'])
        }
        
        input_df = pd.DataFrame([input_data])
        for column in encoders:
            if column in input_df.columns:
                input_df[column] = encoders[column].transform(input_df[column])

        if st.button("🔍 Predict Autism Risk"):
            prediction = best_model.predict(input_df)
            result_text = "🚨 High Risk of Autism" if prediction[0] == 1 else "✅ Low Risk of Autism"
            st.success(result_text)

            # Log the prediction
            cursor.execute("INSERT INTO logs (username, prediction_result) VALUES (?, ?)",
                           (st.session_state["username"], result_text))
            conn.commit()

# Admin Panel
elif selected == "Admin Panel":
    if st.session_state.get("authenticated", False) and st.session_state.get("role") == "admin":
        st.title("🔧 Admin Panel")

        # Manage Users
        st.subheader("👤 User Management")
        cursor.execute("SELECT id, username, role FROM users")
        users = cursor.fetchall()

        for user in users:
            col1, col2, col3 = st.columns([3, 2, 2])
            col1.write(f"**{user[1]}** ({user[2].capitalize()})")

            # Change Role
            new_role = col2.selectbox(f"Role for {user[1]}", ["user", "admin"], index=0 if user[2] == "user" else 1)
            if col2.button(f"Update {user[1]}", key=f"role_{user[0]}"):
                cursor.execute("UPDATE users SET role=? WHERE id=?", (new_role, user[0]))
                conn.commit()
                st.success(f"✅ Role updated for {user[1]}")
                st.rerun()

            # Delete User
            if col3.button(f"❌ Delete {user[1]}", key=f"delete_{user[0]}"):
                cursor.execute("DELETE FROM users WHERE id=?", (user[0],))
                conn.commit()
                st.warning(f"⚠️ Deleted {user[1]}")
                st.rerun()

        # View Logs
        st.subheader("📊 Prediction Logs")
        cursor.execute("SELECT username, prediction_result, timestamp FROM logs ORDER BY timestamp DESC")
        logs = cursor.fetchall()

        logs_df = pd.DataFrame(logs, columns=["Username", "Prediction Result", "Timestamp"])
        st.dataframe(logs_df)

    else:
        st.warning("❌ Access Denied. Admins only.")

# About Us Page
elif selected == "About Us":
    st.title("ℹ️ About Us")

# Contact Us Page
elif selected == "Contact Us":
    st.title("📞 Contact Us")

# Logout
elif selected == "Logout":
    logout()
