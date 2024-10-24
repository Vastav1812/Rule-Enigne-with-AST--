# **Rule Engine Application**

### **Objective**

This application allows users to create, evaluate, and combine rules in real-time. The rules are designed in the form of Abstract Syntax Trees (AST), which supports operations like AND, OR, and comparisons such as greater than, less than, equals, etc. The rules are stored and evaluated based on user input.

---

### **Features**

- **Rule Creation**: 
  - Users can create rules using simple comparison operations (e.g., `age > 30` or `department = 'Sales'`).
  
- **Rule Evaluation**:
  - Created rules can be evaluated based on user data.
  - Rules can handle various operators like `>`, `<`, `=`, `>=`, `<=`, and logical operators `AND`, `OR`.

- **Rule Combination**:
  - Users can combine multiple rules using logical operators `AND` and `OR`.

- **Database Integration**:
  - All rules are stored in an SQLite database with their Abstract Syntax Trees (AST) serialized in JSON format.

---

### **Technologies Used**

- **Flask**: Web framework for API and WebSocket server
- **Flask-SQLAlchemy**: ORM for database interactions
- **Flask-SocketIO**: WebSocket handling for real-time communication
- **SQLite**: Database
- **Docker**: For containerizing the application and its dependencies

---

### **API and WebSocket Endpoints**

#### **Rule WebSocket Commands**:
1. **Create Rule**: 
   - Command: `"create rule: <rule_string>"`
   - Example: `"create rule: age > 30"`

2. **Evaluate Rule**: 
   - Command: `"evaluate rule: <rule_id>: <user_data>"`
   - Example: `"evaluate rule: rule1: {'age': 35}"`

3. **Combine Rules**: 
   - Command: `"combine rules: <rule1, rule2>: <operator>"`
   - Example: `"combine rules: rule1, rule2: AND"`

#### **HTTP API Endpoints**:
1. **View All Rules**: `GET /rules`
   - Displays all rules created and stored in the database.
   
2. **Clear All Rules**: `POST /clear_rules`
   - Clears all rules from the database.

---

### **Data Validation**

- The application validates the format of user data when evaluating rules.
- Conditions must follow the proper format (e.g., `age > 30`, `department = 'Sales'`).
- User input for evaluation is validated for correct JSON structure.

---

### **Installation and Setup**

#### **1. Clone the repository**:
```bash
git clone https://github.com/your-username/rule-engine-app.git
cd rule-engine-app
```
----

### **Set up the virtual environment:**
```bash
python3 -m venv rule_engine_env
source rule_engine_env/bin/activate  # For Linux/Mac
rule_engine_env\Scripts\activate  # For Windows
```

### **Install dependencies:**
```bash
Copy code
pip install -r requirements.txt
```
