from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send
import json
from datetime import datetime
from rule_engine import Node, create_rule, evaluate_rule, combine_rules

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rules.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Database model for rules
class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String(50), unique=True, nullable=False)
    rule_ast = db.Column(db.Text, nullable=False)  # Store AST as JSON
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# Initialize the database within the application context
with app.app_context():
    db.create_all()

# Store rules in memory for the current session
rules = {}

@app.route('/')
def index():
    return render_template('chat.html')

@app.route('/rules', methods=['GET'])
def get_rules():
    rules = Rule.query.all()
    rules_list = [{"rule_id": rule.rule_id, "rule_ast": rule.rule_ast, "created_at": rule.created_at} for rule in rules]
    return render_template('rules.html', rules=rules_list)

@app.route('/clear_rules', methods=['POST'])
def clear_rules():
    try:
        # Clear all rules from the database
        db.session.query(Rule).delete()  # Deletes all entries in the Rule table
        db.session.commit()  # Commit the changes
        return jsonify({"message": "All rules cleared successfully."}), 200
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({"error": str(e)}), 500


# Helper function to convert dictionary to Node (AST)
def dict_to_node(data):
    """
    Recursively converts a dictionary (representing an AST) back into a Node object.
    :param data: The dictionary to convert (e.g., from a JSON AST).
    :return: A Node object.
    """
    if data is None:
        return None

    # Create the Node object from the dictionary
    node_type = data.get('node_type')
    value = data.get('value')
    left = dict_to_node(data.get('left'))  # Recursively convert the left child
    right = dict_to_node(data.get('right'))  # Recursively convert the right child

    return Node(node_type=node_type, value=value, left=left, right=right)


@socketio.on('message')
def handle_message(msg):
    print(f"Received message: {msg}")

    try:
        # Handle 'create rule' command
        if 'create rule' in msg.lower():
            rule_string = msg.split("create rule: ")[1]
            ast = create_rule(rule_string)  # Create the AST for the new rule
            rule_ast_json = json.dumps(ast, default=lambda o: o.__dict__)  # Serialize the AST

            # Check if a similar rule (same logic) already exists in the database
            existing_rule = Rule.query.filter_by(rule_ast=rule_ast_json).first()

            if existing_rule:
                send(f"Error: A rule with the same logic already exists as '{existing_rule.rule_id}'.")
            else:
                last_rule = Rule.query.order_by(Rule.id.desc()).first()
                rule_id = f"rule{last_rule.id + 1 if last_rule else 1}"

                rules[rule_id] = ast

                # Store the new rule in the database
                new_rule = Rule(rule_id=rule_id, rule_ast=rule_ast_json)
                db.session.add(new_rule)
                db.session.commit()

                print(f"Rule saved: {rule_id} - AST: {rule_ast_json}")
                send(f"Rule created: {rule_id}")

        # Handle 'evaluate rule' command
        elif 'evaluate rule' in msg.lower():
            parts = msg.split(":", 2)
            rule_name = parts[1].strip()  # Use rule name directly
            user_data_str = parts[2].strip()
            print(f"Received user data string: {user_data_str}")
            user_data = json.loads(user_data_str)

            # Fetch rule from the database if not in memory
            if rule_name not in rules:
                rule = Rule.query.filter_by(rule_id=rule_name).first()
                if rule:
                    # Convert the stored JSON AST back to a Node object
                    rules[rule_name] = dict_to_node(json.loads(rule.rule_ast))

            # Now evaluate the rule (which is in Node format)
            if rule_name in rules:
                result = evaluate_rule(rules[rule_name], user_data)
                send(f"Evaluation result: {result}")
            else:
                send(f"Error: Rule '{rule_name}' not found.")

        # Handle 'combine rules' command
        elif 'combine rules' in msg.lower():
            parts = msg.split(":", 2)
            rule_names_str = parts[1].strip()
            operator = parts[2].strip()

            rule_names = [rule_name.strip() for rule_name in rule_names_str.split(',')]  # Clean rule names
            asts = []

            # Fetch the ASTs for the rules from memory or database
            for rule_name in rule_names:
                if rule_name in rules:
                    asts.append(rules[rule_name])
                else:
                    rule = Rule.query.filter_by(rule_id=rule_name).first()
                    if rule:
                        ast = json.loads(rule.rule_ast)
                        rules[rule_name] = dict_to_node(ast)  # Cache in memory after converting to Node
                        asts.append(rules[rule_name])
                    else:
                        send(f"Error: Rule '{rule_name}' not found.")
                        return

            # Combine the rules using the specified operator
            combined_ast = combine_rules(asts, operator)

            # Generate a new rule ID for the combined rule
            last_rule = Rule.query.order_by(Rule.id.desc()).first()
            new_rule_id = f"rule{last_rule.id + 1 if last_rule else 1}"

            # Store the combined rule in memory and in the database
            rules[new_rule_id] = combined_ast
            combined_rule = Rule(rule_id=new_rule_id, rule_ast=json.dumps(combined_ast, default=lambda o: o.__dict__))
            db.session.add(combined_rule)
            db.session.commit()

            send(f"Rules combined into new rule: {new_rule_id}")

        else:
            send(f"Unrecognized command: {msg}")

    except json.JSONDecodeError as e:
        send(f"Error evaluating rule: Invalid JSON - {str(e)}")
        print(f"JSON parsing error: {str(e)}")
    except Exception as e:
        send(f"Error: {str(e)}")
        print(f"Error: {str(e)}")


if __name__ == '__main__':
    socketio.run(app, debug=True)
