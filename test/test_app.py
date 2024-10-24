import pytest
import json
from app import app, db, Rule, dict_to_node, socketio
from flask_socketio import SocketIOTestClient


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use in-memory DB for testing
    with app.app_context():  # Ensuring an app context is active
        db.create_all()  # Set up the database for the test
    test_client = app.test_client()
    yield test_client
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def socketio_client():
    """ Fixture for creating a socket.io test client """
    client = socketio.test_client(app)
    yield client
    client.disconnect()


# Test Case 1: Test Rule Creation
def test_create_rule(socketio_client):
    # Emit the WebSocket message to create a rule
    socketio_client.emit('message', "create rule: age > 30")

    # Ensure rule is created in the database
    with app.app_context():
        rule = Rule.query.filter_by(rule_id='rule1').first()
        assert rule is not None
        assert json.loads(rule.rule_ast)['value'] == 'age > 30'


# Test Case 2: Test Duplicate Rule Creation
def test_duplicate_rule_creation(socketio_client):
    # Create a rule
    socketio_client.emit('message', "create rule: age > 30")

    # Try creating the same rule again
    socketio_client.emit('message', "create rule: age > 30")

    received = socketio_client.get_received()
    # Check if the error message is returned for a duplicate rule
    assert any("Error: A rule with the same logic already exists" in str(message) for message in received)


# Test Case 3: Test Rule Evaluation
def test_evaluate_rule(socketio_client):
    # Create a rule first
    socketio_client.emit('message', "create rule: age > 30")

    # Now test evaluation with correct user data
    eval_data = json.dumps({"age": 35})
    socketio_client.emit('message', f"evaluate rule: rule1: {eval_data}")

    received = socketio_client.get_received()
    # Check if the rule evaluated correctly
    assert any("Evaluation result: True" in str(message) for message in received)


# Test Case 4: Test Rule Evaluation with Invalid User Data
def test_evaluate_rule_invalid_data(socketio_client):
    # Create a rule first
    socketio_client.emit('message', "create rule: age > 30")

    # Now test evaluation with incorrect user data format
    eval_data = '{"age": "35"}'  # Invalid JSON
    socketio_client.emit('message', f"evaluate rule: rule1: {eval_data}")

    received = socketio_client.get_received()
    # Check if the system returns an error for invalid user data
    assert any("Error: Invalid JSON" in str(message) for message in received)


# Test Case 5: Test Combining Rules
def test_combine_rules(socketio_client):
    # Create two rules
    socketio_client.emit('message', "create rule: age > 30")
    socketio_client.emit('message', "create rule: department = 'Sales'")

    # Now combine the two rules
    socketio_client.emit('message', "combine rules: rule1, rule2: AND")

    # Check if the combined rule was created
    with app.app_context():
        combined_rule = Rule.query.filter_by(rule_id='rule3').first()
        assert combined_rule is not None
        assert 'AND' in combined_rule.rule_ast


# Test Case 6: Test Rule Evaluation after Combination
def test_evaluate_combined_rule(socketio_client):
    # Create and combine rules
    socketio_client.emit('message', "create rule: age > 30")
    socketio_client.emit('message', "create rule: department = 'Sales'")
    socketio_client.emit('message', "combine rules: rule1, rule2: AND")

    # Test evaluation of the combined rule
    eval_data = json.dumps({"age": 35, "department": "Sales"})
    socketio_client.emit('message', f"evaluate rule: rule3: {eval_data}")

    received = socketio_client.get_received()
    # Check if the combined rule evaluates correctly
    assert any("Evaluation result: True" in str(message) for message in received)


# Test Case 4: Test Rule Evaluation with Invalid User Data
def test_evaluate_rule_invalid_data(socketio_client):
    # Create a rule first
    socketio_client.emit('message', "create rule: age > 30")

    # Now test evaluation with incorrect user data format (string instead of number)
    eval_data = '{"age": "thirty-five"}'  # Invalid type for 'age'
    socketio_client.emit('message', f"evaluate rule: rule1: {eval_data}")

    received = socketio_client.get_received()
    # Check if the system returns an error for invalid type
    assert any("Invalid type for comparison" in str(message) for message in received)

