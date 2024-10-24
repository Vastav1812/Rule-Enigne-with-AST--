# Rule Engine with AST - Flask Application

## Overview

This project implements a rule engine that dynamically builds rules using Abstract Syntax Trees (AST). You can create rules, combine them, and evaluate user data against the rules via API endpoints.

## API Endpoints

- **POST /create_rule**: Create a rule and store it as an AST.
- **POST /evaluate_rule**: Evaluate a user's data against a rule.
- **POST /combine_rules**: Combine multiple rules into a single rule using AND/OR.

## Example Usage

### Create a Rule

```bash
curl -X POST http://localhost:5000/create_rule -H "Content-Type: application/json" -d '{"rule": "age > 30 AND department = 'Sales'", "rule_id": "rule1"}'
```
