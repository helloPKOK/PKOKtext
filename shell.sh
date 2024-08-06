#!/bin/sh

# Run database migrations
flask db init
flask db migrate
flask db upgrade

# Start the application
python3 app.py
