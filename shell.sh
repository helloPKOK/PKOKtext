#!/bin/sh

# Initialize migrations if the directory doesn't exist
if [ ! -d "migrations" ]; then
  echo "Initializing migrations directory."
  flask db init
fi

# Run migrations and upgrades
echo "Running database migrations."
flask db migrate
flask db upgrade

# Start the application with Gunicorn
echo "Starting the application with Gunicorn."
exec gunicorn -b 0.0.0.0:$PORT app:app
