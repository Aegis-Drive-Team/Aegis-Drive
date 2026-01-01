# Using the official Python image
# Later implementation for other Docker images will be added
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# set environment variables 
ENV FLASK_APP=app.py 
ENV FLASK_RUN_HOST=0.0.0.0 
ENV PORT=5000 
ENV PYTHONPATH=/app

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
