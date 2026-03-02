FROM python:3.10-slim

WORKDIR /app

# Install system deps
RUN apt-get update && \
    apt-get install -y yara && \
    rm -rf /var/lib/apt/lists/*

# Install python deps
RUN pip install yara-python kafka-python

# Copy updater script
COPY ./rule_updater.py /app/

CMD ["python3", "rule_updater.py"]
