FROM python:latest
RUN pip install --upgrade pip
RUN mkdir /app
WORKDIR /app
ADD . .
RUN pip install -r requirements.txt