FROM python:3.13-alpine
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY probe.py gateway.py ./
RUN python3 gateway.py --help > /dev/null
CMD ["python3", "gateway.py"]
