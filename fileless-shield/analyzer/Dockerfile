FROM python:3.11-slim
RUN pip install psutil
WORKDIR /analyzer
COPY analyzer.py .
CMD ["python3", "-u", "analyzer.py"]
