FROM python

WORKDIR /app

COPY semgrep-scan.py /app/semgrep_scan.py

RUN apt-get update && \
    apt-get install -y wget && \
    pip3 install prettytable && \
    pip3 install semgrep && \
    pip3 install --upgrade requests

CMD ["python3", "./semgrep_scan.py"]