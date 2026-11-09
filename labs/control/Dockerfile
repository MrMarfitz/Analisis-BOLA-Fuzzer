FROM python:3.13-slim
WORKDIR /lab
COPY service.py /lab/service.py
ENV CONTROL_BIND=0.0.0.0 CONTROL_PORT=8899
USER 65534:65534
CMD ["python", "service.py"]
