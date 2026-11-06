FROM python:3.12-slim
RUN useradd --create-home --uid 1000 appuser
COPY app.py /home/appuser/app.py
USER appuser
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
CMD ["python", "/home/appuser/app.py"]
