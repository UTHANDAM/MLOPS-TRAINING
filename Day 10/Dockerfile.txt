FROM python:3.11-slim

# Install system dependencies needed by OpenCV and ultralytics
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /Task21

# Install PyTorch CPU-only FIRST (avoids downloading full CUDA build ~2GB)
RUN pip install --no-cache-dir \
    torch==2.3.0+cpu torchvision==0.18.0+cpu \
    --index-url https://download.pytorch.org/whl/cpu


# Install remaining requirements last
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy model and script
COPY train/weights/best.pt .
COPY predict.py .

CMD ["python", "predict.py"]