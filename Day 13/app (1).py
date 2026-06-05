import os
import io
import base64
import json
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from ultralytics import YOLO
from PIL import Image
import numpy as np

app = Flask(__name__)

# ── Config ──────────────────────────────────────────────────────────────────
MODEL_PATH = Path(__file__).parent / "best.pt"
CONF_THRESHOLD = 0.25
MAX_IMAGE_SIZE = 1280            # YOLO inference size
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "bmp"}

# ── Load model once at startup ───────────────────────────────────────────────
print(f"[ProofAI] Loading model from {MODEL_PATH} …")
model = YOLO(str(MODEL_PATH))
CLASS_NAMES = model.names          # {0: 'fire', 1: 'smoke'}
print(f"[ProofAI] Model ready. Classes: {CLASS_NAMES}")

# ── Helpers ──────────────────────────────────────────────────────────────────
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def image_to_base64(img_array: np.ndarray) -> str:
    """Convert a BGR numpy array (from YOLO .plot()) to a base64 PNG string."""
    img_rgb = img_array[..., ::-1]          # BGR → RGB
    pil_img = Image.fromarray(img_rgb)
    buffer = io.BytesIO()
    pil_img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def pil_to_base64(pil_img: Image.Image) -> str:
    buffer = io.BytesIO()
    pil_img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", classes=CLASS_NAMES)


@app.route("/predict", methods=["POST"])
def predict():
    if "image" not in request.files:
        return jsonify({"error": "No image file in request."}), 400

    file = request.files["image"]
    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": f"Unsupported file type. Allowed: {ALLOWED_EXTENSIONS}"}), 400

    # Read image
    try:
        pil_img = Image.open(file.stream).convert("RGB")
    except Exception as e:
        return jsonify({"error": f"Could not read image: {e}"}), 400

    # Keep original for side-by-side display
    original_b64 = pil_to_base64(pil_img)
    orig_w, orig_h = pil_img.size

    # Run YOLO inference
    conf = float(request.form.get("conf", CONF_THRESHOLD))
    results = model.predict(
        source=pil_img,
        conf=conf,
        imgsz=MAX_IMAGE_SIZE,
        verbose=False
    )
    result = results[0]

    # Annotated image
    annotated_array = result.plot()          # returns BGR numpy array
    annotated_b64 = image_to_base64(annotated_array)

    # Build detections list
    detections = []
    boxes = result.boxes
    if boxes is not None and len(boxes):
        for box in boxes:
            cls_id   = int(box.cls[0].item())
            conf_val = float(box.conf[0].item())
            xyxy     = box.xyxy[0].tolist()   # [x1, y1, x2, y2] in pixels
            label    = CLASS_NAMES.get(cls_id, f"class_{cls_id}")
            detections.append({
                "class_id":   cls_id,
                "label":      label,
                "confidence": round(conf_val * 100, 1),   # as %
                "bbox": {
                    "x1": round(xyxy[0]),
                    "y1": round(xyxy[1]),
                    "x2": round(xyxy[2]),
                    "y2": round(xyxy[3]),
                }
            })

    # Sort by confidence descending
    detections.sort(key=lambda d: d["confidence"], reverse=True)

    return jsonify({
        "original":   original_b64,
        "annotated":  annotated_b64,
        "detections": detections,
        "image_size": {"width": orig_w, "height": orig_h},
        "total":      len(detections),
        "conf_used":  conf
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "classes": CLASS_NAMES, "model": str(MODEL_PATH.name)})


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
