from ultralytics import YOLO

model = YOLO('train/weights/best.pt')

results = model('test.png')

print(results)