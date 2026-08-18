from app.database.database import SessionLocal
from app.database.crud import create_alert

db = SessionLocal()

alert = create_alert(
    db=db,
    attack_type="SYN_FLOOD",
    severity="HIGH",
    source_ip="192.168.0.17",
    destination_ip="34.107.243.93",
    score=-0.92,
    message="Test alert"
)

print(alert.id)
print("Alert saved successfully!")