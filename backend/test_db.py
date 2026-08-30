from app.database.database import SessionLocal
from app.database.crud import create_alert


db = SessionLocal()

alert = create_alert(
    db=db,
    attack_type="SYN_FLOOD",
    severity="HIGH",
    score=85.0,
    source_ip="192.168.0.17"
)

print(alert.id)
print("Alert saved successfully!")

db.close()