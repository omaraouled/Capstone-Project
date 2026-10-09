import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_PATH = os.getenv("DATABASE_PATH", "security_events.db")
CLOUDWATCH_LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "/technova/security")
SUSPICIOUS_PROCESSES = {
    item.strip().lower()
    for item in os.getenv("SUSPICIOUS_PROCESSES", "nc,ncat,netcat,mimikatz").split(",")
    if item.strip()
}
