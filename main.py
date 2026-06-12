from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import aiohttp

# DB Setup
DATABASE_URL = "sqlite:///./database.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread:" False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_type = Column(String) #ex Subdomains or ports
    count = Column(Integer)
    timestamp = Column(dateTime, default = datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)

#2 FastAPI Init
app = FastAPI()

#Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

#3 OSINT Async engine module
async def fetch_subdomains(domain: "str") -> "int":
    #Queries crt.sh passively to find logging subdomains
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    #Return the count of unique subdomains found
                    unique_subs = len(set([item['name_value'] for item in data]))
                    return unique_subs
    except Exception:
        return 0

#4 API  /api/scan
@app.get("/api/scan")
async def run_intel_scan(target:str):
    db = SessionLocal()
    
    #Run OSINT queries concurrently
    subdomain_count = await fetch_subdomains(target)

    #Save the results to SQLITE to track trends
    scan_record = ScanResult(target=target, scan_type = "Subdomains",  count = subdomain_count)