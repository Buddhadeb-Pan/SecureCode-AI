from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from language_detector import detect_language
app = FastAPI(title="SecureCode AI API")

# React frontend-কে backend access করার permission
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# React থেকে যে data আসবে তার structure
class CodeRequest(BaseModel):
    code: str
    file_name: str = "unknown"
    language: str = "unknown"



@app.get("/")
def root():
    return {
        "message": "SecureCode AI Backend is running"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SecureCode AI Backend"
    }
@app.post("/analyze")
def analyze_code(data: CodeRequest):
    print("\n==============================")
    print("Analyze request received")
    print("File:", data.file_name)
    print("Frontend language hint:", data.language)

    language_result = detect_language(
        code=data.code,
        file_name=data.file_name,
        frontend_hint=data.language,
    )

    print("Detected language:", language_result["language"])
    print("Confidence:", language_result["confidence"])
    print("Status:", language_result["status"])
    print("==============================\n")

    return {
        "status": "success",
        "message": "Code received and language analyzed",
        "file_name": data.file_name,
        "detected_language": language_result["language"],
        "language_confidence": language_result["confidence"],
        "language_status": language_result["status"],
        "parser_passed": language_result["parser_passed"],
        "code": data.code,
    }