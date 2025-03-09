from fastapi import FastAPI, HTTPException, Depends, Cookie
from fastapi.middleware.cors import CORSMiddleware
from models import SignupRequest, LoginRequest
from config import user_collection
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import uuid

app = FastAPI()

# CORS Configuration
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session management (in-memory session store for simplicity)
sessions = {}

@app.post("/signup")
def signup(data: SignupRequest):
    doc = dict(data)
    
    # Check if username already exists in MongoDB
    if user_collection.find_one({"username": doc["username"]}):
        raise HTTPException(status_code=400, detail="Username already taken")

    # Hash the password before storing
    doc["password"] = str(pwd_context.hash(doc["password"]))

    del doc["confirm_password"]  # Remove confirm_password from the document
    
    # Insert data into MongoDB
    user_collection.insert_one(doc)
    
    return {"message": "Signup successful! Redirecting to login..."}

@app.post("/login")
def login(data: LoginRequest):
    user = user_collection.find_one({"username": data.username})

    if not user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    # Verify password
    if not pwd_context.verify(data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    # Generate a unique session token
    session_token = str(uuid.uuid4())
    
    # Store session token (in a real application, use a secure store like Redis)
    sessions[session_token] = {"username": user["username"], "expires": datetime.utcnow() + timedelta(minutes=30)}

    # Set session token in cookies
    response = JSONResponse(content={"message": "Login successful", "username": user["username"]})
    response.set_cookie(key="session_token", value=session_token, httponly=True, max_age=30*60)

    return response

@app.get("/users")
def get_all_users():
    users = list(user_collection.find())

    for user in users:
        user["_id"] = str(user["_id"])

    return users

@app.get("/profile")
def profile(session_token: str = Cookie(None)):
    if not session_token or session_token not in sessions:
        raise HTTPException(status_code=401, detail="Not logged in")

    session = sessions[session_token]
    if session["expires"] < datetime.utcnow():
        del sessions[session_token]  # Session expired, remove it
        raise HTTPException(status_code=401, detail="Session expired")

    return {"message": f"Hello, {session['username']}!"}

@app.post("/logout")
def logout(session_token: str = Cookie(None)):
    if session_token and session_token in sessions:
        del sessions[session_token]  # Remove session
    return {"message": "Logged out successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8075)  # Ensure the port is 9001 to match React