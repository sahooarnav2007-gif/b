from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import json, os

app = FastAPI(title="AI Network Attack Forecasting API")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def home():
    return {"message":"AI Attack Forecasting API running"}

@app.get("/summary")
def summary():
    if os.path.exists("model_summary_real.json"):
        return json.load(open("model_summary_real.json"))
    return {"error":"Train model first"}

@app.get("/predictions")
def predictions(limit:int=20):
    if os.path.exists("predictions_real.csv"):
        df=pd.read_csv("predictions_real.csv")
        return df.tail(limit).to_dict(orient="records")
    return {"error":"No predictions available"}

@app.get("/features")
def features():
    if os.path.exists("feature_importance_real.csv"):
        return pd.read_csv("feature_importance_real.csv").head(20).to_dict(orient="records")
    return {"error":"No feature importance available"}
