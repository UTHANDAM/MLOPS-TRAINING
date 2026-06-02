import pickle
from pathlib import Path

import numpy as np
import pandas as pd


ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "riskproof_ai_best_model.pkl"

_model_bundle = None
_model = None
_feature_columns = None


DEFAULT_INPUT = {
    "Month": "Jan",
    "WeekOfMonth": 3,
    "DayOfWeek": "Monday",
    "Make": "Toyota",
    "AccidentArea": "Urban",
    "DayOfWeekClaimed": "Monday",
    "MonthClaimed": "Jan",
    "WeekOfMonthClaimed": 3,
    "Sex": "Male",
    "MaritalStatus": "Married",
    "Age": 35,
    "Fault": "Policy Holder",
    "PolicyType": "Sedan - Collision",
    "VehicleCategory": "Sedan",
    "VehiclePrice": "20000 to 29000",
    "Deductible": 400,
    "DriverRating": 3,
    "Days_Policy_Accident": "more than 30",
    "Days_Policy_Claim": "more than 30",
    "PastNumberOfClaims": "none",
    "AgeOfVehicle": "7 years",
    "AgeOfPolicyHolder": "31 to 35",
    "PoliceReportFiled": "No",
    "WitnessPresent": "No",
    "AgentType": "External",
    "NumberOfSuppliments": "none",
    "AddressChange_Claim": "no change",
    "NumberOfCars": "1 vehicle",
    "Year": 1994,
}


FORM_OPTIONS = {
    "Month": ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
    "DayOfWeek": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
    "Make": [
        "Accura", "BMW", "Chevrolet", "Dodge", "Ferrari", "Ford", "Honda", "Jaguar",
        "Lexus", "Mazda", "Mecedes", "Mercury", "Nisson", "Pontiac", "Porche",
        "Saab", "Saturn", "Toyota", "VW",
    ],
    "AccidentArea": ["Urban", "Rural"],
    "DayOfWeekClaimed": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
    "MonthClaimed": ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
    "Sex": ["Male", "Female"],
    "MaritalStatus": ["Married", "Single", "Divorced", "Widow"],
    "Fault": ["Policy Holder", "Third Party"],
    "PolicyType": [
        "Sedan - Liability", "Sedan - Collision", "Sedan - All Perils",
        "Sport - Liability", "Sport - Collision", "Sport - All Perils",
        "Utility - Liability", "Utility - Collision", "Utility - All Perils",
    ],
    "VehicleCategory": ["Sedan", "Sport", "Utility"],
    "VehiclePrice": [
        "less than 20000", "20000 to 29000", "30000 to 39000",
        "40000 to 59000", "60000 to 69000", "more than 69000",
    ],
    "Deductible": [300, 400, 500, 700],
    "DriverRating": [1, 2, 3, 4],
    "Days_Policy_Accident": ["none", "1 to 7", "8 to 15", "15 to 30", "more than 30"],
    "Days_Policy_Claim": ["none", "8 to 15", "15 to 30", "more than 30"],
    "PastNumberOfClaims": ["none", "1", "2 to 4", "more than 4"],
    "AgeOfVehicle": ["new", "2 years", "3 years", "4 years", "5 years", "6 years", "7 years", "more than 7"],
    "AgeOfPolicyHolder": ["16 to 17", "18 to 20", "21 to 25", "26 to 30", "31 to 35", "36 to 40", "41 to 50", "51 to 65", "over 65"],
    "PoliceReportFiled": ["No", "Yes"],
    "WitnessPresent": ["No", "Yes"],
    "AgentType": ["External", "Internal"],
    "NumberOfSuppliments": ["none", "1 to 2", "3 to 5", "more than 5"],
    "AddressChange_Claim": ["no change", "under 6 months", "1 year", "2 to 3 years", "4 to 8 years"],
    "NumberOfCars": ["1 vehicle", "2 vehicles", "3 to 4", "5 to 8", "more than 8"],
    "Year": [1994, 1995, 1996],
}


NUMERIC_FIELDS = {
    "WeekOfMonth",
    "WeekOfMonthClaimed",
    "Age",
    "Deductible",
    "DriverRating",
    "Year",
}


def load_saved_artifacts():
    global _model_bundle, _model, _feature_columns

    if _model_bundle is None:
        with open(MODEL_PATH, "rb") as file:
            _model_bundle = pickle.load(file)
        _model = _model_bundle["model"]
        _feature_columns = _model_bundle["feature_columns"]

    return _model_bundle


def get_model_metadata():
    bundle = load_saved_artifacts()
    return {
        "model_name": bundle.get("model_name"),
        "best_accuracy": bundle.get("best_accuracy"),
        "target_column": bundle.get("target_column"),
        "feature_count": len(bundle.get("feature_columns", [])),
        "risk_label_map": bundle.get("risk_label_map", {0: "Low-risk claim", 1: "High-risk claim"}),
    }


def get_form_options():
    return {
        "defaults": DEFAULT_INPUT,
        "options": FORM_OPTIONS,
        "numeric_fields": sorted(NUMERIC_FIELDS),
    }


def _coerce_input(raw_input):
    claim = DEFAULT_INPUT.copy()
    for key in claim:
        if key in raw_input and raw_input[key] not in (None, ""):
            claim[key] = raw_input[key]

    for key in NUMERIC_FIELDS:
        claim[key] = int(float(claim[key]))

    return claim


def _build_feature_frame(claim):
    row = pd.DataFrame(np.zeros((1, len(_feature_columns))), columns=_feature_columns)

    for field, value in claim.items():
        if field in NUMERIC_FIELDS and field in row.columns:
            row.at[0, field] = float(value)
            continue

        encoded_col = f"{field}_{value}"
        if encoded_col in row.columns:
            row.at[0, encoded_col] = 1

    return row


def _recommendation(prediction, risk_score):
    if prediction == 1:
        return (
            "High-risk claim. Broker should verify police report, witness availability, "
            "claim timing, past claim history, and supporting evidence before submission."
        )

    if risk_score is not None and risk_score >= 0.35:
        return (
            "Moderate risk signals detected. Broker should review claim documents and "
            "confirm that evidence is complete before submission."
        )

    return "Low-risk claim. Evidence packet can proceed with standard broker review."


def predict_claim_risk(raw_input):
    load_saved_artifacts()
    claim = _coerce_input(raw_input)
    feature_frame = _build_feature_frame(claim)

    prediction = int(_model.predict(feature_frame)[0])
    risk_score = None

    if hasattr(_model, "predict_proba"):
        risk_score = float(_model.predict_proba(feature_frame)[0][1])
    elif hasattr(_model, "decision_function"):
        risk_score = float(_model.decision_function(feature_frame)[0])

    risk_label_map = _model_bundle.get(
        "risk_label_map",
        {0: "Low-risk / genuine claim", 1: "High-risk / suspicious claim"},
    )

    return {
        "model_name": _model_bundle.get("model_name"),
        "best_accuracy": _model_bundle.get("best_accuracy"),
        "prediction": prediction,
        "risk_label": risk_label_map.get(prediction, str(prediction)),
        "risk_score": risk_score,
        "input_used": claim,
        "recommendation": _recommendation(prediction, risk_score),
    }


if __name__ == "__main__":
    load_saved_artifacts()
    print(get_model_metadata())
    print(predict_claim_risk(DEFAULT_INPUT))
