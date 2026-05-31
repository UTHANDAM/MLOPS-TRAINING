import pickle
import numpy as np
import warnings
warnings.filterwarnings('ignore')

model_data = None

def load_artifacts():
    global model_data
    with open('riskproof_ai_best_model.pkl', 'rb') as f:
        model_data = pickle.load(f)
    print(f"[RiskProof AI] Model loaded: {model_data['model_name']} | Accuracy: {model_data['best_accuracy']:.2%}")

def get_model_info():
    return {
        'model_name': model_data['model_name'],
        'accuracy': round(model_data['best_accuracy'] * 100, 2)
    }

def predict_claim(raw_input):
    model      = model_data['model']
    feat_cols  = model_data['feature_columns']
    label_map  = model_data['risk_label_map']

    features = {col: 0 for col in feat_cols}

    # Numerical features — set directly
    for col in ['WeekOfMonth', 'WeekOfMonthClaimed', 'Age', 'Deductible', 'DriverRating', 'Year']:
        if col in raw_input:
            try:
                features[col] = float(raw_input[col])
            except:
                pass

    # Categorical → one-hot prefixes
    cat_map = {
        'Month'               : 'Month_',
        'DayOfWeek'           : 'DayOfWeek_',
        'Make'                : 'Make_',
        'AccidentArea'        : 'AccidentArea_',
        'DayOfWeekClaimed'    : 'DayOfWeekClaimed_',
        'MonthClaimed'        : 'MonthClaimed_',
        'Sex'                 : 'Sex_',
        'MaritalStatus'       : 'MaritalStatus_',
        'Fault'               : 'Fault_',
        'PolicyType'          : 'PolicyType_',
        'VehicleCategory'     : 'VehicleCategory_',
        'VehiclePrice'        : 'VehiclePrice_',
        'Days_Policy_Accident': 'Days_Policy_Accident_',
        'Days_Policy_Claim'   : 'Days_Policy_Claim_',
        'PastNumberOfClaims'  : 'PastNumberOfClaims_',
        'AgeOfVehicle'        : 'AgeOfVehicle_',
        'AgeOfPolicyHolder'   : 'AgeOfPolicyHolder_',
        'PoliceReportFiled'   : 'PoliceReportFiled_',
        'WitnessPresent'      : 'WitnessPresent_',
        'AgentType'           : 'AgentType_',
        'NumberOfSuppliments' : 'NumberOfSuppliments_',
        'AddressChange_Claim' : 'AddressChange_Claim_',
        'NumberOfCars'        : 'NumberOfCars_',
    }

    for field, prefix in cat_map.items():
        if field in raw_input:
            key = prefix + str(raw_input[field])
            if key in features:
                features[key] = 1

    X = np.array([[features[c] for c in feat_cols]])
    pred  = model.predict(X)[0]
    proba = model.predict_proba(X)[0]

    # Risk factors (top feature importances that fired)
    importances  = model.feature_importances_
    top_idx      = importances.argsort()[::-1][:5]
    risk_factors = []
    for i in top_idx:
        col = feat_cols[i]
        if features[col] > 0 and importances[i] > 0.01:
            risk_factors.append({
                'factor': col.replace('_', ' '),
                'weight': round(float(importances[i]) * 100, 1)
            })

    return {
        'prediction'       : int(pred),
        'label'            : label_map[int(pred)],
        'fraud_probability': round(float(proba[1]) * 100, 1),
        'safe_probability' : round(float(proba[0]) * 100, 1),
        'confidence'       : round(float(max(proba)) * 100, 1),
        'model_used'       : model_data['model_name'],
        'model_accuracy'   : round(model_data['best_accuracy'] * 100, 2),
        'risk_factors'     : risk_factors
    }
