# Model Folder

This folder contains the model-side proof for the RiskProof AI final demo.

Included files:

- `RiskProofAI_Full_Model_Benchmark.ipynb` - final notebook
- `RiskProofAI_Full_Model_Benchmark.executed.ipynb` - executed notebook with outputs
- `fraud_oracle.csv` - training dataset
- `riskproof_ai_best_model.pkl` - final best model bundle saved with pickle
- `riskproof_ai_best_model.joblib` - final best model bundle saved with joblib
- `model_comparison_metrics.csv` - model accuracy, balanced accuracy, fraud precision, fraud recall, fraud F1
- `per_model_predictions.csv` - test predictions from each model
- `saved_model_files.csv` - saved model artifact list

The final selected model is a Decision Tree by test accuracy.
