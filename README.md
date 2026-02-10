# AI-Powered Anomaly Detection System


## Overview
This project detects unusual or suspicious behavior in system logs using Machine Learning. 
Instead of relying on static rules (like traditional SIEM systems), it uses models such as 
Isolation Forest to automatically learn normal patterns and identify anomalies.

The system includes:
- Log ingestion
- Data preprocessing
- Feature engineering
- Machine learning anomaly detection
- Alerting system
- Dashboard for visualization
- API for predictions





## Project Structure

ai_anomaly_detection/
├── data/
│ ├── raw_logs/
│ ├── processed/
│ └── features/
├── src/
│ ├── data_ingestion.py
│ ├── preprocessing.py
│ ├── feature_engineering.py
│ ├── model_train.py
│ ├── model_predict.py
│ ├── alert_system.py
│ └── utils.py
├── models/
├── config/
├── dashboard/
├── api.py
├── requirements.txt
└── README.md






## Features
- Automatic anomaly detection using Machine Learning
- Detects suspicious login behavior, IP anomalies, request spikes, etc.
- Real-time alerting based on anomaly score
- Dashboard for monitoring anomalies
- API for integrating the model with other applications





## How It Works
1. Logs are ingested and cleaned
2. Features are extracted from logs
3. An Isolation Forest model is trained
4. The model generates anomaly scores
5. Alerts trigger if the score exceeds the threshold
6. Dashboard visualizes anomalies and trends





## Technologies Used
- Python
- Pandas, NumPy
- Scikit-learn
- FastAPI
- Streamlit
- Matplotlib




## Installation
pip install -r requirements.txt




## Running the API
uvicorn api:app --reload



## Running the Dashboard
streamlit run dashboard/dashboard.py




## Future Improvements
- Autoencoder-based deep learning model
- Log streaming in real-time
- Integration with SIEM tools
- Threat scoring mechanism



## Author
Manish  
AI-Based Security Projects

