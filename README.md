Autonomous Cyber Defence with Digital Twin

An AI-assisted cybersecurity prototype that monitors network traffic, detects
suspicious activity, recommends defensive actions, and records investigation
and Digital Twin validation results.

The project brings together machine learning, network monitoring, automated
response logic, traceback information, and a web-based dashboard in one system.
1. What does this project do?

The system is organised into five main modules:

1. Network Monitoring and Traffic Collection – collects and processes
   available network-flow information.
2. AI-Based Traffic Analysis and Attack Detection – uses machine learning
   to classify traffic and identify suspicious behaviour.
3. Autonomous Defence and Response – selects a recommended response based
   on the detection result.
4. AIORI Traceback and Digital Twin Validation – provides contextual
   information about suspicious IP addresses and supports validation using a
   virtual network test environment.
5. Security Dashboard and Data Management – presents detection results,
   defence records, investigations, and validation information.

2. Technology used

Area				Technologies
--------------------------------------------------------------------------------
Backend  			Python, FastAPI 
Frontend 			React, Vite, JavaScript 
Machine Learning		Scikit-learn, Random Forest, Isolation Forest
Network Monitoring		Scapy
Digital Twin Testbed 		Mininet 
Data and Model Handling 	Pandas, NumPy, Joblib 
Network Defence Integration 	iptables (prototype integration) 
Visualisation 			React dashboard, Chart.js (where configured) 

The machine-learning models are trained using the CICIDS2017 dataset.

3. Project requirements

Before running the project, install:

- Ubuntu/Linux or another compatible development environment
- Python 3.11
- Node.js 20.19+ or 22.12+
- npm
- Git (optional, if cloning the repository)

The trained model files must be present:

- ml/models/random_forest.joblib
- ml/models/isolation_forest.joblib

4. Project structure

Smart-Cyber-Defence/
│
├── backend/             # FastAPI backend and application modules
├── digital_twin/        # Mininet-based virtual network testbed
├── docs/                # Project documentation
├── frontend/            # React and Vite dashboard
├── ml/
│   ├── dataset/         # Dataset-related files
│   ├── models/          # Trained machine-learning models
│   ├── preprocessing/   # Data preparation scripts
│   └── training/        # Model training scripts
├── tests/               # Project tests
├── requirements.txt     # Python dependencies
└── README.md            # Project setup and usage guide

5. How to run the project locally

Run the backend and frontend in two separate terminal windows.
Step A: Set up the backend
Open Terminal 1 and move into the project directory: cd Smart-Cyber-Defence

Create a Python virtual environment: python3.11 -m venv .venv

Activate it: source .venv/bin/activate

Upgrade pip and install the required packages:
python -m pip install --upgrade pip
pip install -r requirements.txt

Start the backend server:
uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 --reload
Keep this terminal open while using the application.

Step B: Check the backend
Open a browser and visit:
- Backend: http://127.0.0.1:8001/
- API health check: http://127.0.0.1:8001/api/health
- Interactive API documentation: http://127.0.0.1:8001/docs
The API documentation allows you to view and test the available backend endpoints.
Step C: Set up the frontend

Open Terminal 2.
Move into the frontend directory: cd Smart-Cyber-Defence/frontend

Install the frontend dependencies: npm install

Start the development server: npm run dev

Vite will display a local URL in the terminal, usually: http://localhost:5173/

Open the URL shown in your terminal to access the dashboard.
Keep both backend and frontend terminals running while using the application.

6. Important API endpoints

Endpoint			  Purpose
--------------------------------------------------------------------------
GET /api/health			  Check backend health
GET /api/dashboard/summary	  Retrieve dashboard statistics
GET /api/dashboard/detections	  Retrieve detection records
GET /api/dashboard/defences	  Retrieve defence records
GET /api/monitoring/summary	  Retrieve monitoring statistics
GET /api/monitoring/flows	  Retrieve available network-flow records
POST /api/detection/analyze	  Analyse a submitted network-flow record
GET /api/traceback/{source_ip}	  Retrieve traceback information
GET /api/investigations		  Retrieve investigation records
POST /api/investigations	  Create an investigation record
GET /api/twin/validations	  Retrieve Digital Twin validation records
POST /api/twin/validations	  Create a validation record

For request formats and response details, use the interactive API documentation
at /docs.

7. Machine-learning detection

The project uses two machine-learning models:
- Random Forest: predicts traffic categories such as NORMAL, DDOS,
  BRUTE_FORCE, and PORT_SCAN.
- Isolation Forest: provides supplementary anomaly detection. It identifies
  unusual traffic patterns but does not independently identify the exact
  attack category.
The two models contribute different information to the detection process.

8. Defence and Digital Twin operation

The defence module evaluates detection results and selects an appropriate
response, such as monitoring, rate limiting, or recommending an IP block.

Important: The current application uses dry-run defence mode. It records
and displays proposed defensive actions but does not automatically execute
firewall blocking in the deployed application.

The Digital Twin component uses a Mininet-based virtual network testbed for
prototype validation. It is not a continuously synchronised replica of a
production network.
Mininet is an optional component and must be installed separately on a
compatible Linux system before running the Digital Twin test scripts.

9. Data storage

The application maintains project records using its configured local storage
and log files. Some records are generated when the application is used. Therefore, an
initially empty dashboard does not necessarily indicate that the application
has failed.

The deployed cloud service uses temporary local storage. Records may not
survive a service restart or redeployment.

10. Online demo

The project is also deployed online:
- Dashboard: https://smart-cyber-defence.vercel.app
- Backend API: https://smart-cyber-defence.onrender.com
- API documentation: https://smart-cyber-defence.onrender.com/docs
The cloud backend may take some time to respond after a period of inactivity
because the hosting service can put the free instance to sleep.

11. Current prototype limitations

This project is a working cybersecurity prototype, and some capabilities
depend on the environment in which it is executed.
- Continuous packet capture is not running on the cloud deployment.
- Traffic from other computers is not automatically monitored unless a
  suitable monitoring agent or sensor is configured.
- Defensive actions in the deployed application are recorded in dry-run mode.
- Digital Twin validation records do not necessarily mean that a Mininet
  simulation was executed.
- IP traceback provides contextual information about a possible source; it
  does not establish the real-world identity of an attacker.
- Machine-learning evaluation results should be interpreted in light of the
  dataset and evaluation methodology described in the project report.

12. Project purpose

The aim of this project is to demonstrate how machine learning, network
monitoring, defensive decision-making, traceback context, and virtual network
validation can be combined into an integrated cybersecurity prototype.

It is intended for academic demonstration, experimentation, and further
development. It should not be treated as a replacement for a production
firewall or a complete enterprise security solution.
