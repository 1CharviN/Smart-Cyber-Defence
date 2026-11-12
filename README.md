# Autonomous Cyber Defence with Digital Twin

An AI-assisted cybersecurity project that monitors network traffic, detects suspicious activity, and helps identify suitable defensive actions. It also brings together IP traceback information, a virtual network test environment, and a web-based dashboard to make the detection and investigation process easier to understand.

The main idea behind this project is to explore how machine learning and network security technologies can work together to support faster threat detection and response.

## 1. What does the project do?

The system is divided into five main modules, with each module handling a different part of the cybersecurity process.

1. **Network Monitoring and Traffic Collection** – Collects and processes available network-flow information for analysis.
2. **AI-Based Traffic Analysis and Attack Detection** – Uses machine-learning models to classify network traffic and identify unusual activity.
3. **Autonomous Defence and Response** – Evaluates detection results and recommends an appropriate defensive action.
4. **AIORI Traceback and Digital Twin Validation** – Provides additional information about suspicious IP addresses and supports testing through a virtual network environment.
5. **Security Dashboard and Data Management** – Displays detection results, defence records, investigation details, and Digital Twin validation information.

Together, these modules demonstrate how different cybersecurity functions can be brought into one application.

## 2. Technologies used

| Area | Technologies |
|---|---|
| Backend | Python, FastAPI |
| Frontend | React, Vite, JavaScript |
| Machine Learning | Scikit-learn, Random Forest, Isolation Forest |
| Network Monitoring | Scapy |
| Digital Twin Testbed | Mininet |
| Data Processing | Pandas, NumPy |
| Model Management | Joblib |
| Defence Integration | iptables (prototype integration) |
| Dashboard and Visualisation | React, Chart.js (where configured) |

The machine-learning models are trained using the CICIDS2017 dataset.

## 3. Requirements

Before setting up the project, make sure you have the following installed:

- Ubuntu/Linux or another compatible development environment
- Python 3.11
- Node.js 20.19+ or 22.12+
- npm
- Git (if you plan to clone the repository)

The trained model files should also be available in the project directory:

- `ml/models/random_forest.joblib`
- `ml/models/isolation_forest.joblib`

## 4. Project structure

The repository is organised into the following main folders:

```text
Smart-Cyber-Defence/
│
├── backend/              # FastAPI backend and application modules
├── digital_twin/         # Mininet-based virtual network testbed
├── docs/                 # Project documentation
├── frontend/             # React and Vite dashboard
├── ml/
│   ├── dataset/          # Dataset-related files
│   ├── models/           # Trained machine-learning models
│   ├── preprocessing/    # Data preparation scripts
│   └── training/         # Model training scripts
├── tests/                # Project tests
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

## 5. Running the project locally

The backend and frontend need to run in separate terminal windows.

### Step A: Start the backend

Open the first terminal and navigate to the project directory:

```bash
cd Smart-Cyber-Defence
```

Create a Python virtual environment:

```bash
python3.11 -m venv .venv
```

Activate the environment:

```bash
source .venv/bin/activate
```

Upgrade pip and install the required packages:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Start the FastAPI server:

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 --reload
```

Keep this terminal running while you use the application.

### Step B: Check the backend

Once the backend has started, open a browser and visit:

- **Backend:** http://127.0.0.1:8001/
- **Health check:** http://127.0.0.1:8001/api/health
- **API documentation:** http://127.0.0.1:8001/docs

The interactive API documentation is useful for viewing the available endpoints and trying out API requests.

### Step C: Start the frontend

Open a second terminal and navigate to the frontend directory:

```bash
cd Smart-Cyber-Defence/frontend
```

Install the frontend dependencies:

```bash
npm install
```

Start the Vite development server:

```bash
npm run dev
```

Vite will display a local address in the terminal, usually:

http://localhost:5173/

Open the address shown in your terminal to access the dashboard.

**Note:** Keep both terminals running while using the locally hosted application.

## 6. Main API endpoints

The backend provides the following API endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Checks backend health |
| GET | `/api/dashboard/summary` | Retrieves dashboard statistics |
| GET | `/api/dashboard/detections` | Retrieves detection records |
| GET | `/api/dashboard/defences` | Retrieves defence records |
| GET | `/api/monitoring/summary` | Retrieves monitoring statistics |
| GET | `/api/monitoring/flows` | Retrieves available network-flow records |
| POST | `/api/detection/analyze` | Analyses a submitted network-flow record |
| GET | `/api/traceback/{source_ip}` | Retrieves traceback information |
| GET | `/api/investigations` | Retrieves investigation records |
| POST | `/api/investigations` | Creates an investigation record |
| GET | `/api/twin/validations` | Retrieves Digital Twin validation records |
| POST | `/api/twin/validations` | Creates a validation record |

For request formats and response details, visit the interactive API documentation at `/docs`.

## 7. Machine-learning based detection

The project uses two machine-learning models to examine network traffic.

**Random Forest**

The Random Forest model predicts traffic categories such as:

- `NORMAL`
- `DDOS`
- `BRUTE_FORCE`
- `PORT_SCAN`

It is used to classify traffic based on the features provided to the model.

**Isolation Forest**

The Isolation Forest model looks for unusual patterns in network traffic. It acts as an additional anomaly detector and helps identify traffic that may require further attention.

It does not independently determine the exact category of an attack.

Both models contribute different information to the detection process, allowing the application to consider both predicted traffic categories and unusual behaviour.

## 8. Defence and Digital Twin

After analysing traffic, the defence module evaluates the detection result and selects a suitable response. Depending on the result, the application may recommend actions such as:

- Monitoring the traffic
- Applying a rate-limiting recommendation
- Recommending that a suspicious IP address be blocked
- Taking no action when the traffic is considered normal or protected

**Current defence status:** The deployed application operates in dry-run mode. It records and displays proposed defensive actions, but does not automatically execute firewall blocking.

The Digital Twin component uses a Mininet-based virtual network as a test environment for prototype validation. This allows selected network scenarios and connectivity behaviour to be examined in a controlled setup.

It is important to note that this is a prototype testbed, not a continuously synchronised replica of a live production network.

Mininet is an optional component and must be installed separately on a compatible Linux system before running the Digital Twin test scripts.

## 9. Data storage

The application maintains its records using the configured local storage and log files. Detection and defence records, along with other project information, may be generated as the application is used.

Because some records are created during runtime, the dashboard may initially appear empty. This does not necessarily mean that the application has failed.

The deployed cloud service uses temporary local storage. As a result, records may not remain available after a service restart or redeployment.

## 10. Online demo

The project is also available through the following deployed links:

- **Dashboard:** https://smart-cyber-defence.vercel.app
- **Backend API:** https://smart-cyber-defence.onrender.com
- **API documentation:** https://smart-cyber-defence.onrender.com/docs

The cloud backend may take a little time to respond if it has been inactive. This is because the hosting service may put its free instance to sleep.

## 11. Current limitations

This project is developed as an academic cybersecurity prototype. Some features depend on the environment and configuration in which the application is running.

The current limitations include:

- Continuous packet capture is not running on the cloud deployment.
- Traffic from other computers is not automatically monitored unless a suitable monitoring agent or network sensor is configured.
- Defensive actions are recorded in dry-run mode rather than automatically applied through the deployed firewall integration.
- IP traceback provides contextual information about a possible traffic source. It does not prove the real-world identity of an attacker.
- Machine-learning results should be considered alongside the dataset, training process, and evaluation methodology described in the project report.

These limitations also provide opportunities for further development.

## 12. Project purpose and future scope

The purpose of this project is to demonstrate how machine learning, network monitoring, defensive decision-making, IP traceback information, and virtual network validation can be combined in a single cybersecurity application.

The current implementation provides a foundation for further work, including improved live traffic integration, more reliable Digital Twin validation, stronger threat analysis, and controlled testing of automated defensive actions.

This project is intended for academic demonstration, experimentation, and further development. It is not designed to replace a production firewall or a complete enterprise cybersecurity solution.
