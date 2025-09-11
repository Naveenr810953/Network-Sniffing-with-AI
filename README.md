  # 🛡️ AI Network Packet Sniffer

A sophisticated web-based network monitoring tool that uses **AI** to detect and analyze security threats in real-time. This app simulates intelligent traffic analysis and alerts for high-severity threats only.

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![AI](https://img.shields.io/badge/AI-Powered-00BFFF?style=for-the-badge&logo=ai&logoColor=white)

---

## 📊 Features

- **Real-time Traffic Analysis** – Monitors TCP, UDP, ICMP, and encrypted traffic  
- **AI-Powered Threat Detection** – Uses ML logic to identify suspicious behavior  
- **Smart Browsing Simulation** – Generates traffic only during "browsing" sessions  
- **Website-Specific Detection** – Displays visited sites and their risk levels  
- **High-Severity Threat Focus** – Notifies only for significant security threats  
- **Interactive Visualizations** – Real-time charts and protocol graphs  
- **Responsive UI** – Works on both desktop and mobile  
- **Dark/Light Theme Toggle** – User-friendly visual themes  

---

## 🎯 How It Works

The tool mimics a network environment with simulated traffic and applies AI logic to detect and classify threats:

1. **Start Monitoring**  
   - Click "Start Analysis" to initiate simulated traffic flow

2. **Simulated Browsing**  
   - Traffic data is generated only when you "browse" websites in-app

3. **Live Visualization**  
   - Packets are charted in real time by protocol (TCP, UDP, etc.)

4. **AI Threat Detection**  
   - The system flags only high-severity risks (ignores low-level noise)

5. **Stop Monitoring**  
   - Click "Stop Analysis" to end the simulation

---

## 🚀 Usage

### Run Locally (No Installation Required)

#### Option 1: Open Directly
```bash
# Just double-click the index.html file
```

#### Option 2: Use a Local Server (Recommended)

**Using Python:**
```bash
python -m http.server 8000
# Then open http://localhost:8000 in your browser
```

**Using Node.js:**
```bash
npx serve
# Then open the provided local address in your browser
```

---

## 📁 Project Structure

```
ai-network-sniffer/
├── index.html       # Main application file
├── README.md        # Project documentation
└── assets/          # (Optional) Additional assets (CSS, JS, icons, etc.)
```

---

## 🌐 UI Overview

| Component            | Description                                             |
|---------------------|---------------------------------------------------------|
| Protocol Statistics | Real-time count of TCP, UDP, ICMP, and encrypted traffic|
| Traffic Charts       | Interactive graphs of packet activity over time        |
| Website Monitoring   | Shows visited websites and their risk assessment       |
| Threat Alerts        | Only displays alerts for high-risk network behavior    |
| AI Log               | Transparent detection rationale and decisions          |

---

## 📊 AI Capabilities

- **Anomaly Detection** – Learns baseline traffic and detects deviations  
- **Pattern Recognition** – Flags behavior similar to known attack signatures  
- **Risk Scoring** – Each website visited is rated based on simulated metrics  
- **Threat Categorization** – Classifies incidents by type and severity  

---

## 🔧 Technologies Used

- **HTML5** – Structure of the web app  
- **CSS3** – Styling and layout (Flexbox, Variables, Dark Mode)  
- **JavaScript** – Core logic for traffic simulation and AI detection  
- **Chart.js** – Real-time graphs and visual data analysis  
- **Font Awesome** – Iconography for UI/UX

---

## 🛠️ Customization

- **Threat Sensitivity** – Tweak thresholds for alerts in JavaScript logic  
- **Website Database** – Add or modify website entries and risk profiles  
- **Chart Settings** – Change chart colors, update frequency, etc.  
- **Theme Colors** – Modify light/dark mode variables in CSS  

---

## 📝 TODO

- 🧲 Add real network packet capture (e.g., via WebSockets or native modules)  
- 🧠 Enhance AI model with real-time learning & improved false positive reduction  
- 📈 Add export feature for reports (PDF/CSV)  
- 🗃️ Implement historical session logging  
- 🔐 Add authentication with multi-user profiles  
- 🌐 Visualize network topology and traffic flows

---

 

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo  
2. Create a branch:
```bash
git checkout -b feature/YourFeature
```
3. Make changes & commit:
```bash
git commit -m "Add YourFeature"
```
4. Push to GitHub:
```bash
git push origin feature/YourFeature
```
5. Open a Pull Request

---

## 👨‍💻 Developer

**Naveen Kumar S**  
📧 Email: navee4147@gmail.com  
💻 GitHub: [Naveenr810953](https://github.com/Naveenr810953)

---

## ⭐️ Show Your Support

If you found this project useful, please **give it a star** on GitHub!
