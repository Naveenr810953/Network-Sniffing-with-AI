// State management
const state = {
    running: false,
    counts: {
        tcp: 0,
        udp: 0,
        icmp: 0,
        encrypted: 0,
        other: 0
    },
    prevCounts: {
        tcp: 0,
        udp: 0,
        icmp: 0,
        encrypted: 0,
        other: 0
    },    
    intervalId: null,
    trafficChart: null,
    distributionChart: null,
    dataPoints: 0,
    alertSound: null,
    startTime: null,
    sourceIPs: {},
    destIPs: {},
    websites: {},
    theme: 'dark',
    aiLog: [],
    browsingActivity: false,
    browsingTimer: null
};
  
// DOM elements  
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const tcpCountEl = document.getElementById('tcp-count');
const udpCountEl = document.getElementById('udp-count');
const icmpCountEl = document.getElementById('icmp-count');
const encryptedCountEl = document.getElementById('encrypted-count');
const alertPanel = document.getElementById('alert-panel');
const alertTitle = document.getElementById('alert-title');
const alertMessage = document.getElementById('alert-message');
const alertDetails = document.getElementById('alert-details');
const threatLevel = document.getElementById('threat-level');
const themeToggle = document.getElementById('theme-toggle');
const sourceIpList = document.getElementById('source-ip-list');
const destIpList = document.getElementById('dest-ip-list');
const websiteList = document.getElementById('website-list');
const trafficRateEl = document.getElementById('traffic-rate');
const aiAnalysisEl = document.getElementById('ai-analysis');

// Website database with security information
const websiteDatabase = {
    "google.com": { category: "Search Engine", risk: "Low", traffic: 0 },
    "youtube.com": { category: "Video Streaming", risk: "Low", traffic: 0 },
    "facebook.com": { category: "Social Media", risk: "Medium", traffic: 0 },
    "amazon.com": { category: "E-commerce", risk: "Low", traffic: 0 },
    "twitter.com": { category: "Social Media", risk: "Medium", traffic: 0 },
    "instagram.com": { category: "Social Media", risk: "Medium", traffic: 0 },
    "linkedin.com": { category: "Professional Network", risk: "Low", traffic: 0 },
    "netflix.com": { category: "Video Streaming", risk: "Low", traffic: 0 },
    "microsoft.com": { category: "Technology", risk: "Low", traffic: 0 },
    "apple.com": { category: "Technology", risk: "Low", traffic: 0 },
    "wikipedia.org": { category: "Reference", risk: "Low", traffic: 0 },
    "reddit.com": { category: "Social News", risk: "Medium", traffic: 0 },
    "whatsapp.com": { category: "Messaging", risk: "Low", traffic: 0 },
    "office.com": { category: "Productivity", risk: "Low", traffic: 0 },
    "zoom.us": { category: "Video Conferencing", risk: "Medium", traffic: 0 },
    "dropbox.com": { category: "Cloud Storage", risk: "Medium", traffic: 0 },
    "github.com": { category: "Development", risk: "Low", traffic: 0 },
    "stackoverflow.com": { category: "Development", risk: "Low", traffic: 0 },
    "paypal.com": { category: "Financial", risk: "High", traffic: 0 },
    "bankofamerica.com": { category: "Banking", risk: "High", traffic: 0 },
    "wellsfargo.com": { category: "Banking", risk: "High", traffic: 0 },
    "chase.com": { category: "Banking", risk: "High", traffic: 0 },
    "citibank.com": { category: "Banking", risk: "High", traffic: 0 },
    "xfinity.com": { category: "ISP", risk: "Low", traffic: 0 },
    "att.com": { category: "ISP", risk: "Low", traffic: 0 },
    "verizon.com": { category: "ISP", risk: "Low", traffic: 0 },
    "tmobile.com": { category: "ISP", risk: "Low", traffic: 0 },
    "espn.com": { category: "Sports", risk: "Low", traffic: 0 },
    "cnn.com": { category: "News", risk: "Low", traffic: 0 },
    "nytimes.com": { category: "News", risk: "Low", traffic: 0 },
    "wsj.com": { category: "News", risk: "Low", traffic: 0 }
};

// High-risk threat patterns
const highRiskThreats = [
    {
        name: "Port Scanning",
        detection: "Multiple connection attempts to different ports",
        severity: "High",
        action: "Block source IP and alert administrator"
    },
    {
        name: "DDoS Attack",
        detection: "Abnormally high traffic from multiple sources",
        severity: "High",
        action: "Enable DDoS protection and notify network team"
    },
    {
        name: "Data Exfiltration",
        detection: "Large outbound transfers to unknown destinations",
        severity: "High",
        action: "Block transfer and initiate forensic analysis"
    },
    {
        name: "Ransomware Communication",
        detection: "Communication with known ransomware C2 servers",
        severity: "Critical",
        action: "Isolate affected system immediately"
    },   
    {
        name: "Phishing Attempt",
        detection: "Suspicious redirect to fake login page",
        severity: "High",
        action: "Block domain and warn users"
    }
];

// Initialize charts   
function initCharts() {
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    state.trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'TCP',
                    data: [],
                    borderColor: '#4361ee',
                    backgroundColor: 'rgba(67, 97, 238, 0.1)',
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'UDP',
                    data: [],
                    borderColor: '#f72585',
                    backgroundColor: 'rgba(247, 37, 133, 0.1)',
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'Encrypted',
                    data: [],
                    borderColor: '#4895ef',
                    backgroundColor: 'rgba(72, 149, 239, 0.1)',
                    tension: 0.2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            },
            animation: {
                duration: 300
            }
        }
    });
    
    const distributionCtx = document.getElementById('distributionChart').getContext('2d');
    state.distributionChart = new Chart(distributionCtx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'Encrypted', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    '#4361ee',
                    '#f72585',
                    '#f8961e',
                    '#4895ef',
                    '#6c757d'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            },
            animation: {
                duration: 300
            }
        }
    });
}

// Initialize audio (for browser compatibility)
function initAudio() {
    try {
        // Create a simple beep sound
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.type = 'sine';
        oscillator.frequency.value = 800;
        gainNode.gain.value = 0.5;
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        state.alertSound = {
            play: function() {
                oscillator.start();
                setTimeout(() => {
                    oscillator.stop();
                }, 500);
            }
        };
    } catch (e) {
        console.log("Audio not supported");
    }
}

// Add AI analysis log entry
function addAILog(message) {
    const timestamp = new Date().toLocaleTimeString();
    state.aiLog.push(`[${timestamp}] ${message}`);
    
    if (state.aiLog.length > 8) {
        state.aiLog.shift();
    }
    
    aiAnalysisEl.innerHTML = state.aiLog.map(log => `<div class="analysis-line">> ${log}</div>`).join('');
    aiAnalysisEl.scrollTop = aiAnalysisEl.scrollHeight;
}

// Simulate browsing activity
function simulateBrowsingActivity() {
    if (!state.running) return;
    
    // Clear previous timer
    if (state.browsingTimer) {
        clearTimeout(state.browsingTimer);
    }
    
    // Set browsing as active
    state.browsingActivity = true;
    
    // Simulate visiting a website
    const websites = Object.keys(websiteDatabase);
    const randomWebsite = websites[Math.floor(Math.random() * websites.length)];
    
    // Update website traffic
    if (!state.websites[randomWebsite]) {
        state.websites[randomWebsite] = 0;
    }
    state.websites[randomWebsite] += Math.floor(Math.random() * 50) + 10;
    
    // Add AI log
    addAILog(`User visiting: ${randomWebsite} (${websiteDatabase[randomWebsite].category})`);
    
    // Simulate packet capture for this browsing session
    simulatePacketCapture(randomWebsite);
    
    // Set timer to stop activity after a random period
    state.browsingTimer = setTimeout(() => {
        state.browsingActivity = false;
        addAILog("Browsing activity stopped - no websites being visited");
    }, Math.random() * 10000 + 5000);
}

// Simulate packet sniffing
function simulatePacketCapture(website) {
    if (!state.browsingActivity) return;
    
    // Generate traffic based on website type
    const websiteInfo = websiteDatabase[website];
    let packetsToGenerate = 1;
    
    if (websiteInfo.category === "Video Streaming") {
        packetsToGenerate = Math.floor(Math.random() * 10) + 5;
    } else if (websiteInfo.category === "Social Media") {
        packetsToGenerate = Math.floor(Math.random() * 8) + 3;
    }
    
    for (let i = 0; i < packetsToGenerate; i++) {
        // Randomly generate different types of traffic
        const packetType = Math.random();
        
        if (packetType < 0.6) {  // 60% TCP
            state.counts.tcp++;
            
            // 20% chance of encrypted traffic
            if (Math.random() < 0.2) {
                state.counts.encrypted++;
            }
        } 
        else if (packetType < 0.9) {  // 30% UDP
            state.counts.udp++;
        } 
        else {  // 10% ICMP
            state.counts.icmp++;
        }
        
        // Track random source and destination IPs
        const sourceIP = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        const destIP = `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        
        state.sourceIPs[sourceIP] = (state.sourceIPs[sourceIP] || 0) + 1;
        state.destIPs[destIP] = (state.destIPs[destIP] || 0) + 1;
        
        // Random high-severity anomaly detection (2% chance)
        if (Math.random() < 0.02) {
            detectHighSeverityAnomaly(sourceIP, destIP, website);
       
