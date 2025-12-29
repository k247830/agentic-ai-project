"""
PHASE 7: FastAPI Demo Application
REST API for incident analysis system with web interface
"""
import sys
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import json
import pandas as pd
from datetime import datetime
from pathlib import Path
import io

sys.path.append(str(Path(__file__).parent.parent))
# Import system components
from ingestion.parser import DataNormalizer
from orchestrator.orchestrator import IncidentOrchestrator

app = FastAPI(
    title="Security Incident Analysis System",
    description="Multi-Agent Cybersecurity Incident Response Platform",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for demo
analysis_results = {}

# Initialize components
normalizer = DataNormalizer()
orchestrator = IncidentOrchestrator()


class AnalysisStatus(BaseModel):
    status: str
    message: str
    incident_id: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve demo web interface"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Incident Analysis System</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .container {
                background: white;
                border-radius: 15px;
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }
            h1 {
                color: #667eea;
                text-align: center;
                margin-bottom: 10px;
            }
            .subtitle {
                text-align: center;
                color: #666;
                margin-bottom: 30px;
            }
            .upload-section {
                border: 3px dashed #667eea;
                border-radius: 10px;
                padding: 40px;
                text-align: center;
                margin-bottom: 30px;
                background: #f8f9ff;
            }
            .btn {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px 30px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
                font-weight: bold;
                transition: transform 0.2s;
            }
            .btn:hover {
                transform: scale(1.05);
            }
            .results {
                display: none;
                margin-top: 30px;
            }
            .alert {
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
            }
            .alert-danger {
                background: #fee;
                border-left: 4px solid #f44;
                color: #c33;
            }
            .alert-success {
                background: #efe;
                border-left: 4px solid #4f4;
                color: #3c3;
            }
            .alert-warning {
                background: #ffeaa7;
                border-left: 4px solid #fdcb6e;
                color: #d63031;
            }
            .metric-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .metric-card {
                background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
                padding: 20px;
                border-radius: 10px;
                border-left: 4px solid #667eea;
            }
            .metric-value {
                font-size: 32px;
                font-weight: bold;
                color: #667eea;
            }
            .metric-label {
                color: #666;
                margin-top: 5px;
            }
            .timeline {
                background: #f8f9ff;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
            }
            .timeline-item {
                padding: 15px;
                border-left: 3px solid #667eea;
                margin-left: 20px;
                margin-bottom: 15px;
                background: white;
                border-radius: 5px;
            }
            .action-list {
                list-style: none;
                padding: 0;
            }
            .action-item {
                padding: 15px;
                margin: 10px 0;
                background: #f8f9ff;
                border-radius: 8px;
                border-left: 4px solid #667eea;
            }
            .loading {
                text-align: center;
                padding: 40px;
                display: none;
            }
            .spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid #667eea;
                border-radius: 50%;
                width: 50px;
                height: 50px;
                animation: spin 1s linear infinite;
                margin: 0 auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .section {
                margin: 30px 0;
                padding: 20px;
                background: #f8f9ff;
                border-radius: 10px;
            }
            .section-title {
                color: #667eea;
                font-size: 20px;
                font-weight: bold;
                margin-bottom: 15px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Security Incident Analysis System</h1>
            <p class="subtitle">Multi-Agent AI-Powered Cybersecurity Platform</p>

            <div class="upload-section">
                <h3>📁 Upload Attack Logs</h3>
                <p>Upload CICIDS2017 CSV file or normalized JSON events</p>
                <input type="file" id="fileInput" accept=".csv,.json" style="margin: 20px 0;">
                <br>
                <button class="btn" onclick="analyzeFile()">🔍 Analyze Security Events</button>
            </div>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Analyzing security events with AI agents...</p>
            </div>

            <div class="results" id="results"></div>
        </div>

        <script>
            async function analyzeFile() {
                const fileInput = document.getElementById('fileInput');
                const file = fileInput.files[0];

                if (!file) {
                    alert('Please select a file first');
                    return;
                }

                const loading = document.getElementById('loading');
                const results = document.getElementById('results');

                loading.style.display = 'block';
                results.style.display = 'none';

                const formData = new FormData();
                formData.append('file', file);

                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        body: formData
                    });

                    const data = await response.json();

                    loading.style.display = 'none';
                    displayResults(data);

                } catch (error) {
                    loading.style.display = 'none';
                    alert('Error analyzing file: ' + error.message);
                }
            }

            function displayResults(report) {
                const results = document.getElementById('results');

                if (report.status === 'No Incidents Detected') {
                    results.innerHTML = `
                        <div class="alert alert-success">
                            <h3>✅ System Secure</h3>
                            <p>${report.executive_summary}</p>
                            <p>Total events analyzed: ${report.analysis_metadata.total_events_analyzed}</p>
                        </div>
                    `;
                    results.style.display = 'block';
                    return;
                }

                const severity = report.severity_assessment.overall_severity;
                const alertClass = severity === 'Critical' ? 'alert-danger' : 
                                  severity === 'High' ? 'alert-warning' : 'alert-success';

                results.innerHTML = `
                    <div class="alert ${alertClass}">
                        <h3>🚨 Security Incident Detected</h3>
                        <p><strong>Incident ID:</strong> ${report.incident_id}</p>
                        <p><strong>Severity:</strong> ${severity}</p>
                        <p>${report.severity_assessment.severity_justification}</p>
                    </div>

                    <div class="metric-grid">
                        <div class="metric-card">
                            <div class="metric-value">${report.attack_intelligence.total_attacks_detected}</div>
                            <div class="metric-label">Attacks Detected</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">$${report.business_impact.financial_impact_usd.toLocaleString()}</div>
                            <div class="metric-label">Estimated Loss</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.business_impact.affected_assets}</div>
                            <div class="metric-label">Affected Assets</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.incident_response.estimated_response_time_hours}h</div>
                            <div class="metric-label">Response Time</div>
                        </div>
                    </div>

                    <div class="section">
                        <div class="section-title">🎯 Attack Intelligence</div>
                        ${report.attack_intelligence.attack_breakdown.map(attack => `
                            <div class="metric-card">
                                <strong>${attack.attack_type}</strong><br>
                                MITRE Technique: ${attack.mitre_technique} - ${attack.technique_name}<br>
                                Severity: ${attack.severity} | Confidence: ${(attack.confidence * 100).toFixed(1)}%<br>
                                Events: ${attack.event_count}
                            </div>
                        `).join('')}
                    </div>

                    <div class="section">
                        <div class="section-title">⚠️ Immediate Actions Required</div>
                        <ul class="action-list">
                            ${report.incident_response.immediate_actions.slice(0, 5).map(action => `
                                <li class="action-item">
                                    <strong>${action.phase}:</strong> ${action.action}<br>
                                    <small>Attack Type: ${action.attack_type}</small>
                                </li>
                            `).join('')}
                        </ul>
                    </div>

                    <div class="section">
                        <div class="section-title">📊 Business Impact</div>
                        <p><strong>Data at Risk:</strong></p>
                        <ul>
                            ${report.business_impact.data_at_risk.map(risk => `<li>${risk}</li>`).join('')}
                        </ul>

                        ${report.business_impact.compliance_violations.length > 0 ? `
                            <p><strong>⚖️ Compliance Violations:</strong></p>
                            <ul>
                                ${report.business_impact.compliance_violations.map(v => `
                                    <li>${v.framework}: ${v.risk} ${v.notification_required ? '(Notification required within ' + v.deadline_hours + 'h)' : ''}</li>
                                `).join('')}
                            </ul>
                        ` : ''}
                    </div>

                    <div class="section">
                        <div class="section-title">💡 Strategic Recommendations</div>
                        <ul class="action-list">
                            ${report.recommendations.map(rec => `
                                <li class="action-item">
                                    <strong>[${rec.priority}] ${rec.category}:</strong> ${rec.recommendation}<br>
                                    <small><em>${rec.rationale}</em></small>
                                </li>
                            `).join('')}
                        </ul>
                    </div>

                    <div class="section">
                        <div class="section-title">📈 Analysis Metadata</div>
                        <p>Processing Time: ${report.analysis_metadata.processing_time_seconds}s</p>
                        <p>Total Events: ${report.analysis_metadata.total_events_analyzed}</p>
                        <p>Malicious Events: ${report.analysis_metadata.malicious_events}</p>
                        <p>Agents: ${report.analysis_metadata.agents_used.join(', ')}</p>
                    </div>
                `;

                results.style.display = 'block';
            }
        </script>
    </body>
    </html>
    """


@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Analyze uploaded security logs
    Accepts CSV (CICIDS2017) or JSON (normalized events)
    """

    try:
        # Read file content
        content = await file.read()

        # Determine file type and process
        if file.filename.endswith('.csv'):
            # Process CSV file
            df = pd.read_csv(io.BytesIO(content))

            # Normalize events
            events = []
            for _, row in df.iterrows():
                try:
                    event = normalizer.normalize_cicids_event(row)
                    events.append(event)
                except Exception as e:
                    continue

        elif file.filename.endswith('.json'):
            # Load JSON directly
            events = json.loads(content.decode('utf-8'))

        else:
            raise HTTPException(status_code=400, detail="Unsupported file format. Use CSV or JSON.")

        if not events:
            raise HTTPException(status_code=400, detail="No valid events found in file")

        # Run analysis through orchestrator
        report = orchestrator.analyze_incident(events, save_intermediates=False)

        # Store result
        incident_id = report.get('incident_id', report.get('report_id'))
        analysis_results[incident_id] = report

        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/report/{incident_id}")
async def get_report(incident_id: str):
    """Retrieve a previously generated report"""

    if incident_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Report not found")

    return analysis_results[incident_id]


@app.get("/reports")
async def list_reports():
    """List all available reports"""

    reports = []
    for incident_id, report in analysis_results.items():
        reports.append({
            "incident_id": incident_id,
            "generated_at": report.get('generated_at'),
            "severity": report.get('severity_assessment', {}).get('overall_severity', 'Unknown'),
            "attacks": report.get('attack_intelligence', {}).get('total_attacks_detected', 0)
        })

    return {"total_reports": len(reports), "reports": reports}


@app.get("/health")
async def health_check():
    """API health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "agents": ["Attack Tracer", "Impact Analyst", "Incident Responder"]
    }


@app.get("/api/docs-info")
async def api_info():
    """API information and usage guide"""
    return {
        "title": "Security Incident Analysis System API",
        "description": "Multi-agent AI platform for cybersecurity incident response",
        "endpoints": {
            "POST /analyze": "Upload and analyze security logs (CSV/JSON)",
            "GET /report/{incident_id}": "Retrieve specific incident report",
            "GET /reports": "List all analyzed incidents",
            "GET /health": "API health check"
        },
        "supported_formats": ["CICIDS2017 CSV", "Normalized JSON events"],
        "agents": [
            {
                "name": "Attack Tracer",
                "function": "Detects attacks and maps to MITRE ATT&CK"
            },
            {
                "name": "Impact Analyst",
                "function": "Assesses business impact and compliance risks"
            },
            {
                "name": "Incident Responder",
                "function": "Generates actionable response plans"
            }
        ]
    }


if __name__ == "__main__":
    import uvicorn

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║   🛡️  SECURITY INCIDENT ANALYSIS SYSTEM API                 ║
    ║                                                              ║
    ║   Multi-Agent AI-Powered Cybersecurity Platform             ║
    ║                                                              ║
    ║   📡 API Documentation: http://localhost:8000/docs          ║
    ║   🌐 Web Interface: http://localhost:8000                   ║
    ║   💚 Health Check: http://localhost:8000/health             ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8000)