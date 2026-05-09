import json
import networkx as nx
import os
from datetime import datetime

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_reports(self, graph: nx.DiGraph, timeline: list, threats: list, profiles: list):
        """
        Generates all report formats.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"investigation_{timestamp}"
        
        # 1. JSON Report
        self._write_json(graph, timeline, threats, profiles, f"{base_name}.json")
        
        # 2. GraphML (for Maltego/Gephi)
        self._write_graphml(graph, f"{base_name}.graphml")
        
        # 3. HTML Executive Summary
        return self._write_html(graph, timeline, threats, profiles, f"{base_name}.html")

    def _write_json(self, graph, timeline, threats, profiles, filename):
        data = {
            "metadata": {"generated_at": datetime.now().isoformat()},
            "threats": threats,
            "profiles": profiles,
            "timeline": timeline,
            "graph": nx.node_link_data(graph)
        }
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump(data, f, indent=2)

    def _write_graphml(self, graph, filename):
        nx.write_graphml(graph, os.path.join(self.output_dir, filename))

    def _write_html(self, graph, timeline, threats, profiles, filename):
        path = os.path.join(self.output_dir, filename)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SpiderAI Intelligence Report</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
                h1, h2 {{ color: #00d2d3; border-bottom: 1px solid #00d2d3; padding-bottom: 10px; }}
                .card {{ background: #16213e; padding: 15px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .threat {{ border-left: 5px solid #ff6b6b; }}
                .high {{ color: #ff6b6b; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #2c3e50; }}
                th {{ background: #0f3460; }}
            </style>
        </head>
        <body>
            <h1>🕷️ SpiderAI Executive Intelligence Report</h1>
            <p>Generated: {datetime.now().isoformat()}</p>
            
            <div class="card">
                <h2>🚨 Threat Summary</h2>
                <p>Total Threats Detected: <span class="high">{len(threats)}</span></p>
                <table>
                    <thead><tr><th>Type</th><th>Indicator</th><th>Severity</th></tr></thead>
                    <tbody>
                        {''.join([f"<tr><td>{t['type']}</td><td>{t['indicator']}</td><td class='high'>{t['severity']}</td></tr>" for t in threats])}
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>👤 Person Intelligence</h2>
                <p>Identified Profiles: {len(profiles)}</p>
                <ul>
                    {''.join([f"<li><strong>{p['identity']['value']}</strong> ({p['identity']['type']}) - Role: {p['role_probability']}</li>" for p in profiles])}
                </ul>
            </div>

            <div class="card">
                <h2>📅 Attack Timeline</h2>
                <table>
                    <thead><tr><th>Time</th><th>Event</th><th>Source</th><th>Target</th></tr></thead>
                    <tbody>
                        {''.join([f"<tr><td>{e['timestamp']}</td><td>{e['summary']}</td><td>{e['src']}</td><td>{e['dst']}</td></tr>" for e in timeline[:50]])}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
            
        return path

    def generate_pdf(self, graph, timeline, threats, profiles, filename, node_id=None):
        try:
            from fpdf import FPDF
        except ImportError:
            return None

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, txt="SpiderAI Intelligence Report", ln=1, align="C")
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt=f"Generated: {datetime.now().isoformat()}", ln=1, align="C")
        pdf.ln(10)

        # Filter if node_id is present
        if node_id:
            pdf.set_font("Arial", "B", 14)
            pdf.cell(200, 10, txt=f"Target Node Report: {node_id}", ln=1, align="L")
            if node_id in graph.nodes:
                node = graph.nodes[node_id]
                pdf.set_font("Arial", size=12)
                pdf.multi_cell(0, 10, txt=f"Label: {node.get('label', 'Unknown')}\nType: {node.get('type', 'Unknown')}\nProperties: {json.dumps(node.get('properties', {}), indent=2)}")
            else:
                pdf.cell(200, 10, txt="Node not found in graph.", ln=1)
            pdf.ln(10)

        # Threat Summary
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, txt=f"Threat Summary ({len(threats)} detected)", ln=1, align="L")
        pdf.set_font("Arial", size=10)
        for t in threats:
            pdf.multi_cell(0, 8, txt=f"[{t['severity'].upper()}] {t['type']}: {t['indicator']}")
        pdf.ln(5)

        # Profiles
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, txt=f"Identified Profiles ({len(profiles)})", ln=1, align="L")
        pdf.set_font("Arial", size=10)
        for p in profiles:
            pdf.multi_cell(0, 8, txt=f"- {p['identity']['value']} ({p['role_probability']})")
        pdf.ln(5)

        # Timeline
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, txt="Recent Activity", ln=1, align="L")
        pdf.set_font("Arial", size=10)
        for e in timeline[:20]: # Limit to 20 for PDF
            pdf.multi_cell(0, 8, txt=f"{e['timestamp']}: {e['summary']}")

        path = os.path.join(self.output_dir, filename)
        pdf.output(path)
        return path
