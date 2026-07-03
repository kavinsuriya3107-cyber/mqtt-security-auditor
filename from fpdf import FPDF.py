from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        # Draw a professional top accent bar
        self.set_fill_color(0, 51, 102) # Deep Industrial Blue
        self.rect(0, 0, 210, 8, 'F')
        
        # Add footer page numbers and headers dynamically on later pages
        if self.page_no() > 1:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, "PowerGuard AI — MSME Idea Hackathon 6.0", 0, 0, "L")
            self.ln(10)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        # Page number
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

pdf = PDF()
pdf.set_auto_page_break(auto=True, margin=15)

# --- PAGE 1: COVER ---
pdf.add_page()
pdf.set_font("Helvetica", "B", 26)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 40, "PowerGuard AI", 0, 1, "C")

pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(102, 102, 102)
pdf.cell(0, 10, "MSME Idea Hackathon 6.0", 0, 1, "C")
pdf.cell(0, 10, 'Focus Track: Industry 4.0 & 5.0', 0, 1, "C")
pdf.ln(15)

pdf.set_font("Helvetica", "I", 12)
pdf.set_text_color(0, 102, 204)
pdf.cell(0, 10, '"Predict. Protect. Prevent."', 0, 1, "C")
pdf.ln(10)

pdf.set_font("Helvetica", "", 11)
pdf.set_text_color(0, 0, 0)
proposal_intro = "A dual-monitoring system that protects MSME machinery from both physical failure and unauthorized digital access."
pdf.multi_cell(0, 6, proposal_intro, align="C")
pdf.ln(20)

# Project Metadata Table
pdf.set_fill_color(240, 244, 248)
pdf.set_font("Helvetica", "B", 11)
pdf.cell(70, 10, " Field", 1, 0, "L", True)
pdf.cell(120, 10, " Detail", 1, 1, "L", True)

pdf.set_font("Helvetica", "", 10)
details = [
    ("Team Size", "4 members"),
    ("Communication", "Wi-Fi / HTTPS REST API"),
    ("Prototype Cost", "Rs. 2,500 - 4,500 per unit"),
    ("Target Selling Price", "Rs. 6,000 - 9,000 per unit"),
    ("Host Institute", "Dr. Mahalingam College of Engineering and Technology (MCET)")
]
for field, detail in details:
    pdf.cell(70, 8, f" {field}", 1, 0, "L")
    pdf.cell(120, 8, f" {detail}", 1, 1, "L")

# --- PAGE 2: PROBLEM & SOLUTION ---
pdf.add_page()
pdf.set_font("Helvetica", "B", 16)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "The Problem", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)

pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(0, 0, 0)
prob_text = ("MSMEs adopting Industry 4.0 sensors face two separate, growing risks, and today, "
             "nobody affordable is watching either one:\n\n"
             "1. Physical / Electrical Risk: Loose electrical plugs and connections that overheat silently; "
             "overheated sockets that go unnoticed until they trip power or cause fire risk; damaged or "
             "degrading cables; failing motors and bearings showing early vibration warnings.\n\n"
             "2. Digital Risk: As MSMEs connect sensors and machines to Wi-Fi, they create a network with no "
             "security team watching it. Unauthorized devices, spoofed readings, or basic attacks on the "
             "monitoring system itself go completely undetected. A monitoring system that is not itself secured "
             "becomes a new attack surface, not a solution.\n\n"
             "Today these are treated as two unrelated problems, requiring two unrelated, expensive tools. "
             "Maintenance in most small factories is reactive on both fronts.")
pdf.multi_cell(0, 6, prob_text)
pdf.ln(10)

pdf.set_font("Helvetica", "B", 16)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "Our Solution", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)

pdf.set_font("Helvetica", "", 10)
sol_text = ("PowerGuard AI is a dual-monitoring system that watches machine health and secures its own data "
             "pipeline at the same time—one affordable device, two real protections.\n\n"
             "• Sensing Smart Plug: Voltage monitoring, current draw monitoring, plug and socket temperature tracking, "
             "and overheating detection at the connection point.\n\n"
             "• Machine Health Patch: Vibration monitoring (bearing wear, imbalance) and machine body temperature tracking.\n\n"
             "• Secured ML API Backend: Both units send readings to our own FastAPI backend over Wi-Fi/HTTPS with no "
             "third-party cloud dependency. Every request is authenticated using JWT tokens, protecting the backend from "
             "malformed payloads.")
pdf.multi_cell(0, 6, sol_text)

# --- PAGE 3: ML LAYER & DIFFERENTIATORS ---
pdf.add_page()
pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "The Intelligence Layer: Machine Learning Anomaly Detection", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)

pdf.set_font("Helvetica", "", 10)
ml_text = ("The gateway logic processes electrical and mechanical readings through a pre-trained, lightweight "
           "Machine Learning model (such as an Isolation Forest via Python's scikit-learn library) hosted on the FastAPI backend.\n\n"
           "Instead of waiting for a temperature or vibration level to cross a dangerous, static threshold (reactive alerting), "
           "the ML model analyzes incoming multi-variable data in real time to catch mathematical deviations from normal "
           "operational behavior. This allows the backend to classify whether a developing fault is electrical, mechanical, "
           "or both, well before a physical failure occurs, while the API layer ensures the data driving that decision can be trusted.")
pdf.multi_cell(0, 6, ml_text)
pdf.ln(10)

pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "What Makes This Different", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)
pdf.set_font("Helvetica", "", 10)
diff_text = ("Enterprise industrial monitoring platforms already combine sensor fusion and cybersecurity—this is an active, "
             "published research area. Our contribution is making both data-layer security and machine learning-driven predictive "
             "insights available in a single low-cost device that an MSME with no IT team can install and trust.")
pdf.multi_cell(0, 6, diff_text)
pdf.ln(10)

pdf.set_font("Helvetica", "B", 11)
pdf.set_text_color(153, 0, 0)
pdf.cell(0, 6, "Honesty Note for Judges:", 0, 1, "L")
pdf.set_font("Helvetica", "I", 10)
pdf.set_text_color(0, 0, 0)
honesty_text = ("We do not claim this is patentable or first-of-its-kind. Sensor-fusion fault diagnosis, machine learning "
                "anomaly detection, and IoT security monitoring all exist in research and enterprise products today. Our strength "
                "is affordability, integration, and demonstrating real, accessible value to MSMEs currently priced out of these categories.")
pdf.multi_cell(0, 6, honesty_text)

# --- PAGE 4: SYSTEM ARCHITECTURE & DEMO ---
pdf.add_page()
pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "System Architecture", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)

pdf.set_font("Helvetica", "", 10)
arch_text = ("1. Sensing: Smart Plug Unit (ACS712 current + DS18B20 temperature) monitors the wall socket connection. "
             "Machine Patch (MPU6050 accelerometer + DS18B20) is mounted directly on equipment.\n\n"
             "2. Transmission: Both ESP32 units send readings over Wi-Fi as authenticated HTTPS POST requests directly to the API endpoint.\n\n"
             "3. Secured API Layer: A FastAPI backend receives readings via a JWT-authenticated REST endpoint (POST /api/readings). "
             "Requests without a valid token are rejected and logged.\n\n"
             "4. ML Inference & Fault Logic: The backend passes the incoming payload into the pre-trained scikit-learn model. "
             "The model computes an anomaly score. Combined with safety thresholds, the system classifies operational health.\n\n"
             "5. Alerting: Local relay and buzzer trigger for urgent conditions; the API pushes alerts to the mobile dashboard.\n\n"
             "6. Dashboard: The mobile dashboard consumes the same secured API (GET /api/status, GET /api/alerts) to show live status.")
pdf.multi_cell(0, 6, arch_text)
pdf.ln(10)

pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "Live Demo Plan", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)
pdf.set_font("Helvetica", "", 10)
demo_text = ("• Security Layer: The API rejecting an unauthorized request sent without a valid JWT token in real time.\n"
             "• Intelligence Layer: The backend receiving standard data versus data simulated to represent a failing bearing, "
             "showing how the ML algorithm instantly flags the anomaly even before hard safety thresholds are crossed.")
pdf.multi_cell(0, 6, demo_text)

# --- PAGE 5: TECH SPECIFICATIONS & MARKET ---
pdf.add_page()
pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "Hardware & Software Specifications", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)

pdf.set_font("Helvetica", "", 10)
specs_text = ("• Smart Plug Unit: ESP32, ACS712 current sensor, DS18B20 temperature sensor, Relay module, Buzzer + status LEDs.\n"
              "• Machine Health Patch: ESP32, MPU6050 accelerometer, DS18B20 temperature sensor, Battery pack.\n"
              "• Software Stack:\n"
              "   - Firmware: Embedded C, Arduino IDE\n"
              "   - Backend & ML Pipeline: FastAPI (Python), Scikit-learn (Isolation Forest model deployment)\n"
              "   - Device & Request Authentication: JWT (JSON Web Tokens)\n"
              "   - Communication Layer: Wi-Fi / HTTPS REST API\n"
              "   - Dashboard: Simple web/mobile dashboard consuming the API")
pdf.multi_cell(0, 6, specs_text)
pdf.ln(10)

pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "Target Market & Market Comparison", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)
pdf.set_font("Helvetica", "", 10)
market_text = ("Primary Target: Factories and MSMEs. Secondary markets include Hospitals, Data Centers, Universities, "
               "Railways, and EV charging stations.\n\n"
               "How We Compare: Enterprise industrial monitoring platforms typically cost lakhs of rupees per year in licensing "
               "and installation. Most Indian MSMEs adopting Industry 4.0 sensors have no equivalent budget or technical staff, "
               "leaving devices with zero security and zero predictive analytics. PowerGuard AI targets that exact gap: equipment "
               "health monitoring, integrated ML anomaly tracking, and data-layer security together at hardware cost.")
pdf.multi_cell(0, 6, market_text)

# --- PAGE 6: BUSINESS MODEL & RESPONSIBILITIES ---
pdf.add_page()
pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "Business Model", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)

pdf.set_fill_color(240, 244, 248)
pdf.set_font("Helvetica", "B", 10)
pdf.cell(95, 8, " Item", 1, 0, "L", True)
pdf.cell(95, 8, " Value", 1, 1, "L", True)
pdf.set_font("Helvetica", "", 10)
biz = [("Device Manufacturing Cost", "Rs. 2,500 - 4,500"), ("Selling Price Per Unit", "Rs. 6,000 - 9,000"), ("Dashboard Subscription", "Rs. 199 / month")]
for item, val in biz:
    pdf.cell(95, 8, f" {item}", 1, 0, "L")
    pdf.cell(95, 8, f" {val}", 1, 1, "L")
pdf.ln(10)

pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "Team Responsibilities", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)
pdf.set_font("Helvetica", "B", 10)
pdf.cell(60, 8, " Role / Member", 1, 0, "L", True)
pdf.cell(130, 8, " Responsibility", 1, 1, "L", True)
pdf.set_font("Helvetica", "", 10)
team = [("Kavinsuriya", "Embedded systems + API security & ML model integration"), ("Member 2", "Circuit design"), ("Member 3", "App + dashboard"), ("Member 4", "Presentation, business case, and market research")]
for name, resp in team:
    pdf.cell(60, 8, f" {name}", 1, 0, "L")
    pdf.cell(130, 8, f" {resp}", 1, 1, "L")

# --- PAGE 7: BUILD PLAN ---
pdf.add_page()
pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "13-Day Accelerated Build Plan", 0, 1, "L")
pdf.line(10, pdf.get_y(), 200, pdf.get_y())
pdf.ln(5)
pdf.set_font("Helvetica", "", 10)
plan_text = ("Paced efficiently across all 4 team members to meet the July 14th final submission deadline:\n\n"
             "• Deliverable 1: Professional proposal document and 10-12 slide pitch deck.\n"
             "• Deliverable 2: System architecture block diagrams and verified hardware circuit designs.\n"
             "• Deliverable 3: ESP32 firmware optimizing Wi-Fi data packet transmission over standard HTTPS REST endpoints.\n"
             "• Deliverable 4: Functional FastAPI backend with active JWT authorization, rate limiting, and access logging.\n"
             "• Deliverable 5: Integrated scikit-learn anomaly detection script deployed directly within backend runtime.\n"
             "• Deliverable 6: Clean mobile/web dashboard UI processing incoming alerts and live status parameters.\n"
             "• Deliverable 7: Live demo validation script proving both a physical machine anomaly flag and an API security block.")
pdf.multi_cell(0, 6, plan_text)

pdf.output("PowerGuard_AI_Pitch_v2.pdf")
print("PDF Generated Successfully as PowerGuard_AI_Pitch_v2.pdf")