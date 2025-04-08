from flask import Flask, render_template, request, send_file, session, flash
import nmap
from fpdf import FPDF

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session and flash messages

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    options = request.form['options']

    if not target:
        flash('Please provide a valid IP address or hostname to scan.', 'danger')
        return render_template('index.html')

    nm = nmap.PortScanner()
    try:
        # Perform the scan
        scan_result = nm.scan(hosts=target, arguments=options)
        hosts = scan_result.get('scan', {}).keys()

        # Format results for easier reading
        results = []
        for host in hosts:
            host_info = {
                "host": host,
                "status": nm[host].state(),
                "ports": []
            }
            if 'tcp' in nm[host]:
                for port, port_data in nm[host]['tcp'].items():
                    host_info["ports"].append({
                        "port": port,
                        "state": port_data.get("state"),
                        "service": port_data.get("name"),
                    })
            results.append(host_info)

        # Save results in session
        session['scan_results'] = results
        session['target'] = target
        session['options'] = options

        return render_template('results.html', target=target, options=options, results=results)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'danger')
        return render_template('index.html')

@app.route('/download', methods=['POST'])
def download_report():
    if 'scan_results' not in session:
        flash('No scan results available. Please perform a scan first.', 'danger')
        return render_template('index.html')

    target = session['target']
    options = session['options']
    results = session['scan_results']

    # Create a PDF report in layman terms
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Title
    pdf.cell(200, 10, txt="Nmap Scan Report", ln=True, align='C')
    pdf.ln(10)

    # Scan summary
    pdf.cell(200, 10, txt=f"Target: {target}", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Scan Options: {options}", ln=True, align='L')
    pdf.ln(10)

    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Scan Results Explained:", ln=True, align='L')
    pdf.ln(5)

    for host_info in results:
        pdf.set_font("Arial", style='B', size=10)
        pdf.cell(200, 10, txt=f"Host: {host_info['host']}", ln=True, align='L')
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt=f"Status: The host is {host_info['status']}. This indicates that the device is reachable on the network.", ln=True, align='L')

        if host_info['ports']:
            pdf.ln(5)
            pdf.cell(200, 10, txt="Open Ports:", ln=True, align='L')
            for port in host_info['ports']:
                pdf.cell(200, 10, txt=f"- Port {port['port']} ({port['state']}): This port is running the {port['service']} service, typically used for {port_description(port['service'])}.", ln=True, align='L')
        else:
            pdf.cell(200, 10, txt="No open ports detected. This suggests no publicly accessible services on this host.", ln=True, align='L')

        pdf.ln(10)

    # Save and serve the PDF
    report_path = "scan_report.pdf"
    pdf.output(report_path)
    return send_file(report_path, as_attachment=True)

# Helper function to provide service descriptions
def port_description(service):
    descriptions = {
        'http': 'web servers',
        'https': 'secure web servers',
        'ftp': 'file transfer',
        'ssh': 'secure shell access',
        'smtp': 'sending emails',
        'dns': 'domain name resolution',
    }
    return descriptions.get(service, "general network communication")

if __name__ == '__main__':
    app.run(debug=True)

