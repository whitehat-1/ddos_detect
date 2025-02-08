from inspect import Traceback
from fastapi import FastAPI, Request, Form
from typing import Union
from fastapi.responses import HTMLResponse
import dpkt
import os
import traceback
from collections import defaultdict

app = FastAPI()

def detect_ddos(pcap_file):
    packet_count = 0
    ip_count = defaultdict(int)

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        for timestamp, buf in pcap:
            packet_count += 1
            eth = dpkt.ethernet.Ethernet(buf)
            
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                ip_count[ip.src] += 1

    threshold = 100
    ddos_detected = False
    for ip, count in ip_count.items():
        if count > threshold:
            ddos_detected = True
            break

    return ddos_detected, packet_count

@app.get("/", response_class=HTMLResponse)
async def index():
    html_content = """
    <html>
    <head>
        <title>DDoS Detection</title>
    </head>
    <body>
        <h1>DDoS Detection</h1>
        <form action="/" method="post">
            <button type="submit">Run Test</button>
        </form>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/", response_class=HTMLResponse)
async def run_test(request: Request):
    try:
        form_data = await request.form()
        folder_path = r"C:\Users\Admin\Desktop\ddos_detect"
        results = []
        for file_name in os.listdir(folder_path):
            if file_name.endswith(".pcap"):
                pcap_file = os.path.join(folder_path, file_name)
                ddos_detected, packet_count = detect_ddos(pcap_file)
                result = {
                    'file_name': file_name,
                    'packet_count': packet_count,
                    'ddos_detected': ddos_detected
                }
                results.append(result)
        html_content = """
        <html>
        <head>
            <title>DDoS Detection Results</title>
        </head>
        <body>
            <h1>DDoS Detection Results</h1>
            <h2>Results:</h2>
            <ul>
        """
        for result in results:
            html_content += f"""
                <li>
                    <p>PCAP File: {result['file_name']}</p>
                    <p>Packet Count: {result['packet_count']}</p>
                    <p>{'DDoS attack detected!' if result['ddos_detected'] else 'No DDoS attack detected.'}</p>
                </li>
            """
        html_content += """
            </ul>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)
    except Exception as e:
        traceback.print_exc()  # Print traceback to the console
        return HTMLResponse(content=f"<h1>Internal Server Error</h1><p>{str(e)}</p>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
