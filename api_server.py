from flask import Flask, request, jsonify
import sys
import os

sys.path.append('/opt/ids-detector/scripts')

app = Flask(__name__)

class IDSAPI:
    def __init__(self):
        self.ml_detector = None
        self.dl_detector = None
        self.load_detectors()
    
    def load_detectors(self):
        try:
            from ml_ids_deployment_original import ML_IDS
            self.ml_detector = ML_IDS("dummy", "dummy")
            print("✅ ML Detector loaded (EXACT ORIGINAL LOGIC)")
        except Exception as e:
            print(f"❌ ML Detector failed: {e}")
            import traceback
            traceback.print_exc()
        
        try:
            from dl_ids_deployment_fixed import AEAnomalyDetector
            self.dl_detector = AEAnomalyDetector(
                "/opt/ids-detector/models/dl_models/mlp_best_numeric_autoencoder.pth",
                "/opt/ids-detector/models/dl_models/all_error.pkl", 
                "/opt/ids-detector/models/dl_models/scaler.pkl"
            )
            print("✅ DL Detector loaded")
        except Exception as e:
            print(f"❌ DL Detector failed: {e}")
            import traceback
            traceback.print_exc()

ids_api = IDSAPI()

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "ml_loaded": ids_api.ml_detector is not None,
        "dl_loaded": ids_api.dl_detector is not None
    })

@app.route('/detect/ml/packets', methods=['POST'])
def detect_ml_from_packets():
    """Accept packet list (base64) and convert to client-compatible ML response"""
    try:
        import base64
        import tempfile
        from scapy.all import wrpcap
        from scapy.layers.l2 import Ether

        data = request.get_json()
        if not data or 'packets' not in data:
            return jsonify({"error": "Missing 'packets' field - should be list of base64-encoded packet bytes"}), 400

        if not ids_api.ml_detector:
            return jsonify({"error": "ML detector not available"}), 500

        # Decode packets
        packets = []
        for idx, pkt_b64 in enumerate(data['packets']):
            try:
                pkt_bytes = base64.b64decode(pkt_b64)
                pkt = Ether(pkt_bytes)
                packets.append(pkt)
            except Exception as e:
                print(f"[WARN] Failed to decode packet {idx}: {e}")

        if not packets:
            return jsonify({"error": "No valid packets could be decoded"}), 400

        # Write to temp PCAP
        temp_pcap = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap', dir='/tmp')
        temp_path = temp_pcap.name
        temp_pcap.close()
        wrpcap(temp_path, packets)

        # Convert to base64 for ML detector
        with open(temp_path, 'rb') as f:
            pcap_content = base64.b64encode(f.read()).decode('utf-8')
        os.remove(temp_path)

        # Call original ML detector
        results = ids_api.ml_detector.bootstrap({
            "filename": "converted.pcap",
            "content": pcap_content
        })

        if "error" in results:
            return jsonify(results), 500

        # Transform into client-compatible response
        attack_types = ["DDoS", "Brute_Force", "Web_Attack", "Port_Scanning", "Infiltration", "Botnet"]
        response = {
            "detector": "ML_IDS",
            "summary": {
                "total_flows": results.get("total_flows", 0),
                "benign_flows": results.get("benign_flows", 0),
                "attack_flows": sum(results.get("attacks", {}).get(at, {}).get("count", 0) for at in attack_types)
            },
            "detailed_results": {}
        }

        for at in attack_types:
            attack_data = results.get("attacks", {}).get(at, {"count": 0, "flows": []})
            response["detailed_results"][f"{at.lower()}_flows"] = {
                "count": attack_data.get("count", 0),
                "flows": attack_data.get("flows", [])
            }

        return jsonify(response)

    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        print(f"[ERROR] ML/PACKETS failed:\n{error_msg}")
        return jsonify({"error": str(e), "traceback": error_msg}), 500

@app.route('/detect/dl/packets', methods=['POST'])
def detect_dl_from_packets():
    """Accept packet list (base64) and convert to DL response"""
    try:
        import base64
        import tempfile
        from scapy.all import wrpcap
        from scapy.layers.l2 import Ether

        data = request.get_json()
        if not data or 'packets' not in data:
            return jsonify({"error": "Missing 'packets' field"}), 400

        if not ids_api.dl_detector:
            return jsonify({"error": "DL detector not available"}), 500

        packets = []
        for idx, pkt_b64 in enumerate(data['packets']):
            try:
                pkt_bytes = base64.b64decode(pkt_b64)
                pkt = Ether(pkt_bytes)
                packets.append(pkt)
            except Exception as e:
                print(f"[WARN] Failed to decode packet {idx}: {e}")

        if not packets:
            return jsonify({"error": "No valid packets could be decoded"}), 400

        temp_pcap = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap', dir='/tmp')
        temp_path = temp_pcap.name
        temp_pcap.close()
        wrpcap(temp_path, packets)

        with open(temp_path, 'rb') as f:
            pcap_content = base64.b64encode(f.read()).decode('utf-8')
        os.remove(temp_path)

        results = ids_api.dl_detector.bootstrap({
            "filename": "converted.pcap",
            "content": pcap_content
        })

        if "error" in results:
            return jsonify(results), 500

        return jsonify({
            "detector": "DL_IDS",
            "status": 200,
            "summary": {
                "total_flows": results.get("total_flows", 0),
                "benign_flows": results.get("benign_flows", 0),
                "anomaly_flows": results.get("anomaly_flows", {}).get("count", 0)
            },
            "detailed_results": {
                "anomaly_flows": results.get("anomaly_flows", {}).get("flows", [])
            }
        })

    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        print(f"[ERROR] DL/PACKETS failed:\n{error_msg}")
        return jsonify({"error": str(e), "traceback": error_msg}), 500

if __name__ == '__main__':
    print("🚀 Starting IDS Detector API Server with EXACT ORIGINAL ML Logic...")
    app.run(host='0.0.0.0', port=8080, debug=False)
