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

@app.route('/detect/ml', methods=['POST'])
def detect_ml():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        if 'content' not in data:
            return jsonify({"error": "Missing 'content' field"}), 400
        
        if not ids_api.ml_detector:
            return jsonify({"error": "ML detector not available"}), 500
        
        results = ids_api.ml_detector.bootstrap(data)
        
        if "error" in results:
            return jsonify(results), 500
        
        response = {
            "detector": "ML_IDS",
            "summary": {
                "total_flows": results.get("total_flows", 0),
                "benign_flows": results.get("benign_flows", 0),
                "attack_flows": sum(attack["count"] for attack in results.get("attacks", {}).values())
            },
            "detailed_results": {}
        }
        
        for attack_type, attack_data in results.get("attacks", {}).items():
            response["detailed_results"][f"{attack_type.lower()}_flows"] = {
                "count": attack_data["count"],
                "flows": [
                    {
                        "src_ip": flow.get('src_ip', 'N/A'),
                        "dst_ip": flow.get('dst_ip', 'N/A'), 
                        "src_port": flow.get('src_port', 'N/A'),
                        "dst_port": flow.get('dst_port', 'N/A'),
                        "attack_type": flow.get('attack', 'N/A')
                    } for flow in attack_data.get("flows", [])
                ]
            }
        
        return jsonify(response)
        
    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500

@app.route('/detect/dl', methods=['POST'])
def detect_dl():
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({"error": "Missing 'content' field"}), 400
        
        if not ids_api.dl_detector:
            return jsonify({"error": "DL detector not available"}), 500
            
        results = ids_api.dl_detector.bootstrap(data)
        
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
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500

@app.route('/detect/ml/packets', methods=['POST'])
def detect_ml_from_packets():
    """Accept packet list (as raw bytes) and convert to PCAP for ML detection"""
    try:
        import base64
        import tempfile
        
        data = request.get_json()
        if not data or 'packets' not in data:
            return jsonify({"error": "Missing 'packets' field - should be list of base64-encoded packet bytes"}), 400
        
        if not ids_api.ml_detector:
            return jsonify({"error": "ML detector not available"}), 500
        
        print(f"[ML/PACKETS] Received {len(data['packets'])} packets")
        
        # Import scapy here to catch import errors
        try:
            from scapy.all import wrpcap, Raw
            from scapy.layers.l2 import Ether
        except ImportError as ie:
            return jsonify({"error": f"Scapy not available on server: {ie}"}), 500
        
        # Rebuild packets from raw bytes
        packets = []
        for idx, pkt_b64 in enumerate(data['packets']):
            try:
                pkt_bytes = base64.b64decode(pkt_b64)
                pkt = Ether(pkt_bytes)
                packets.append(pkt)
            except Exception as e:
                print(f"[WARN] Failed to decode packet {idx}: {e}")
                continue
        
        if not packets:
            return jsonify({"error": "No valid packets could be decoded"}), 400
        
        print(f"[ML/PACKETS] Successfully decoded {len(packets)} packets")
        
        # Write to temp PCAP file
        temp_pcap = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap', dir='/tmp')
        temp_path = temp_pcap.name
        temp_pcap.close()
        
        wrpcap(temp_path, packets)
        print(f"[ML/PACKETS] Wrote PCAP to {temp_path}")
        
        # Convert to base64
        with open(temp_path, 'rb') as f:
            pcap_content = base64.b64encode(f.read()).decode('utf-8')
        
        os.remove(temp_path)
        
        # Use existing ML detection logic
        results = ids_api.ml_detector.bootstrap({
            "filename": "converted.pcap",
            "content": pcap_content
        })
        
        if "error" in results:
            return jsonify(results), 500
        
        response = {
            "detector": "ML_IDS",
            "summary": {
                "total_flows": results.get("total_flows", 0),
                "benign_flows": results.get("benign_flows", 0),
                "attack_flows": sum(attack["count"] for attack in results.get("attacks", {}).values())
            },
            "detailed_results": {}
        }
        
        for attack_type, attack_data in results.get("attacks", {}).items():
            response["detailed_results"][f"{attack_type.lower()}_flows"] = {
                "count": attack_data["count"],
                "flows": attack_data.get("flows", [])
            }
        
        return jsonify(response)
        
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        print(f"[ERROR] ML/PACKETS failed:\n{error_msg}")
        return jsonify({
            "error": str(e),
            "traceback": error_msg
        }), 500

@app.route('/detect/dl/packets', methods=['POST'])
def detect_dl_from_packets():
    """Accept packet list (as raw bytes) and convert to PCAP for DL detection"""
    try:
        import base64
        import tempfile
        
        data = request.get_json()
        if not data or 'packets' not in data:
            return jsonify({"error": "Missing 'packets' field - should be list of base64-encoded packet bytes"}), 400
        
        if not ids_api.dl_detector:
            return jsonify({"error": "DL detector not available"}), 500
        
        print(f"[DL/PACKETS] Received {len(data['packets'])} packets")
        
        # Import scapy here to catch import errors
        try:
            from scapy.all import wrpcap
            from scapy.layers.l2 import Ether
        except ImportError as ie:
            return jsonify({"error": f"Scapy not available on server: {ie}"}), 500
        
        # Rebuild packets from raw bytes
        packets = []
        for idx, pkt_b64 in enumerate(data['packets']):
            try:
                pkt_bytes = base64.b64decode(pkt_b64)
                pkt = Ether(pkt_bytes)
                packets.append(pkt)
            except Exception as e:
                print(f"[WARN] Failed to decode packet {idx}: {e}")
                continue
        
        if not packets:
            return jsonify({"error": "No valid packets could be decoded"}), 400
        
        print(f"[DL/PACKETS] Successfully decoded {len(packets)} packets")
        
        # Write to temp PCAP file
        temp_pcap = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap', dir='/tmp')
        temp_path = temp_pcap.name
        temp_pcap.close()
        
        wrpcap(temp_path, packets)
        print(f"[DL/PACKETS] Wrote PCAP to {temp_path}")
        
        # Convert to base64
        with open(temp_path, 'rb') as f:
            pcap_content = base64.b64encode(f.read()).decode('utf-8')
        
        os.remove(temp_path)
        
        # Use existing DL detection logic
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
        return jsonify({
            "error": str(e),
            "traceback": error_msg
        }), 500

if __name__ == '__main__':
    print("🚀 Starting IDS Detector API Server with EXACT ORIGINAL ML Logic...")
    app.run(host='0.0.0.0', port=8080, debug=False)