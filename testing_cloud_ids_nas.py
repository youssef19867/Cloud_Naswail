import requests
import base64
import time
import json
from datetime import datetime
from scapy.all import sniff

IDS_URL = "http://101.46.64.170:8080"
CAPTURE_DURATION = 20  # seconds
SLEEP_BETWEEN_BATCHES = 1  # seconds
LOG_FILE = "ids_detections.log"

def get_protocol_name(proto_num):
    """Convert protocol number to name"""
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6"
    }
    return protocols.get(proto_num, f"Protocol-{proto_num}")

def log_detection(batch_num, detection_type, details):
    """Log detection to file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "batch": batch_num,
        "type": detection_type,
        "details": details
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def analyze_packets(packet_list, batch_num):
    """Send packets to both ML and DL detectors"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n{'='*60}")
    print(f"📊 BATCH #{batch_num} - {timestamp}")
    print(f"{'='*60}")
    
    # ML Detection
    print("🔍 Analyzing with ML detector...")
    try:
        ml_response = requests.post(
            f"{IDS_URL}/detect/ml/packets",
            json={"packets": packet_list},
            timeout=30
        )
        if ml_response.status_code == 200:
            result = ml_response.json()
            print(f"✅ ML Results:")
            print(f"   Total Flows: {result['summary']['total_flows']}")
            print(f"   Benign: {result['summary']['benign_flows']}")
            print(f"   Attacks: {result['summary']['attack_flows']}")
            
            # Show attack details if any
            total_attacks = result['summary']['attack_flows']
            if total_attacks > 0:
                print(f"   🚨 ATTACKS DETECTED ({total_attacks} total):")
                for attack_type, data in result['detailed_results'].items():
                    if data['count'] > 0:
                        print(f"\n      [{attack_type.upper()}] - {data['count']} flows:")
                        for idx, flow in enumerate(data['flows'][:3], 1):
                            proto_num = flow.get('protocol', 0)
                            proto_name = get_protocol_name(proto_num)
                            print(f"\n      Anomaly #{idx}:")
                            print(f"         Flow Index:  {flow.get('index', 'N/A')}")
                            print(f"         Protocol:    {proto_name} ({proto_num})")
                            print(f"         Source:      {flow.get('src_ip', 'N/A')}")
                            print(f"         Src Port:    {flow.get('src_port', 'N/A')}")
                            print(f"         Destination: {flow.get('dst_ip', 'N/A')}")
                            print(f"         Dst Port:    {flow.get('dst_port', 'N/A')}")
                            print(f"         Direction:   {flow.get('src_ip', 'N/A')} → {flow.get('dst_ip', 'N/A')}")
                        if len(data['flows']) > 3:
                            print(f"         ... and {len(data['flows']) - 3} more")
                        
                        # Log to file
                        log_detection(batch_num, f"ML_{attack_type}", data['flows'])
        else:
            print(f"❌ ML Error: {ml_response.json()}")
    except Exception as e:
        print(f"❌ ML Request failed: {e}")
    
    # DL Detection
    print("\n🔍 Analyzing with DL detector...")
    try:
        dl_response = requests.post(
            f"{IDS_URL}/detect/dl/packets",
            json={"packets": packet_list},
            timeout=30
        )
        if dl_response.status_code == 200:
            result = dl_response.json()
            print(f"✅ DL Results:")
            print(f"   Total Flows: {result['summary']['total_flows']}")
            print(f"   Benign: {result['summary']['benign_flows']}")
            print(f"   Anomalies: {result['summary']['anomaly_flows']}")
            
            # Show anomaly details if any
            anomalies = result['detailed_results'].get('anomaly_flows', [])
            if anomalies:
                print(f"   🚨 ANOMALIES DETECTED ({len(anomalies)} total):")
                for idx, flow in enumerate(anomalies[:5], 1):
                    proto_num = flow.get('protocol', 0)
                    proto_name = get_protocol_name(proto_num)
                    
                    print(f"\n      Anomaly #{idx}:")
                    print(f"         Flow Index:  {flow.get('index', 'N/A')}")
                    print(f"         Protocol:    {proto_name} ({proto_num})")
                    print(f"         Source:      {flow.get('src_ip', 'N/A')}")
                    print(f"         Src Port:    {flow.get('src_port', 'N/A')}")
                    print(f"         Destination: {flow.get('dst_ip', 'N/A')}")
                    print(f"         Dst Port:    {flow.get('dst_port', 'N/A')}")
                    print(f"         Direction:   {flow.get('src_ip', 'N/A')} → {flow.get('dst_ip', 'N/A')}")
                if len(anomalies) > 5:
                    print(f"\n      ... and {len(anomalies) - 5} more anomalies")
                
                # Log to file
                log_detection(batch_num, "DL_ANOMALY", anomalies)
        else:
            print(f"❌ DL Error: {dl_response.json()}")
    except Exception as e:
        print(f"❌ DL Request failed: {e}")

def main():
    print("🚀 Starting Continuous IDS Monitor")
    print(f"📡 Capturing packets for {CAPTURE_DURATION} seconds per batch")
    print(f"⏱️  {SLEEP_BETWEEN_BATCHES}s delay between batches")
    print(f"🌐 API Server: {IDS_URL}")
    print(f"📝 Logging detections to: {LOG_FILE}")
    print("\nPress CTRL+C to stop\n")
    
    batch_num = 0
    
    try:
        while True:
            batch_num += 1
            
            # Capture packets for specified duration
            print(f"📡 Capturing batch #{batch_num} for {CAPTURE_DURATION} seconds...")
            try:
                captured_packets = sniff(filter="ip", timeout=CAPTURE_DURATION)
                
                if not captured_packets:
                    print("⚠️  No packets captured, retrying...")
                    time.sleep(SLEEP_BETWEEN_BATCHES)
                    continue
                
                # Convert to base64-encoded raw bytes
                packet_list = []
                for pkt in captured_packets:
                    pkt_bytes = bytes(pkt)
                    pkt_b64 = base64.b64encode(pkt_bytes).decode('utf-8')
                    packet_list.append(pkt_b64)
                
                print(f"✅ Captured {len(packet_list)} packets")
                
                # Analyze
                analyze_packets(packet_list, batch_num)
                
                # Wait before next batch
                print(f"\n⏳ Waiting {SLEEP_BETWEEN_BATCHES}s before next batch...")
                time.sleep(SLEEP_BETWEEN_BATCHES)
                
            except Exception as e:
                print(f"❌ Error in batch #{batch_num}: {e}")
                time.sleep(SLEEP_BETWEEN_BATCHES)
                continue
    
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping monitor...")
        print(f"📊 Total batches processed: {batch_num}")
        print("✅ Monitor stopped")

if __name__ == "__main__":
    main()