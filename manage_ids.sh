#!/bin/bash

# IDS Detector Management Script
SCRIPT_DIR="/opt/ids-detector"
API_SCRIPT="api_server_with_results.py"
LOG_FILE="/var/log/ids-detector.log"

start_ids() {
    echo "Starting IDS Detector..."
    cd $SCRIPT_DIR
    # Start in screen session for persistence
    screen -dmS ids-api python3 $API_SCRIPT
    echo "IDS Detector started in screen session"
    echo "Attach to screen: screen -r ids-api"
}

stop_ids() {
    echo "Stopping IDS Detector..."
    # Kill the screen session and python process
    screen -S ids-api -X quit 2>/dev/null
    pkill -f "python3.*$API_SCRIPT"
    echo "IDS Detector stopped"
}

restart_ids() {
    echo "Restarting IDS Detector..."
    stop_ids
    sleep 2
    start_ids
}

status_ids() {
    echo "Checking IDS Detector status..."
    if pgrep -f "python3.*$API_SCRIPT" > /dev/null; then
        echo "✅ IDS Detector is running"
        ps aux | grep "python3.*$API_SCRIPT" | grep -v grep
        echo ""
        echo "Screen sessions:"
        screen -ls | grep ids-api
    else
        echo "❌ IDS Detector is not running"
    fi
}

case "$1" in
    start)
        start_ids
        ;;
    stop)
        stop_ids
        ;;
    restart)
        restart_ids
        ;;
    status)
        status_ids
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
