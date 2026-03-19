import requests
import json

# Set this to your local Flask port (usually 5000)
BASE_URL = "http://127.0.0.1:5000/api/v1"

def print_result(name, response):
    print(f"\n--- Testing {name} ---")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response (Text): {response.text}")

def run_tests():
    print(f"Starting Local API Tests targeting: {BASE_URL}...\n")

    # 1. Test Health Check
    try:
        res_health = requests.get(f"{BASE_URL}/health", timeout=5)
        print_result("Health Endpoint", res_health)
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Could not connect to the server. Is Flask running?")
        return

    # 2. Test Admin Login (Using the fallback local password or your custom one)
    # If you run Flask locally without env vars, it defaults to 'change-me'
    login_payload = {
        "username": "admin",
        "password": "change-me" # Change to 'zdr' if you set the env var locally
    }
    res_login = requests.post(f"{BASE_URL}/auth/login", json=login_payload)
    print_result("Admin Login", res_login)

    # 3. Test URL Analysis
    analyse_payload = {
        "url": "http://example.com",
        "client_scan_id": "local-test-123"
    }
    res_analyse = requests.post(f"{BASE_URL}/analyse", json=analyse_payload)
    print_result("URL Analysis", res_analyse)

if __name__ == "__main__":
    run_tests()