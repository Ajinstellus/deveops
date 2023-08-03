import requests
import json
from datetime import datetime

API_URL = 'https://example.com/api/endpoint'  # Replace with your actual API endpoint URL

def send_alert(name, timestamp):
    # Prepare the data to be sent
    data = {
        'name': name,
        'timestamp': timestamp
    }

    # Convert the data to JSON format
    json_data = json.dumps(data)

    # Make a POST request to the API endpoint
    response = requests.post(API_URL, data=json_data)

    # Print the response
    print(response.text)

    # Check the response status
    if response.status_code == 200:
        print('Alert sent successfully')
    else:
        print('Failed to send alert')

# Example usage
name = "John"  # Replace with the actual recognized name
current_time = datetime.now().strftime("%y-%m-%d %H:%M:%S")  # Get the current timestamp

send_alert(name, current_time)
