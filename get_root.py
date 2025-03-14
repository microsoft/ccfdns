import requests

url = "https://0.0.0.0:1025/roots/0"
response = requests.get(url, verify=False)

with open("pebble_root.pem", "wb") as file:
    file.write(response.content)

