import requests

url = "http://127.0.0.1:5000/analyze"

data = {
  
"message": "URGENT! Your bank account will be blocked. Click here to verify your account and share your OTP."

}

response = requests.post(url, json=data)

print(response.json())