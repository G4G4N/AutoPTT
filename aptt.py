import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from threading import Thread
import subprocess
import re
import requests
import bcrypt
import jwt
import datetime

class NetworkScanner:
    @staticmethod
    def scan(ip_range):
        try:
            # Use nmap for scanning (ensure nmap is installed on your system)
            result = subprocess.run(["nmap", "-sP", ip_range], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"

class VulnerabilityAnalyzer:
    @staticmethod
    def analyze(scan_result):
        # Basic vulnerability extraction using regular expressions
        vuln_pattern = re.compile(r"\b(\d+\.\d+\.\d+\.\d+)\b")

        vulnerabilities = []
        for match in vuln_pattern.finditer(scan_result):
            ip_address = match.group(1)
            vulnerabilities.append({'ip_address': ip_address, 'vulnerabilities': []})

        # You can further analyze, categorize, or take actions based on the extracted vulnerabilities
        return vulnerabilities

class ResultStorage:
    @staticmethod
    def save_to_api(api_url, scan_results):
        try:
            response = requests.post(api_url, json={'results': scan_results})
            return response.text
        except requests.exceptions.RequestException as e:
            return f"Error: {str(e)}"

class UserAuthentication:
    SECRET_KEY = 'your_secret_key'  # Replace with a long, random secret key

    @staticmethod
    def authenticate(username, password):
        # Retrieve hashed password from a secure storage (e.g., a database)
        hashed_password = b'$2a$04$Ku1CrhS0L77FrpXaGwJ5L.W3W1Ls2Dq3kRpxhO9LepzCOZbvpsLCS'  # Replace with actual hashed password

        # Use bcrypt to verify the provided password against the hashed password
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return UserAuthentication.generate_token(username)
        else:
            return None

    @staticmethod
    def generate_token(username):
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        payload = {
            'username': username,
            'exp': expiration_time
        }
        token = jwt.encode(payload, UserAuthentication.SECRET_KEY, algorithm='HS256')
        return token

    @staticmethod
    def verify_token(token):
        try:
            payload = jwt.decode(token, UserAuthentication.SECRET_KEY, algorithms=['HS256'])
            return payload['username']
        except jwt.ExpiredSignatureError:
            return None  # Token has expired
        except jwt.InvalidTokenError:
            return None  # Invalid token

class PenetrationTestingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Penetration Testing Tool")

        # User Authentication
        self.logged_in_user = None
        self.logged_in_user_token = None

        # UI components
        self.username_label = ttk.Label(root, text="Username:")
        self.username_entry = ttk.Entry(root, width=20)
        self.password_label = ttk.Label(root, text="Password:")
        self.password_entry = ttk.Entry(root, width=20, show="*")
        self.login_button = ttk.Button(root, text="Login", command=self.authenticate_user)
        self.ip_range_label = ttk.Label(root, text="IP Range:")
        self.ip_range_entry = ttk.Entry(root, width=20)
        self.scan_button = ttk.Button(root, text="Scan", command=self.start_scan)
        self.results_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20, state=tk.DISABLED)

        # Layout
        self.username_label.grid(column=0, row=0, padx=10, pady=10, sticky=tk.W)
        self.username_entry.grid(column=1, row=0, padx=10, pady=10, sticky=tk.W)
        self.password_label.grid(column=0, row=1, padx=10, pady=10, sticky=tk.W)
        self.password_entry.grid(column=1, row=1, padx=10, pady=10, sticky=tk.W)
        self.login_button.grid(column=2, row=1, padx=10, pady=10, sticky=tk.W)
        self.ip_range_label.grid(column=0, row=2, padx=10, pady=10, sticky=tk.W)
        self.ip_range_entry.grid(column=1, row=2, padx=10, pady=10, sticky=tk.W)
        self.scan_button.grid(column=2, row=2, padx=10, pady=10, sticky=tk.W)
        self.results_text.grid(column=0, row=3, columnspan=3, padx=10, pady=10, sticky=tk.W)

    def authenticate_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        token = UserAuthentication.authenticate(username, password)
        if token:
            self.logged_in_user = username
            self.logged_in_user_token = token
            self.display_results(f"Welcome, {username}!\n")
            self.display_results("Authentication successful!\n")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password. Please try again.")

    def start_scan(self):
        if not self.logged_in_user:
            messagebox.showerror("Unauthorized", "Please log in before initiating a scan.")
            return

        ip_range = self.ip_range_entry.get()
        if not ip_range:
            self.display_results("Please enter an IP range.")
            return

        self.results_text.delete(1.0, tk.END)  # Clear previous results

        # Validate the stored token before initiating a scan
        username = UserAuthentication.verify_token(self.logged_in_user_token)
        if username:
            # Start scanning in a separate thread
            scan_thread = Thread(target=self.scan_and_report, args=(ip_range,))
            scan_thread.start()
        else:
            self.display_results("Session expired. Please log in again.\n")

    def scan_and_report(self, ip_range):
        # Step 1: Network Scanning
        self.display_results("Step 1: Network Scanning...\n")
        scan_result = NetworkScanner.scan(ip_range)

        # Step 2: Vulnerability Analysis
        self.display_results("\nStep 2: Vulnerability Analysis...\n")
        vulnerabilities = VulnerabilityAnalyzer.analyze(scan_result)

        # Step 3: Generate Report
        self.display_results("\nStep 3: Generating Report...\n")
        report = self.generate_report(scan_result, vulnerabilities)

        # Display Results
        self.display_results("\nResults:\n")
        self.display_results(report)

        # Step 4: Save Results to API (Example)
        self.display_results("\nStep 4: Saving Results to API (Example)...\n")
        api_url = "https://example.com/api/save_results"
        response = ResultStorage.save_to_api(api_url, vulnerabilities)
        self.display_results(f"\nAPI Response: {response}\n")

    def generate_report(self, scan_result, vulnerabilities):
        # Basic report generation (replace with a more detailed report structure)
        report = f"Network Scan Results:\n{scan_result}\n\nVulnerability Analysis:\n"
        for vuln in vulnerabilities:
            report += f"IP Address: {vuln['ip_address']}\nVulnerabilities: {vuln['vulnerabilities']}\n\n"
        return report

    def display_results(self, text):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text)
        self.results_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PenetrationTestingApp(root)
    root.mainloop()
