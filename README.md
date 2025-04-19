![busPwn](https://raw.githubusercontent.com/aravind0x7/BusPwn/refs/heads/main/assets/ezgif-11ea92e96d9f1f.gif)

`BusPwn` is a **GUI-based Modbus hacking framework** designed for testing and exploiting vulnerabilities in Modbus-based systems, often used in **Industrial Control Systems (ICS)** and **Operational Technology (OT)**. This tool is intended for cybersecurity professionals, red teamers, and researchers to explore & pentest **Modbus TCP** protocols.

## 🔥 Features
- **GUI Interface**: Intuitive and user-friendly interface for ease of use.
- **Modbus Scanning**: Discover devices, registers, and points in your Modbus network.
- **Command Injection**: Launch attacks to inject modbus elements (coils, discrete inputs, holding registers, and input registers).
- **DoS (Denial of Service)**: Launch and analyze the impact of DoS attacks on ICS networks.
- **Cross-Platform**: Built with Python and compatible with Linux, macOS, and Windows environments.
- **Educational Use**: Perfect for learning, research, and authorized penetration testing.

## 🚨 Disclaimer
> **This tool is for educational purposes and authorized testing only.**  
> Unauthorized access to systems or networks is illegal and unethical.  
> Always obtain explicit permission before running `busPwn` on any network or device.

## 🚀 Installation

1. **Clone the repo:**

```bash
git clone https://github.com/aravind0x7/BusPwn.git
cd BusPwn
```
**🐍 Optional: Create a Virtual Environment**
#### It's recommended to use a virtual environment to manage dependencies:

```bash
# Create a virtual environment
python -m venv venv

# Activate it
# On Windows
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process (Optional)
venv\Scripts\activate
# On Linux/macOS
source venv/bin/activate
```
This helps avoid conflicts between different Python projects.

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Run the tool:**

```bash
python pwn.py
```

## 🔧 Usage

After launching the tool, access the localhost ip ([127.0.0.1:5000](https://127.0.0.1:5000)) in your browser to interact with various sections to scan and exploit Modbus devices. Here's an overview of what you can do:

- **Modbus Scan**: Enter a target IP and perform a device scan.
- **Run Attacks**: Select from various attacks like **DoS** or **Command Injection** to test the resilience of the Modbus devices.
- **Customizable Settings**: Adjust time intervals, ports, and other attack parameters using the GUI options.

## 🎯 Tinkered For
- **Cybersecurity professionals** testing Modbus-based ICS/OT systems.
- **Red teamers** simulating real-world attacks on industrial networks.
- **Researchers** studying vulnerabilities in legacy systems and protocols.
- **OT engineers** wanting to understand security flaws in Modbus protocols.

## ⚙️ Developed By
**aravind0x7**  
Mechatronics Engineer | OT Security Enthusiast  
[GitHub](https://github.com/aravind0x7) | [Medium](https://aravind07.medium.com/) | [Instagram](https://instagram.com/aravind0x7)

## 🧠 Contributing

Feel free to fork the repo, submit pull requests, or open issues. If you want to contribute to `BusPwn`, check out the [contributing guide](CONTRIBUTING.md) for more details.

## 🛡️ License
This project is licensed under the **MIT License** – see the [LICENSE](https://github.com/aravind0x7/BusPwn/blob/main/LICENSE) file for details.

## ☕ Support

If you find **busPwn** useful or cool, consider buying me a coffee!

<a href="https://www.buymeacoffee.com/aravind0x7" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50" width="210">
</a>

> **“If it speaks Modbus, I make it scream.”** - aravind0x7
