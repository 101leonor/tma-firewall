# <div align="center">**IoT Firewall**</div>

<p align="center">
<img src="./assets/iot_firewall_icon.png" width="500" height="500" >

   
An open-source IoT firewall designed to block unwanted IoT devices on user request, ensuring network security with ease!

## Getting Started

Follow the steps below to implement your own IoT firewall:

1. **Clone the repository**  
   Use the command below to clone the repository:
   ```bash
   git clone https://github.com/your-username/iot-firewall.git

2. **Run the firewall script as root**
  To avoid issues with iptables or tcpdump, run the script as root:
     ```bash
     sudo python3 iot_firewall.py

3. **Manage firewall rules**
  You can now add, modify, and delete rules to control IoT device access to your network.
