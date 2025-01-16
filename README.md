# <div align="center">**IoT Firewall**</div>

<p align="center">
<img src="./assets/iot_firewall_icon.png" width="500" height="500" >

   
A linux only open-source IoT firewall designed to block unwanted IoT devices by their type on user request, ensuring network security with ease!

## Getting Started

Follow the steps below to implement your own IoT firewall:

1. **Clone the repository**  
   Use the command below to clone the repository:
   ```bash
   git clone https://github.com/your-username/iot-firewall.git
2. **Virtual environment**
   You might need a virtual environment in order to install all the needed dependencies:
   ```bash
   python3 -m venv myenv
   source myenv/bin/activate
If conda is more convenient for you that is possible as well.

3. **Run the firewall script as root**
   To avoid issues with iptables or tcpdump, run the script as root:
     ```bash
     sudo python3 iot_firewall.py
   
4. **Manage firewall rules**
  You can now add, modify, and delete rules to control IoT device access to your network.

## Code Structure 

**iot_firewall.py** contains all the code for running the firewall by itself provided that there is a **rf_classifier.pkl** file in the directory for classifying the devices.

**IOTClassifier.ipynb** is a notebook which is used for training a Random Forest Classifier which detects the type of device using flow level information. 
For the training of the current version of rf_classifier.pkl we used this dataset: https://paperswithcode.com/dataset/iot-devices-captures
The notebook reads all the captures from the dataset and aggregates them into flows. It also balances the classes before classification by getting equal
counts of each class to train on. The accuracy on the given dataset using an 80:20 split is 85% which for our purposes is enough. We cannot guarantee 
the real life accuracy because we do not have access to another labeled dataset for testing.

The current version is able to classify only the following IoT devices due to dataset limitations: **IP Camera, Smart Switch, Smart Hub, Smart Plug**

