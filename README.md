An intrusion detection system (IDS) is designed to monitor network traffic and detect potential threats.

The project goals are as follows: 1. Capture and process network packets in real-time. The system should intercept traffic on the selected network interface, extract the headers and payload of packets, and perform initial classification based on TCP, UDP, and ICMP; 2. Analyze network packets for signs of threats. To achieve this goal, it is necessary to implement a packet verification mechanism based on behavioral characteristics that indicate anomalies and typical signs of suspicious activity, such as port scanning and unusual TCP flags; 3. Provide visualization of the received data. The program should display the main parameters of network packets; 4. Record the analysis results and save the traffic history. To successfully implement these requirements, you will need a technical implementation plan and a structural diagram of the system being developed, which will describe the main mechanisms for intercepting network packets and detecting threats.

Development tools used: Visual Studio, pcap library, and Qt framework.

## 🛠 Tech Stack
* **Language:** C++ (C++17 or higher)
* **IDE:** Visual Studio 2022
* **Framework:** Qt 6.x
* **Library:** [Npcap SDK](https://npcap.com/sdk/) (modern alternative to WinPcap)

## Setup & Build Instructions
To compile and run the project in Visual Studio, follow these steps:

### 1. Prerequisites
* Install the [Npcap Driver](https://npcap.com/#download) on your system.
* Download and extract the [Npcap SDK](https://npcap.com/sdk/) to a local folder.

### 2. Configure Visual Studio
Open your project properties (`Project Properties` -> `VC++ Directories`):
* **Include Directories:** Add the path to the `Include` folder from the Npcap SDK.
* **Library Directories:** Add the path to the `Lib` (or `Lib/x64`) folder from the Npcap SDK.
* **Linker -> Input:** Add `wpcap.lib` and `Packet.lib` to **Additional Dependencies**.

### 3. Build & Run
* Open the `.slnx` or `.vcxproj` file in Visual Studio.
* Build the solution (**Build -> Build Solution**).
* **Important:** Run the application **as Administrator** to allow the driver to access network interfaces.

##  How to Use
1. Launch the application with administrative privileges.
2. Select your active network adapter from the list.
3. Click the **Start** button to begin monitoring.
4. View real-time packet data and traffic statistics in the main window.

##  Disclaimer
This project is intended for educational and ethical testing purposes only. Use it only on net
