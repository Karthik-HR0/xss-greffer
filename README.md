

<div align="center">
   <a href="https://github.com/Karthik-HR0/xss-greffer"><img src="https://sdmntprnortheu.oaiusercontent.com/files/00000000-98d8-61f4-a0c9-349dba1f95f6/raw?se=2025-09-02T09%3A42%3A04Z&sp=r&sv=2024-08-04&sr=b&scid=234af591-5f95-53ef-9ad1-ba1513d68345&skoid=0b778285-7b0b-4cdc-ac3b-fb93e8c3686f&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2025-09-01T16%3A20%3A37Z&ske=2025-09-02T16%3A20%3A37Z&sks=b&skv=2024-08-04&sig=M3jL8vmThmPheuhNAQkYRzbm1njj1xJ/96SDc5LAIBE%3D" hight="225" width="450" align="center"/></a>
</div>

<br>
<br>
<br>

<div align="center">

| XSS Greffer | Cross-Site Scripting Scanner | for Web Applications          |
| ----------- | ---------------------------- | ----------------------------- |
| `X`         | `=`                          | `Cross-Site Scripting (XSS)`  |
| `S`         | `=`                          | `Script Injection Detection`  |
| `S`         | `=`                          | `Selenium-Based Testing`      |
| `G`         | `=`                          | `GUI Interface`               |
| `reffer`    | `=`                          | `Automated Report Generation` |

> **XSS Greffer** is an easy-to-use tool designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications. It features a user-friendly GUI, multi-threaded scanning, and automated HTML report generation.  
>   
> _`Made by`_ - Team XSS Greffer
---

  
  
  

## Features

|Features|About|
|---|---|
|`XSS Scanner`|Detects Cross-Site Scripting vulnerabilities via payload injection.|
|`GUI Interface`|User-friendly interface built with `tkinter` and `ttkbootstrap`.|
|`Multi-threaded Scanning`|Supports concurrent scanning for improved performance.|
|`Customizable Payloads`|Use custom payload files to target specific XSS vulnerabilities.|
|`Cookie Support`|Handles cookies for authenticated page scanning.|
|`Telegram Notifications`|Sends real-time scan updates and results via Telegram (optional).|
|`HTML Report Generation`|Generates detailed HTML reports with scan results and vulnerable URLs.|
|`Vulnerable URL Management`|View, copy, and open vulnerable URLs directly from the GUI.|
|`Progress Bar`|Visualizes scan progress in real-time.|

  

---

  
  

## Dependencies

|Language|Packages|
|---|---|
|**Python**|`Python 3.x` `selenium` `webdriver_manager` `ttkbootstrap` `requests` `urllib3`|

  

---

  

## Installation

### Clone the Repository

```bash
git clone https://github.com/Karthik-HR0/xss-greffer.git
```

```bash
cd xss-greffer
```

### Install the Requirements

```bash
pip3 install -r requirements.txt
```

### Run the Script

```bash
python3 xss_greffer.py
```

### Requirements File (`requirements.txt`)

Create a `requirements.txt` file with the following content:

```text
selenium>=4.10.0
webdriver_manager>=3.8.6
ttkbootstrap>=1.10.1
requests>=2.31.0
urllib3>=1.26.16
```

  

---

  

## Input Information

|Input Information|Description|
|---|---|
|Input URL/File|Provide a single URL or a file containing multiple URLs for scanning.|
|Payload File|Select or provide a custom payload file with XSS payloads (e.g., `<script>alert(1)</script>`).|
|Cookies|Input cookies (e.g., `sessionid=abc123; token=xyz789`) for authenticated scans.|
|Timeout|Set the timeout (in seconds) for detecting alerts during scans.|
|Threads|Specify the number of threads (1–10) for multi-threaded scanning.|
|View and Save Results|View results in the GUI, save vulnerable URLs, and generate HTML reports.|

  

---

  

## Customization

|Customization|Description|
|---|---|
|Custom Payloads|Create or modify payload files to target specific XSS vulnerabilities.|
|Cookie Configuration|Add cookies for scanning authenticated pages.|
|Thread Count|Adjust the number of threads for performance optimization.|
|Telegram Integration|Configure Telegram notifications via a `tgbot.txt` file with bot token and chat ID.|

### Telegram Configuration

To enable Telegram notifications, create a `tgbot.txt` file in the project directory with the following format:

```text
token=your_bot_token
id=your_chat_id
```

Example:

```text
token=123456:ABC-DEF1234ghIkl-xyz
id=123456789
```

  

---

  

## Chrome Installation (Linux)

```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

If you encounter errors during installation, run:

```bash
sudo apt -f install
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

## ChromeDriver Installation (Linux)

```bash
wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip
```

```bash
unzip chromedriver-linux64.zip
```

```bash
cd chromedriver-linux64
```

```bash
sudo mv chromedriver /usr/bin
```

  

---

  

> [!WARNING]  
> XSS Greffer is intended for educational and ethical hacking purposes only. It should only be used to test systems you own or have explicit permission to test. Unauthorized use of third-party websites or systems without consent is illegal and unethical.

  
