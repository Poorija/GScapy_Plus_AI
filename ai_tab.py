import os
import sys
import json
import logging
import re
import socket
import time
from threading import Event

from PyQt6.QtCore import (QObject, pyqtSignal, Qt, QThread, QTimer,
                          QPropertyAnimation, QEasingCurve, QParallelAnimationGroup,
                          QSequentialAnimationGroup, QPoint, QSize)
from PyQt6.QtGui import (QAction, QIcon, QFont, QTextCursor, QActionGroup, QPalette, QImage, QPixmap)
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel,
                             QPlainTextEdit, QPushButton, QHBoxLayout,
                             QTreeWidget, QTreeWidgetItem, QSplitter,
                             QFileDialog, QMessageBox, QComboBox,
                             QListWidget, QListWidgetItem, QScrollArea,
                             QLineEdit, QCheckBox, QFrame, QMenu, QTextEdit,
                             QGroupBox, QTextBrowser, QDialog, QFormLayout,
                             QInputDialog, QTreeWidgetItemIterator)
try:
    from lxml import etree
except ImportError:
    etree = None
    logging.warning("LXML not found, AI analysis for Nmap XML will be basic.")


# This function is used by the AI tab, so it's moved here.
def create_themed_icon(icon_path, color_str):
    """Loads an SVG, intelligently replaces its color, and returns a QIcon."""
    try:
        with open(icon_path, 'r', encoding='utf-8') as f:
            svg_data = f.read()

        themed_svg_data, count = re.subn(r'stroke:#[0-9a-fA-F]{6}', f'stroke:{color_str}', svg_data)

        if count == 0 and '<svg' in themed_svg_data:
            themed_svg_data = themed_svg_data.replace('<svg', f'<svg fill="{color_str}"')

        image = QImage.fromData(themed_svg_data.encode('utf-8'))
        pixmap = QPixmap.fromImage(image)
        return QIcon(pixmap)
    except Exception as e:
        logging.warning(f"Could not create themed icon for {icon_path}: {e}")
        return QIcon(icon_path)

class TypingIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(40)
        self.dots = []
        self.animations = QParallelAnimationGroup(self)

        for i in range(3):
            dot = QLabel("●", self)
            dot.setStyleSheet("color: #b0b0b0; font-size: 20px;")
            self.dots.append(dot)

            anim = QPropertyAnimation(dot, b"pos")
            anim.setDuration(400)
            anim.setStartValue(QPoint(20 + i * 20, 20))
            anim.setEndValue(QPoint(20 + i * 20, 10))
            anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

            reverse_anim = QPropertyAnimation(dot, b"pos")
            reverse_anim.setDuration(400)
            reverse_anim.setStartValue(QPoint(20 + i * 20, 10))
            reverse_anim.setEndValue(QPoint(20 + i * 20, 20))
            reverse_anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

            seq = QSequentialAnimationGroup()
            seq.addPause(i * 150)
            seq.addAnimation(anim)
            seq.addAnimation(reverse_anim)
            seq.setLoopCount(-1)
            self.animations.addAnimation(seq)

    def start_animation(self):
        self.animations.start()

    def stop_animation(self):
        self.animations.stop()


class ThinkingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_expanded = False # Start collapsed by default
        self._init_ui()

    def _init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 5, 0, 5)
        self.main_layout.setSpacing(0)

        self.header_frame = QFrame()
        self.header_frame.setStyleSheet("""
            QFrame {
                background-color: #f0f0f0;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
            }
            QPushButton {
                border: none;
                text-align: left;
                font-weight: bold;
                padding: 5px;
                color: #555;
            }
            QLabel {
                border: none;
                padding-right: 5px;
            }
        """)
        header_layout = QHBoxLayout(self.header_frame)
        header_layout.setContentsMargins(5, 0, 5, 0)

        self.toggle_button = QPushButton("🤔 Thinking...")
        self.toggle_button.clicked.connect(self.toggle_content)

        self.arrow_label = QLabel("\u25B6") # Right-pointing arrow for collapsed state

        header_layout.addWidget(self.toggle_button)
        header_layout.addStretch()
        header_layout.addWidget(self.arrow_label)

        self.content_widget = QTextEdit()
        self.content_widget.setReadOnly(True)
        self.content_widget.setStyleSheet("""
            QTextEdit {
                background-color: #f7f7f7;
                border: 1px solid #e0e0e0;
                border-top: none;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
                color: #888;
                padding: 8px;
            }
        """)
        self.content_widget.setVisible(False) # Start collapsed

        self.main_layout.addWidget(self.header_frame)
        self.main_layout.addWidget(self.content_widget)
        self.adjustSize()

    def toggle_content(self):
        self.is_expanded = not self.is_expanded
        self.content_widget.setVisible(self.is_expanded)
        self.arrow_label.setText("\u25BC" if self.is_expanded else "\u25B6")
        self.header_frame.setStyleSheet(self.header_frame.styleSheet())

        if self.parentWidget():
            self.parentWidget().updateGeometry()
            for i in range(self.parentWidget().count()):
                item = self.parentWidget().item(i)
                widget = self.parentWidget().itemWidget(item)
                if widget is self:
                    item.setSizeHint(self.sizeHint())
                    break

    def append_text(self, text):
        self.content_widget.moveCursor(QTextCursor.MoveOperation.End)
        self.content_widget.insertPlainText(text)
        self.content_widget.moveCursor(QTextCursor.MoveOperation.End)
        self.adjustSize()
        if self.parentWidget():
             self.parentWidget().updateGeometry()

    def is_collapsed(self):
        return not self.is_expanded


class ChatBubble(QWidget):
    """A custom widget that displays text in a chat bubble, handling dynamic resizing."""
    # Signal to notify the container that the size hint has changed
    sizeHintChanged = pyqtSignal()

    def __init__(self, text, is_user, is_streaming=False, parent=None):
        super().__init__(parent)
        self.is_user = is_user
        self.is_streaming = is_streaming
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.setMarkdown(text)
        self.text_edit.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.text_edit.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.text_edit.document().contentsChanged.connect(self.on_contents_changed)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.addWidget(self.text_edit)
        self.set_stylesheet()

    def set_stylesheet(self):
        # Common styles for the QTextEdit
        self.text_edit.setStyleSheet("QTextEdit { border: none; background-color: transparent; }")

        # Container styles for the bubble appearance
        if self.is_user:
            padding = "10px 14px 10px 14px"
            self.setStyleSheet(f"""
                ChatBubble {{
                    background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                                    stop: 0 #2a8afc, stop: 1 #0a6dcf);
                    color: white;
                    padding: {padding};
                    border-radius: 18px;
                    border-bottom-right-radius: 4px;
                }}
            """)
            self.layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        else:
            padding = "10px 14px 10px 14px"
            bg_color = "#f0f0f0"
            self.setStyleSheet(f"""
                ChatBubble {{
                    background-color: {bg_color};
                    color: #202020;
                    padding: {padding};
                    border-radius: 18px;
                    border-bottom-left-radius: 4px;
                }}
            """)
            self.layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Set text color based on bubble type
        text_color = "white" if self.is_user else "#202020"
        self.text_edit.setStyleSheet(f"QTextEdit {{ border: none; background-color: transparent; color: {text_color}; }}")


    def append_text(self, text_chunk):
        current_text = self.text_edit.toPlainText()
        self.text_edit.setMarkdown(current_text + text_chunk)

    def finish_streaming(self):
        self.is_streaming = False

    def on_contents_changed(self):
        # Adjust the height of the text_edit to fit its content
        doc_height = self.text_edit.document().size().height()
        self.text_edit.setFixedHeight(int(doc_height))
        self.updateGeometry()
        self.sizeHintChanged.emit() # Signal that the overall widget size has changed

    def sizeHint(self):
        # Override sizeHint to provide an accurate size based on content.
        # The width is constrained by the parent, and height is dynamic.
        parent_width = self.parent().width() if self.parent() else 800
        max_bubble_width = int(parent_width * 0.75)

        # Calculate the ideal size without setting a fixed width on the widget itself
        return QSize(max_bubble_width, self.text_edit.height())


class AIAssistantTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent # GScapy main window instance
        self.thinking_widget = None
        self.current_ai_bubble = None
        self.ai_thread = None

        self.ai_prompts = {
            "Threat Detection & Analysis": {
                "Analyze Firewall Logs for Anomalies": "Analyze the following firewall logs for anomalies. Identify any unauthorized or suspicious inbound/outbound connections, looking for patterns of repeated denied connections, connections to non-standard ports, or traffic from known malicious IPs.",
                "Identify Abnormal Process Behavior": "Monitor this list of system processes and flag any abnormal behavior. Look for unusually named processes, processes with high CPU/memory usage, those making unexpected network connections, or any process executing from a temporary directory.",
                "Scan Network Traffic for Malware": "Given the following network traffic dump (.pcap data), conduct a deep scan to identify hidden or stealthy malware. Look for covert channels, unusual DNS queries (e.g., DGA), encrypted traffic to unknown endpoints, or non-standard protocol usage.",
                "Detect Advanced Phishing Attempts": "Analyze the following email headers and content to detect sophisticated phishing or spear-phishing attempts. Check for mismatches in 'From' and 'Reply-To' fields, suspicious links (URL shorteners, punycode), urgent or threatening language, and spoofed sender domains.",
                "Review Web Server Logs for Attack Patterns": "Review these web server logs (Apache/Nginx) for attack patterns. Identify potential SQL injection, cross-site scripting (XSS), directory traversal, command injection, or reconnaissance scanning attempts.",
                "Scan Database Logs for Insider Threats": "Scan the following database logs for signs of unauthorized access or insider threats. Look for queries from unexpected IP addresses, unusually large data exports, access to sensitive tables outside of business hours, or repeated failed login attempts.",
                "Detect DNS Tunneling/Hijacking": "Analyze the provided DNS traffic for signs of DNS tunneling, hijacking, or poisoning. Look for abnormally long or encoded subdomains, high volumes of TXT record queries, or unexpected responses to common DNS queries.",
                "Find Network Security Misconfigurations": "Perform a vulnerability assessment on the provided network device configurations (e.g., firewall, router, switch). Identify weaknesses like open management ports, default credentials, outdated firmware, weak SNMP community strings, or permissive ACLs.",
                "Detect Data Exfiltration Patterns": "Analyze these network flow logs to detect potential data exfiltration. Look for large, encrypted uploads to external sites, sustained low-and-slow outbound connections, traffic to known cloud storage services, or use of non-standard ports for common protocols.",
                "Identify Credential Stuffing/Brute-Force Attacks": "Monitor these authentication logs (e.g., Active Directory, SSH, web app) and identify brute-force or credential stuffing attacks. Look for a high volume of failed logins from a single IP or for a single user account across multiple services.",
                "Analyze Packet Capture for IOCs": "Analyze the following packet capture data and extract Indicators of Compromise (IOCs). List any suspicious IP addresses, domains, file hashes, or network artifacts.",
                "Correlate Logs from Multiple Sources": "Correlate the following logs from a firewall, an IDS, and a web server for the same timeframe. Identify any related events that indicate a multi-stage attack and describe the potential attack chain.",
            },
            "Incident Response": {
                "Generate an Initial Incident Triage Report": "Based on the following alert data, generate an initial incident triage report. Include a summary of the event, affected systems, potential severity, and recommended initial containment steps. Alert data: ",
                "Develop a Ransomware Containment Strategy": "A ransomware attack has been detected on a workstation. Provide an immediate, step-by-step containment strategy for the incident response team. Include network segmentation, host isolation, and evidence preservation steps.",
                "Guide Forensic Evidence Collection (Windows)": "Guide an incident responder through collecting volatile and non-volatile evidence from a compromised Windows server. Include specific commands and tools for memory acquisition, disk imaging, and collecting critical system logs.",
                "Guide Forensic Evidence Collection (Linux)": "Create a checklist for collecting forensic evidence from a compromised Linux web server. Prioritize the collection of volatile data and include commands for capturing memory, running processes, network connections, and relevant logs.",
                "Formulate a DDoS Mitigation Plan": "Our main web server at {TARGET_IP} is under a DDoS attack. Provide an immediate, actionable mitigation plan. Include steps for identifying the attack type, working with our upstream provider, and implementing rate limiting or filtering.",
                "Analyze Malware Behavior": "Analyze the following description of a malware sample's behavior and hypothesize its objectives and potential threat actor. Suggest next steps for reverse engineering. Behavior: ",
                "Create Incident Communication Templates": "Draft three communication templates for a data breach incident: 1) An internal notification to employees, 2) A notification to affected customers, and 3) A statement for the press.",
                "Post-Incident Review (Lessons Learned)": "Facilitate a post-incident review (lessons learned) for a recent security event. Provide a structured agenda and a list of key questions to ask the team to identify root causes and improve future responses.",
                "Eradicate Malware from a Network": "Outline a systematic process for eradicating a malware infection from a corporate network after it has been contained. Include steps for system cleaning, credential resets, and vulnerability patching.",
                "Verify System Recovery and Hardening": "After a system has been restored from a backup, provide a checklist to verify its integrity and harden it against re-infection before bringing it back online.",
            },
            "Vulnerability Assessment & PenTesting": {
                "Suggest Nmap Scan for a Web Server": "Suggest a comprehensive but non-intrusive Nmap command to scan a public web server for open ports, service versions, and common web vulnerabilities. The target is {TARGET_URL}.",
                "Suggest Nmap Scan for Internal Network": "What Nmap command would you recommend for an initial discovery scan of an internal corporate subnet ({TARGET_SUBNET}) to identify live hosts and common services?",
                "Find Exploits for a Specific Service": "Find potential public exploits or attack vectors for a service identified as 'Apache 2.4.41 on Ubuntu'. Provide CVE numbers and links to exploit-db if possible.",
                "Analyze Nmap Scan Results": "Analyze the following Nmap scan results for potential vulnerabilities and suggest the top 3-5 next steps for a penetration tester. Results: ",
                "Explain Scan Results to a Non-Expert": "Explain the following scan results in simple, non-technical terms. What was the tool trying to do, and what do these results mean for our security? Results: ",
                "Generate a Phishing Email Template": "Create a convincing phishing email template for a corporate security awareness test. The scenario should be a fake 'urgent password reset' request.",
                "Outline a Web App Penetration Test Plan": "Outline a high-level penetration testing plan for a new e-commerce web application. Include the key phases (recon, scanning, exploitation, post-exploitation) and the main areas to test.",
                "Harden a Linux Server Configuration": "Based on the following server information, provide a checklist of the top 10 security hardening steps to take. Info: Ubuntu 22.04, running a public-facing Nginx web server and SSH.",
                "Assess Wireless Network Security": "Analyze this wireless network configuration and recommend security enhancements. The current setup is: SSID 'CorporateWifi', WPA2-PSK with a known weak password, and no client isolation.",
                "Craft a Subdomain Enumeration Command": "Provide a one-line command that combines multiple tools (like subfinder, assetfinder, and httpx) to perform comprehensive subdomain enumeration and identify live web servers.",
                "Formulate a Password Cracking Strategy": "Given a set of NTLMv2 password hashes, what would be the most effective password cracking strategy using Hashcat? Describe the recommended attack modes and wordlists.",
                "Script a Basic XSS Payloaod": "Provide a few basic, non-malicious XSS payloads that can be used to test for reflected XSS vulnerabilities in a web application's search field.",
            },
            "Scripting & Automation": {
                "Generate Nmap Script with Output": "Generate a bash script that takes a file of IP addresses as input, runs a version-detection Nmap scan (-sV) on each one, and saves the output to a separate file for each IP.",
                "Create a Scapy TCP SYN Scanner": "Write a Python script using Scapy to perform a TCP SYN scan on a given IP address and a list of ports. It should print whether each port is open, closed, or filtered.",
                "Create a Scapy ARP Scanner": "Write a Python script using Scapy to perform an ARP scan on a given local network range (e.g., 192.168.1.0/24) and print a list of live hosts and their MAC addresses.",
                "Automate Log Parsing with Python": "Write a Python script to parse an Apache access log file. The script should identify and count the top 10 most frequent IP addresses and the top 10 most requested URLs.",
                "Automate Log Parsing with PowerShell": "Write a PowerShell script to parse the Windows Security event log for failed login attempts (Event ID 4625) and output a summary of the top 10 source IP addresses and usernames.",
                "Create a Bash Port Check Script": "Create a simple bash script that uses 'netcat' or '/dev/tcp' to check if a specific TCP port is open on a remote host. The script should take the host and port as arguments.",
                "Python Script to Check for Weak SSH Ciphers": "Write a Python script using the 'paramiko' library to connect to an SSH server and check if it allows weak or outdated cryptographic algorithms (e.g., CBC ciphers, SHA-1).",
                "Automate Subdomain Enumeration with Bash": "Create a bash one-liner that chains together 'subfinder' and 'httpx' to find live subdomains for a given domain and save the results to a file.",
                "PowerShell Script to Find Inactive AD Users": "Write a PowerShell script for Active Directory that finds user accounts that have not logged in for over 90 days and exports their names and last logon dates to a CSV file.",
                "Python Script for Password Strength Check": "Write a Python script that takes a password as input and checks its strength based on length, and the inclusion of uppercase letters, lowercase letters, numbers, and special characters.",
                "Python Script to Decode a Base64 String": "Write a simple Python script that takes a Base64 encoded string as an argument and prints the decoded result.",
            },
            "Policy & Compliance": {
                "Draft an Acceptable Use Policy (AUP)": "Draft a template for an Acceptable Use Policy (AUP) for employees at a mid-sized tech company. It should cover internet usage, email, and company-owned devices.",
                "Create a Password Management Policy": "Develop a comprehensive password management policy. It should include requirements for password length, complexity, history, and expiration, as well as guidelines for multi-factor authentication (MFA) usage.",
                "Outline a Data Classification Policy": "Provide a template for a data classification policy. Include at least three levels of classification (e.g., Public, Internal, Confidential) and define the handling requirements for each.",
                "Develop a Mobile Device (BYOD) Policy": "Offer recommendations for creating a Bring Your Own Device (BYOD) policy. It should address security requirements for personal devices, data segregation, and what happens if a device is lost or stolen.",
                "Establish a Vendor Security Assessment Policy": "Outline a policy for conducting security assessments of third-party vendors. Include a questionnaire template covering key areas like data protection, access control, and incident response.",
                "Draft an Incident Response Policy": "Provide a high-level template for an Incident Response Policy. It should define what constitutes an incident, the roles and responsibilities of the IR team, and the phases of incident handling (e.g., Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned).",
                "Define a Patch Management Policy": "Help define a patch management policy that specifies timelines for applying critical, high, medium, and low severity patches to different types of systems (e.g., servers, workstations).",
                "Create an Encryption Policy": "Assist in developing a data encryption policy. It should specify the minimum required encryption standards for data at rest (e.g., AES-256) and data in transit (e.g., TLS 1.2+).",
                "Generate a Rules of Engagement (ROE) Document": "You are a senior penetration tester. Based on the following scope, generate a formal Rules of Engagement (ROE) document in Markdown format. Scope: Target is the web application at {TARGET_URL} and its underlying server. No social engineering is permitted.",
                "Translate Technical Findings for an Executive Summary": "Translate the following technical vulnerability report into a concise, non-technical executive summary. Focus on the business risk and the required actions. Report: ",
            }
        }

        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Left Panel: Collapsible Prompts ---
        self.prompts_container = QFrame(self)
        self.prompts_container.setFixedWidth(300)
        self.prompts_container.setObjectName("promptsContainer")
        self.prompts_container.setStyleSheet("#promptsContainer { border-right: 1px solid #e0e0e0; }")
        prompts_layout = QVBoxLayout(self.prompts_container)
        prompts_layout.setContentsMargins(5, 10, 5, 10)
        prompts_layout.setSpacing(10)

        prompt_search_bar = QLineEdit(self)
        prompt_search_bar.setPlaceholderText("Search prompts...")
        prompt_search_bar.textChanged.connect(self._filter_prompts)
        prompts_layout.addWidget(prompt_search_bar)

        self.prompt_tree = QTreeWidget()
        self.prompt_tree.setHeaderHidden(True)
        self.prompt_tree.itemClicked.connect(self._on_prompt_selected)
        self._populate_prompts()
        prompts_layout.addWidget(self.prompt_tree)
        main_layout.addWidget(self.prompts_container)

        # --- Right Panel: Chat Interface ---
        chat_container = QWidget()
        chat_layout = QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(10, 0, 10, 10)
        chat_layout.setSpacing(10)

        # Custom Header
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(5, 5, 5, 5)
        self.toggle_prompts_btn = QPushButton("☰ Prompts")
        self.toggle_prompts_btn.setCheckable(True)
        self.toggle_prompts_btn.setChecked(True)
        self.toggle_prompts_btn.toggled.connect(self.prompts_container.setVisible)
        header_layout.addWidget(self.toggle_prompts_btn, 0, Qt.AlignmentFlag.AlignLeft)

        header_title = QLabel("AI Assistant")
        header_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(header_title, 0, Qt.AlignmentFlag.AlignCenter)
        header_layout.addStretch()
        chat_layout.addWidget(header_frame)


        self.chat_list = QListWidget(self)
        self.chat_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.chat_list.setStyleSheet("QListWidget { border: none; background-color: #ffffff; }")
        # Add some space between bubbles
        self.chat_list.setSpacing(5)
        chat_layout.addWidget(self.chat_list)

        self.typing_indicator = TypingIndicator(self)
        self.typing_indicator.setFixedHeight(30)
        self.typing_indicator.hide()
        chat_layout.addWidget(self.typing_indicator)

        # Modern Input Field
        bottom_controls_layout = QHBoxLayout()
        input_frame = QFrame(self)
        input_frame.setObjectName("inputFrame")
        input_frame.setStyleSheet("""
            #inputFrame {
                border: 1px solid #d0d0d0;
                border-radius: 22px;
                background-color: #ffffff;
            }
        """)
        input_frame_layout = QHBoxLayout(input_frame)
        input_frame_layout.setContentsMargins(15, 5, 5, 5)
        input_frame_layout.setSpacing(10)

        self.user_input = QLineEdit(self)
        self.user_input.setPlaceholderText("Ask the AI Assistant...")
        self.user_input.setStyleSheet("border: none; background-color: transparent; font-size: 14px; color: #333;")
        input_frame_layout.addWidget(self.user_input)

        self.send_button = QPushButton()
        self.send_button.setFixedSize(36, 36)
        self.send_button.setStyleSheet("QPushButton { border: none; border-radius: 18px; }")
        self.send_button.setToolTip("Send Message")
        input_frame_layout.addWidget(self.send_button)

        bottom_controls_layout.addWidget(input_frame)

        self.ai_settings_btn = QPushButton()
        self.ai_settings_btn.setToolTip("Configure & Select AI Models")
        self.ai_settings_btn.setFixedSize(44, 44)
        self.ai_settings_btn.setStyleSheet("QPushButton { border: none; border-radius: 22px; }")
        bottom_controls_layout.addWidget(self.ai_settings_btn)

        chat_layout.addLayout(bottom_controls_layout)
        main_layout.addWidget(chat_container)

        self.send_button.clicked.connect(self.send_message)
        self.user_input.returnPressed.connect(self.send_message)
        self.ai_settings_btn.clicked.connect(self._show_ai_settings_menu)

        self.update_theme() # Set initial themed icons

    def update_theme(self):
        """Updates the icon color to match the new theme."""
        # Get the current theme's text color to make the icon theme-aware
        try:
            palette = self.palette()
            text_color = palette.color(QPalette.ColorRole.Text)
            icon_color_str = text_color.name()
        except Exception:
            icon_color_str = "#505050" # Fallback color

        self.ai_settings_btn.setIcon(create_themed_icon(os.path.join("icons", "gear.svg"), icon_color_str))
        self.ai_settings_btn.setIconSize(QSize(28, 28))

        # The send button icon should always be white as it's on a solid color background
        self.send_button.setIcon(create_themed_icon(os.path.join("icons", "paper-airplane.svg"), "#ffffff"))
        self.send_button.setIconSize(QSize(24, 24))

        # Style the send button to be more prominent
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #0a6dcf;
                border: none;
                border-radius: 18px;
            }
            QPushButton:hover {
                background-color: #2a8afc;
            }
        """)

    def _filter_prompts(self, text):
        """Filters the prompt tree based on the search text."""
        iterator = QTreeWidgetItemIterator(self.prompt_tree)
        while iterator.value():
            item = iterator.value()
            # Search in both prompt name (item text) and prompt content (UserRole data)
            prompt_name = item.text(0).lower()
            prompt_content = (item.data(0, Qt.ItemDataRole.UserRole) or "").lower()
            is_match = text.lower() in prompt_name or text.lower() in prompt_content

            # Logic for visibility
            if item.parent(): # It's a prompt item
                item.setHidden(not is_match)
            iterator += 1

        # After filtering, update visibility of categories
        for i in range(self.prompt_tree.topLevelItemCount()):
            category_item = self.prompt_tree.topLevelItem(i)
            has_visible_child = False
            for j in range(category_item.childCount()):
                if not category_item.child(j).isHidden():
                    has_visible_child = True
                    break
            category_item.setHidden(not has_visible_child)
            # Always expand categories when searching to show results
            if has_visible_child and text:
                category_item.setExpanded(True)
            elif not text:
                category_item.setExpanded(False)


    def _populate_prompts(self):
        self.prompt_tree.clear()
        for category, prompts in self.ai_prompts.items():
            category_item = QTreeWidgetItem(self.prompt_tree, [category])
            font = category_item.font(0)
            font.setBold(True)
            category_item.setFont(0, font)
            # Make categories non-selectable but clickable to expand/collapse
            category_item.setFlags(category_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            for prompt_name, prompt_text in prompts.items():
                prompt_item = QTreeWidgetItem(category_item, [prompt_name])
                prompt_item.setData(0, Qt.ItemDataRole.UserRole, prompt_text)
                prompt_item.setToolTip(0, prompt_text)
        # Collapse all categories by default
        self.prompt_tree.collapseAll()


    def _on_prompt_selected(self, item, column):
        if item and item.parent():
            prompt_text = item.data(0, Qt.ItemDataRole.UserRole)
            if prompt_text:
                self.user_input.setText(prompt_text)
                self.user_input.setFocus() # Focus the input field

    def _add_chat_bubble(self, message, is_user):
        bubble = ChatBubble(message, is_user, parent=self.chat_list)
        item = QListWidgetItem(self.chat_list)

        # This is the key fix: connect the bubble's size change signal
        # to a lambda that updates the QListWidgetItem's size hint.
        bubble.sizeHintChanged.connect(lambda: item.setSizeHint(bubble.sizeHint()))

        # Set initial size hint
        item.setSizeHint(bubble.sizeHint())

        self.chat_list.addItem(item)
        self.chat_list.setItemWidget(item, bubble)
        self.chat_list.scrollToBottom()

    def _show_typing_indicator(self, show=True):
        if show:
            self.typing_indicator.show()
            self.typing_indicator.start_animation()
        else:
            self.typing_indicator.hide()
            self.typing_indicator.stop_animation()

    def send_message(self):
        user_text = self.user_input.text().strip()
        if not user_text: return
        self._add_chat_bubble(user_text, is_user=True)
        self.user_input.clear()
        self.start_ai_analysis(user_text)

    def start_ai_analysis(self, prompt):
        ai_settings = self.parent.get_ai_settings()
        if not ai_settings: return
        self._show_typing_indicator(True)
        self.ai_thread = AIAnalysisThread(prompt, ai_settings, self)
        self.ai_thread.response_ready.connect(self.handle_ai_response)
        self.ai_thread.error.connect(self.handle_ai_error)
        self.ai_thread.finished.connect(self.on_ai_thread_finished)
        self.ai_thread.start()

    def handle_ai_response(self, chunk, is_thinking, is_final_answer_chunk):
        self._show_typing_indicator(False)
        if is_thinking:
            if not self.thinking_widget:
                self.thinking_widget = ThinkingWidget(parent=self.chat_list)
                item = QListWidgetItem(self.chat_list)
                item.setSizeHint(self.thinking_widget.sizeHint())
                self.chat_list.addItem(item)
                self.chat_list.setItemWidget(item, self.thinking_widget)
            self.thinking_widget.append_text(chunk)
        else:
            # Collapse the thinking widget if it exists and is open
            if self.thinking_widget and not self.thinking_widget.is_collapsed():
                 self.thinking_widget.toggle_content()

            if self.current_ai_bubble is None:
                # Create the bubble and the list item that will hold it
                self.current_ai_bubble = ChatBubble("", is_user=False, is_streaming=True, parent=self.chat_list)
                item = QListWidgetItem(self.chat_list)

                # Connect the signal to the slot
                self.current_ai_bubble.sizeHintChanged.connect(lambda: item.setSizeHint(self.current_ai_bubble.sizeHint()))

                # Set initial size and add to the list
                item.setSizeHint(self.current_ai_bubble.sizeHint())
                self.chat_list.addItem(item)
                self.chat_list.setItemWidget(item, self.current_ai_bubble)

            self.current_ai_bubble.append_text(chunk)
            # Continually scroll to the bottom as new content is added
            self.chat_list.scrollToBottom()

    def on_ai_thread_finished(self):
        self._show_typing_indicator(False)
        if self.current_ai_bubble:
            self.current_ai_bubble.finish_streaming()
        # Reset for the next message
        self.thinking_widget = None
        self.current_ai_bubble = None

    def handle_ai_error(self, error_message):
        self._show_typing_indicator(False)
        self._add_chat_bubble(f"**Error:** {error_message}", is_user=False)
        if self.thinking_widget: self.thinking_widget.hide()
        self.thinking_widget = None
        self.current_ai_bubble = None

    def send_to_analyst(self, tool_name, results_data=None, context=None):
        formatted_results, header = "", ""
        if tool_name == "nmap":
            header = f"Nmap scan results for target: {context}"
            if results_data and etree:
                try:
                    # A more robust parsing of Nmap XML for the AI prompt
                    root = etree.fromstring(results_data.encode('utf-8'))
                    lines = [f"Host: {host.find('address').get('addr')} ({host.find('status').get('state')})"]
                    for port in host.findall('.//port'):
                        if port.find('state').get('state') == 'open':
                            service = port.find('service')
                            product = service.get('product', '')
                            version = service.get('version', '')
                            service_info = f"{product} {version}".strip()
                            lines.append(f"  - Port {port.get('portid')}/{port.get('protocol')} ({service.get('name', 'n/a')}): {service_info}")
                    formatted_results = "\n".join(lines)
                except Exception:
                    # Fallback to just sending the raw XML if parsing fails
                    formatted_results = results_data
            else:
                formatted_results = "No Nmap XML data available or LXML not installed."

        elif tool_name == "subdomain":
            header = f"Subdomain scan for: {context}"
            formatted_results = "\n".join([results_data.topLevelItem(i).text(0) for i in range(results_data.topLevelItemCount())])
        elif tool_name == "port_scanner":
            header = f"Port scan for: {context}"
            formatted_results = "\n".join([f"Port {p} is {s} ({srv})" for p, s, srv in results_data])

        if not formatted_results.strip():
            QMessageBox.information(self, "No Data", "No data to send."); return

        full_text = f"You are a cybersecurity expert. Analyze the following from the '{tool_name}' tool and provide a concise summary of potential vulnerabilities, misconfigurations, or recommended next steps for a penetration tester. Be direct and focus on actionable insights.\n\n--- {header} ---\n{formatted_results}\n--- END ---"
        self.user_input.setText(full_text)
        # Switch to the AI Assistant tab and focus the input
        self.parent.tab_widget.setCurrentWidget(self)
        self.user_input.setFocus()
        self.send_message() # Automatically send for analysis

    def _show_ai_settings_menu(self):
        settings_file = "ai_settings.json"
        try:
            settings = {}
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f: settings = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            QMessageBox.warning(self, "Error", f"Could not load AI settings: {e}"); return

        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                border: 1px solid #ccc;
                border-radius: 8px;
                padding: 5px;
            }
            QMenu::item:selected {
                background-color: #2a8afc;
                color: white;
                border-radius: 4px;
            }
            QMenu::separator {
                height: 1px;
                background: #e0e0e0;
                margin-left: 10px;
                margin-right: 10px;
            }
        """)

        provider_group = QActionGroup(self)
        provider_group.setExclusive(True)
        active_provider = settings.get("active_provider")
        active_model = settings.get("active_model")

        # --- Local AI ---
        local_settings = settings.get("local_ai", {})
        if local_model_name := local_settings.get("model"):
            action_text = f"Local: {local_model_name}"
            action = QAction(QIcon(os.path.join("icons", "tool.svg")), action_text, self, checkable=True)
            if active_provider == "local_ai" and active_model == local_model_name:
                action.setChecked(True)
            action.triggered.connect(lambda chk, p="local_ai", m=local_model_name: self._set_active_ai_provider(p, m))
            provider_group.addAction(action)
            menu.addAction(action)

        # --- Online Services ---
        online_settings = settings.get("online_ai", {})
        online_options_exist = any(
            (p_data := online_settings.get(name, {})) and p_data.get("api_key") and p_data.get("model")
            for name in ["OpenAI", "Gemini", "Grok", "DeepSeek", "Qwen"]
        )

        if online_options_exist:
            online_menu = menu.addMenu("Online Services")
            online_menu.setIcon(QIcon(os.path.join("icons", "wifi.svg")))
            for name in ["OpenAI", "Gemini", "Grok", "DeepSeek", "Qwen"]:
                if (p_data := online_settings.get(name, {})) and p_data.get("api_key") and p_data.get("model"):
                    action_text = f"{name}: {p_data['model']}"
                    action = QAction(action_text, self, checkable=True)
                    if active_provider == name and active_model == p_data['model']:
                        action.setChecked(True)
                    action.triggered.connect(lambda chk, p=name, m=p_data['model']: self._set_active_ai_provider(p, m))
                    provider_group.addAction(action)
                    online_menu.addAction(action)
        else:
            # Guide the user to the settings if no online services are set up.
            no_online_action = QAction("Configure Online Services...")
            no_online_action.triggered.connect(self._open_settings_to_online_tab)
            menu.addAction(no_online_action)

        menu.addSeparator()
        settings_action = QAction("Advanced Settings...", self)
        settings_action.setToolTip("Open the full settings dialog to add or edit AI provider configurations.")
        settings_action.triggered.connect(lambda: self.parent._show_ai_settings_dialog(start_tab_index=0))
        settings_action.setIcon(QIcon(os.path.join("icons", "gear.svg")))
        menu.addAction(settings_action)

        menu.exec(self.ai_settings_btn.mapToGlobal(QPoint(0, -menu.sizeHint().height() - 5)))

    def _open_settings_to_online_tab(self):
        """Opens the settings dialog and switches to the online services tab."""
        # The parent method now supports opening to a specific tab index.
        self.parent._show_ai_settings_dialog(start_tab_index=1)

    def _set_active_ai_provider(self, provider, model):
        settings_file = "ai_settings.json"
        try:
            settings = {}
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f: settings = json.load(f)

            settings['active_provider'] = provider
            settings['active_model'] = model

            with open(settings_file, 'w') as f: json.dump(settings, f, indent=4)
            logging.info(f"AI Provider set to {provider} ({model})")
            # Optional: provide feedback without a blocking dialog
            self.parent.status_bar.showMessage(f"AI model changed to {provider}: {model}", 5000)

        except (IOError, json.JSONDecodeError) as e:
            QMessageBox.warning(self, "Error", f"Could not save AI settings: {e}")


class AIAnalysisThread(QThread):
    """
    A thread to run AI analysis requests in the background, supporting streaming.
    Emits signals for each chunk of the response, distinguishing between 'thinking'
    and 'answer' parts of the stream.
    """
    # Signal: (chunk, is_thinking, is_final_answer_chunk)
    response_ready = pyqtSignal(str, bool, bool)
    error = pyqtSignal(str)

    def __init__(self, prompt, settings, parent=None):
        super().__init__(parent)
        self.prompt = prompt
        self.settings = settings
        self.stop_event = Event()

    def run(self):
        try:
            import requests
            import json

            provider = self.settings.get("provider")
            endpoint = self.settings.get("endpoint")
            model = self.settings.get("model")
            api_key = self.settings.get("api_key")

            if not provider or not model or not endpoint:
                raise ValueError("AI provider, model, or endpoint is not configured.")

            headers = {"Content-Type": "application/json"}
            if api_key and provider == "OpenAI":
                headers["Authorization"] = f"Bearer {api_key}"

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": self.prompt}],
                "stream": True
            }

            with requests.post(endpoint, headers=headers, json=payload, stream=True, timeout=60) as response:
                response.raise_for_status()

                is_thinking_phase = False
                is_answer_phase = False

                for line in response.iter_lines():
                    if self.stop_event.is_set(): break
                    if not line: continue

                    line = line.decode('utf-8')
                    if line.startswith('data:'):
                        line = line[5:].strip()

                    try:
                        data = json.loads(line)
                        chunk = data.get('message', {}).get('content', '') or \
                                (data.get('choices', [{}])[0].get('delta', {}).get('content', '')) or \
                                data.get('response', '')

                        if not chunk: continue

                        # Use regex for case-insensitive tag matching and removal
                        if re.search(r'<thinking>', chunk, re.IGNORECASE):
                            is_thinking_phase = True
                            is_answer_phase = False
                            chunk = re.sub(r'<\/?thinking>', '', chunk, flags=re.IGNORECASE).strip()

                        if re.search(r'<answer>', chunk, re.IGNORECASE):
                            is_thinking_phase = False
                            is_answer_phase = True
                            chunk = re.sub(r'<\/?answer>', '', chunk, flags=re.IGNORECASE).strip()

                        if chunk:
                            # The third parameter was incorrect, it should be is_answer_phase
                            self.response_ready.emit(chunk, is_thinking_phase, is_answer_phase)

                    except json.JSONDecodeError:
                        logging.warning(f"Could not decode JSON from stream line: {line}")
                        continue

        except Exception as e:
            error_message = f"Failed to get AI analysis: {e}"
            logging.error(error_message, exc_info=True)
            self.error.emit(error_message)

    def stop(self):
        self.stop_event.set()


class AISettingsDialog(QDialog):
    """A dialog to configure the AI analysis feature."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Analysis Settings")
        self.setMinimumWidth(500)
        self.settings_file = "ai_settings.json"
        self.fetch_thread = None

        # Main layout
        main_layout = QVBoxLayout(self)

        # Tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # --- Local AI Tab ---
        local_ai_widget = QWidget()
        local_ai_layout = QFormLayout(local_ai_widget)

        self.local_endpoint_edit = QLineEdit()
        detect_button = QPushButton("Detect Running Services")
        detect_button.clicked.connect(self.detect_local_services)
        local_ai_layout.addRow("API Endpoint URL:", self.local_endpoint_edit)
        local_ai_layout.addRow(detect_button)

        # Model selection with refresh
        model_layout = QHBoxLayout()
        self.local_model_combo = QComboBox()
        self.local_model_combo.setEditable(True)
        self.local_model_combo.setToolTip("Select an available model or type a custom one.")
        model_layout.addWidget(self.local_model_combo)
        self.refresh_button = QPushButton("Refresh List")
        self.refresh_button.clicked.connect(self.refresh_local_models)
        model_layout.addWidget(self.refresh_button)
        local_ai_layout.addRow("Model Name:", model_layout)

        self.tab_widget.addTab(local_ai_widget, "Local AI (Ollama, etc.)")

        # --- Online Services Tab ---
        online_ai_widget = QWidget()
        online_main_layout = QVBoxLayout(online_ai_widget)

        self.online_provider_tabs = QTabWidget()
        online_main_layout.addWidget(self.online_provider_tabs)

        # Create a dictionary to hold the widgets for each provider
        self.provider_widgets = {}

        # List of providers to add
        providers = ["OpenAI", "Gemini", "Grok", "DeepSeek", "Qwen"]

        for provider_name in providers:
            provider_widget = QWidget()
            provider_layout = QFormLayout(provider_widget)

            api_key_edit = QLineEdit()
            api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)

            model_edit = QLineEdit()

            test_button = QPushButton("Test Connection")

            # Enable the button only for implemented providers
            if provider_name == "OpenAI":
                test_button.setEnabled(True)
                test_button.clicked.connect(lambda checked, p=provider_name: self._test_api_connection(p))
            else:
                test_button.setEnabled(False)
                test_button.setToolTip("Connection test for this provider is not yet implemented.")
                test_button.setToolTip("Connection test for this provider is not yet implemented.")


            provider_layout.addRow(f"{provider_name} API Key:", api_key_edit)
            provider_layout.addRow("Model Name:", model_edit)
            provider_layout.addRow(test_button)

            self.provider_widgets[provider_name] = {
                'api_key': api_key_edit,
                'model': model_edit,
                'test_btn': test_button
            }
            self.online_provider_tabs.addTab(provider_widget, provider_name)

        self.tab_widget.addTab(online_ai_widget, "Online Services")

        # --- Save/Cancel Buttons ---
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.save_settings)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        self.load_settings()

    def detect_local_services(self):
        """Tries to detect common local AI endpoints by checking for open ports."""
        known_services = {
            "Ollama": {"port": 11434, "path": "/api/chat"},
            "LMStudio": {"port": 1234, "path": "/v1/chat/completions"}
        }
        detected_services = []

        for name, details in known_services.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1) # Quick timeout
                    s.connect(("localhost", details["port"]))
                detected_services.append(name)
            except (socket.timeout, ConnectionRefusedError):
                continue

        if not detected_services:
            QMessageBox.information(self, "Detection Result", "No running local AI services (Ollama, LMStudio) could be detected on their default ports.")
        elif len(detected_services) == 1:
            service_name = detected_services[0]
            port = known_services[service_name]["port"]
            path = known_services[service_name]["path"]
            endpoint = f"http://localhost:{port}{path}"
            self.local_endpoint_edit.setText(endpoint)
            QMessageBox.information(self, "Detection Result", f"Detected {service_name} running. Endpoint has been set.\n\nPlease refresh the model list.")
        else: # Multiple services detected
            service_name, ok = QInputDialog.getItem(self, "Multiple Services Detected",
                                                    "Multiple AI services were found. Please select one to configure:",
                                                    detected_services, 0, False)
            if ok and service_name:
                port = known_services[service_name]["port"]
                path = known_services[service_name]["path"]
                endpoint = f"http://localhost:{port}{path}"
                self.local_endpoint_edit.setText(endpoint)

    def refresh_local_models(self):
        """Queries the local AI endpoint to get a list of available models."""
        endpoint = self.local_endpoint_edit.text()
        if not endpoint:
            QMessageBox.warning(self, "Error", "Please enter a local AI endpoint URL first.")
            return

        if endpoint.endswith("/api/chat"):
            tags_url = endpoint.replace("/api/chat", "/api/tags")
        else:
            QMessageBox.information(self, "Unsupported", "Model auto-discovery is currently only supported for Ollama endpoints.")
            return

        self.local_model_combo.clear()
        self.local_model_combo.addItem("Refreshing...")
        self.refresh_button.setEnabled(False)

        # Use the dedicated thread with signals for robust communication
        self.fetch_thread = FetchModelsThread(tags_url, self)
        self.fetch_thread.models_fetched.connect(self.on_models_fetched)
        self.fetch_thread.models_error.connect(self.on_models_error)
        self.fetch_thread.finished.connect(lambda: self.refresh_button.setEnabled(True))
        self.fetch_thread.start()

    def on_models_fetched(self, model_list):
        """Slot to handle successfully fetched models."""
        self.local_model_combo.clear()
        if model_list:
            self.local_model_combo.addItems(model_list)
        else:
            self.local_model_combo.addItem("No models found")
        self.refresh_button.setEnabled(True)

    def on_models_error(self, error_message):
        """Slot to handle errors during model fetching."""
        self.local_model_combo.clear()
        self.local_model_combo.addItem("Error refreshing")
        QMessageBox.warning(self, "Error", f"Could not fetch models: {error_message}")
        self.refresh_button.setEnabled(True)


    def load_settings(self):
        """Loads settings from the JSON file."""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
            else:
                settings = {} # Create empty settings if file doesn't exist

            # Load general settings
            self.tab_widget.setCurrentIndex(settings.get("provider_tab_index", 0))

            # Load Local AI settings
            local_settings = settings.get("local_ai", {})
            self.local_endpoint_edit.setText(local_settings.get("endpoint", "http://localhost:11434/api/chat"))
            self.local_model_combo.setCurrentText(local_settings.get("model", "llama3"))

            # Load Online AI settings
            online_settings = settings.get("online_ai", {})
            self.online_provider_tabs.setCurrentIndex(online_settings.get("selected_provider_index", 0))

            for provider_name, widgets in self.provider_widgets.items():
                provider_data = online_settings.get(provider_name, {})
                widgets['api_key'].setText(provider_data.get('api_key', ''))
                widgets['model'].setText(provider_data.get('model', ''))

        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Could not load AI settings: {e}")
            QMessageBox.warning(self, "Warning", f"Could not load AI settings file: {e}")


    def save_settings(self):
        """Saves the current settings to the JSON file."""

        # Build the online_ai settings dictionary
        online_ai_settings = {
            "selected_provider_index": self.online_provider_tabs.currentIndex()
        }
        for provider_name, widgets in self.provider_widgets.items():
            online_ai_settings[provider_name] = {
                "api_key": widgets['api_key'].text(),
                "model": widgets['model'].text()
            }

        settings = {
            "provider_tab_index": self.tab_widget.currentIndex(),
            "local_ai": {
                "endpoint": self.local_endpoint_edit.text(),
                "model": self.local_model_combo.currentText()
            },
            "online_ai": online_ai_settings
        }
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
            self.accept() # Close the dialog
        except IOError as e:
            QMessageBox.critical(self, "Error", f"Could not save AI settings: {e}")

    def _test_api_connection(self, provider_name):
        widgets = self.provider_widgets.get(provider_name)
        if not widgets:
            return

        api_key = widgets['api_key'].text()
        if not api_key:
            QMessageBox.warning(self, "API Key Missing", f"Please enter an API key for {provider_name} before testing.")
            return

        widgets['test_btn'].setText("Testing...")
        widgets['test_btn'].setEnabled(False)

        self.test_thread = TestAPIThread(provider_name, api_key, self)
        self.test_thread.success.connect(self._on_test_success)
        self.test_thread.error.connect(self._on_test_error)
        self.test_thread.finished.connect(lambda: widgets['test_btn'].setText("Test Connection"))
        self.test_thread.finished.connect(lambda: widgets['test_btn'].setEnabled(True))
        self.test_thread.start()

    def _on_test_success(self, message):
        QMessageBox.information(self, "Connection Successful", message)

    def _on_test_error(self, message):
        QMessageBox.warning(self, "Connection Failed", message)


class AIGuideDialog(QDialog):
    """A dialog to show the user guide for AI features."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Features Guide for GScapy + AI")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout(self)
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)

        guide_html = """
        <html>
        <head>
            <style>
                body { font-family: sans-serif; line-height: 1.6; }
                h1, h2, h3 { color: #4a90e2; }
                code { background-color: #2d313a; padding: 2px 5px; border-radius: 4px; font-family: "Courier New", monospace; }
                a { color: #8be9fd; }
                ul { padding-left: 20px; }
                .button-icon { display: inline-block; width: 16px; height: 16px; vertical-align: middle; }
            </style>
        </head>
        <body>
            <h1>AI Integration Guide (v3.0)</h1>
            <p>This guide explains how to set up and use the new AI analysis features within <b>GScapy + AI</b>.</p>

            <h2>1. Setting Up an AI Service</h2>
            <p>GScapy's AI features work by connecting to a Large Language Model (LLM). You can use a local service that you run on your own machine (ensuring privacy) or an online provider.</p>

            <h3>Local AI (Recommended)</h3>
            <p>We recommend using <b>Ollama</b> or <b>LMStudio</b>.</p>
            <ol>
                <li>Download and install Ollama from <a href="https://ollama.com/">ollama.com</a>.</li>
                <li>Open your terminal and run <code>ollama pull llama3</code> to get a great general-purpose model.</li>
                <li>Ensure the service is running in the background.</li>
            </ol>

            <h3>Online AI</h3>
            <p>You can also connect to providers like OpenAI. You will need an API key from the provider.</p>

            <h2>2. Configuring GScapy + AI</h2>
            <p>You must tell GScapy how to connect to your chosen AI service.</p>
            <ol>
                <li>In the 'AI Assistant' tab, click the settings icon &#x2699; next to the 'Send' button.</li>
                <li>Click 'Advanced Settings...' to open the main configuration dialog.</li>
                <li><b>For Local AI:</b>
                    <ul>
                        <li>Go to the 'Local AI' tab.</li>
                        <li>Use the 'Detect Running Services' button to automatically find Ollama/LMStudio, or enter the endpoint manually (e.g., <code>http://localhost:11434/api/chat</code> for Ollama).</li>
                        <li>Enter the name of the model you have downloaded (e.g., <code>llama3</code>).</li>
                    </ul>
                </li>
                <li><b>For Online Services:</b>
                    <ul>
                        <li>Go to the 'Online Services' tab.</li>
                        <li>Select your provider (e.g., 'OpenAI').</li>
                        <li>Enter your API Key and the model name you wish to use (e.g., <code>gpt-4-turbo</code>).</li>
                    </ul>
                </li>
                <li>Click 'Save'.</li>
            </ol>

            <h2>3. Selecting the Active Model</h2>
            <p>The new AI settings menu makes switching between your configured models easy.</p>
            <ol>
                <li>Click the settings icon &#x2699; in the AI Assistant tab.</li>
                <li>A menu will appear showing all configured Local and Online models.</li>
                <li>Simply click on the model you want to use for your next chat. A checkmark will indicate the active model.</li>
            </ol>


            <h2>4. Using the AI Features</h2>
            <ul>
                <li><b>AI Assistant Tab:</b> The main AI tab has been redesigned.
                    <ul>
                    <li>The left panel contains a categorized list of over 70 prompts. Click any button to load the prompt into the input box.</li>
                    <li>The main chat view now uses conversational bubbles. Your prompts are on the right, and the AI's responses are on the left.</li>
                    </ul>
                </li>
                <li><b>Send to AI Analyst Button:</b> After running a scan in the Nmap, Port Scanner, or Subdomain Scanner tools, click the "Send to AI Analyst" button to automatically load the results into the AI Assistant tab for analysis.</li>
            </ul>
        </body>
        </html>
        """
        text_browser.setHtml(guide_html)
        layout.addWidget(text_browser)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button, 0, Qt.AlignmentFlag.AlignRight)
