import logging
import json
import os
import re
import socket

from PyQt6.QtCore import (
    pyqtSignal, Qt, QTimer, QPoint, QSize, QPropertyAnimation, QEasingCurve,
    QParallelAnimationGroup, QSequentialAnimationGroup
)
from PyQt6.QtGui import QActionGroup, QAction, QPalette, QIcon, QImage, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGridLayout,
    QDialog, QTabWidget, QLineEdit, QPushButton, QComboBox, QMessageBox,
    QInputDialog, QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem,
    QFrame, QMenu, QTextEdit, QTextBrowser, QGroupBox, QLabel, QSplitter
)

from ai_threads import FetchModelsThread, TestAPIThread, AIAnalysisThread

# This function is used by the AIAssistantTab and its components
def create_themed_icon(icon_path, color_str):
    """Loads an SVG, intelligently replaces its color, and returns a QIcon."""
    try:
        with open(icon_path, 'r', encoding='utf-8') as f:
            svg_data = f.read()

        # First, try to replace a stroke color in a style block (for paper-airplane.svg)
        themed_svg_data, count = re.subn(r'stroke:#[0-9a-fA-F]{6}', f'stroke:{color_str}', svg_data)

        # If no stroke was found in a style, fall back to injecting a fill attribute (for gear.svg)
        if count == 0 and '<svg' in themed_svg_data:
            themed_svg_data = themed_svg_data.replace('<svg', f'<svg fill="{color_str}"')

        image = QImage.fromData(themed_svg_data.encode('utf-8'))
        pixmap = QPixmap.fromImage(image)
        return QIcon(pixmap)
    except Exception as e:
        logging.warning(f"Could not create themed icon for {icon_path}: {e}")
        return QIcon(icon_path) # Fallback to original icon


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


class AIAnalysisDialog(QDialog):
    """A dialog to show the results of AI analysis."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Analysis")
        self.setMinimumSize(600, 400)

        layout = QVBoxLayout(self)
        self.results_text = QTextEdit("Analyzing... Please wait.")
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)

        button_layout = QHBoxLayout()
        copy_button = QPushButton("Copy to Clipboard")
        copy_button.clicked.connect(self.copy_results)
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addStretch()
        button_layout.addWidget(copy_button)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def set_results(self, text):
        self.results_text.setPlainText(text)

    def set_error(self, text):
        self.results_text.setPlainText(f"An error occurred:\n\n{text}")

    def copy_results(self):
        QApplication.clipboard().setText(self.results_text.toPlainText())


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


class TypingIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(40)
        self.dots = []
        self.animations = QParallelAnimationGroup(self)

        for i in range(3):
            dot = QLabel("●", self)
            dot.setStyleSheet("color: #909090; font-size: 20px;")
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
            seq.setLoopCount(-1) # Loop indefinitely
            self.animations.addAnimation(seq)

    def start_animation(self):
        self.animations.start()

    def stop_animation(self):
        self.animations.stop()


class ThinkingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_expanded = True
        self._init_ui()
        self.set_stylesheet() # Apply theme-aware styles

    def _init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.header_frame = QFrame()
        header_layout = QHBoxLayout(self.header_frame)
        header_layout.setContentsMargins(5, 5, 5, 5)

        self.toggle_button = QPushButton("Thinking...")
        self.toggle_button.setStyleSheet("border: none; text-align: left; font-weight: bold;")
        self.toggle_button.clicked.connect(self.toggle_content)

        self.arrow_label = QLabel("\u25BC") # Down-pointing arrow
        self.arrow_label.setStyleSheet("border: none;")

        header_layout.addWidget(self.toggle_button)
        header_layout.addStretch()
        header_layout.addWidget(self.arrow_label)

        self.content_widget = QTextEdit()
        self.content_widget.setReadOnly(True)

        self.main_layout.addWidget(self.header_frame)
        self.main_layout.addWidget(self.content_widget)
        self.adjustSize()

    def set_stylesheet(self):
        """Sets theme-aware stylesheet."""
        palette = self.palette()
        base_color = palette.color(QPalette.ColorRole.Base)
        # A color slightly lighter/darker than the base for the header
        header_color = base_color.lighter(110) if base_color.lightness() < 128 else base_color.darker(103)
        # A color for the content that is between the header and the base
        content_color = base_color.lighter(105) if base_color.lightness() < 128 else base_color.darker(101)
        border_color = palette.color(QPalette.ColorRole.Mid).name()
        text_color = palette.color(QPalette.ColorRole.Text).name()
        muted_text_color = palette.color(QPalette.ColorRole.Mid).name()

        self.header_frame.setStyleSheet(f"background-color: {header_color.name()}; border-radius: 5px;")
        self.content_widget.setStyleSheet(f"""
            background-color: {content_color.name()};
            border: 1px solid {border_color};
            border-top: none;
            border-radius: 5px;
            color: {muted_text_color};
        """)
        self.toggle_button.setStyleSheet(f"border: none; text-align: left; font-weight: bold; color: {text_color};")
        self.arrow_label.setStyleSheet(f"border: none; color: {text_color};")

    def toggle_content(self):
        self.is_expanded = not self.is_expanded
        self.content_widget.setVisible(self.is_expanded)
        self.arrow_label.setText("\u25BC" if self.is_expanded else "\u25B6")

        # We need to inform the list view that our size has changed.
        # A simple way is to update the geometry of the top-level widget.
        if self.parentWidget():
            self.parentWidget().updateGeometry()
            # Find the QListWidgetItem this widget belongs to and update its size hint
            for i in range(self.parentWidget().count()):
                item = self.parentWidget().item(i)
                widget = self.parentWidget().itemWidget(item)
                if widget is self:
                    item.setSizeHint(self.sizeHint())
                    break

    def append_text(self, text):
        self.content_widget.append(text)
        self.adjustSize()
        if self.parentWidget():
             self.parentWidget().updateGeometry()

    def is_collapsed(self):
        return not self.is_expanded


class ChatBubble(QFrame):
    """
    A QFrame-based chat bubble that correctly handles dynamic text resizing,
    word wrapping, and theming.
    """
    def __init__(self, text, is_user, parent=None):
        super().__init__(parent)
        self.is_user = is_user

        # Main layout for the bubble
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(10, 8, 10, 8) # Padding inside the bubble

        # The QLabel will handle the text display
        self.label = QLabel(text)
        self.label.setWordWrap(True)
        # Allow text selection and link interaction
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.LinksAccessibleByMouse)
        self.label.setOpenExternalLinks(True)

        # Set a max width for the label based on the parent list view
        if parent:
            # Set a reasonable maximum width for the bubble to ensure it doesn't span the entire chat view.
            # This helps with readability and the classic chat look.
            self.setMaximumWidth(int(parent.width() * 0.75))


        # A wrapper widget to control the alignment of the bubble
        self.wrapper = QWidget()
        self.wrapper_layout = QHBoxLayout(self.wrapper)
        self.wrapper_layout.setContentsMargins(5, 2, 5, 2) # Margins for the entire list item
        if self.is_user:
            self.wrapper_layout.addStretch()
            self.wrapper_layout.addWidget(self)
        else:
            self.wrapper_layout.addWidget(self)
            self.wrapper_layout.addStretch()

        self.layout.addWidget(self.label)
        self.set_stylesheet()

    def set_stylesheet(self):
        """Sets the stylesheet using the application's palette for theme-awareness."""
        palette = self.palette()
        if self.is_user:
            # User messages use the theme's highlight color (e.g., blue in default themes)
            bg_color = palette.color(QPalette.ColorRole.Highlight).name()
            text_color = palette.color(QPalette.ColorRole.HighlightedText).name()
            self.setStyleSheet(f"""
                ChatBubble {{
                    background-color: {bg_color};
                    color: {text_color};
                    border-radius: 15px;
                    border-bottom-right-radius: 3px;
                }}
            """)
        else:
            # AI messages use a color slightly different from the base window color
            # This creates a subtle visual distinction. We calculate this color.
            base_color = palette.color(QPalette.ColorRole.Base)
            # Make the AI bubble slightly lighter or darker depending on the theme
            bg_color = base_color.lighter(115) if base_color.lightness() < 128 else base_color.darker(105)
            text_color = palette.color(QPalette.ColorRole.Text).name()
            self.setStyleSheet(f"""
                ChatBubble {{
                    background-color: {bg_color.name()};
                    color: {text_color};
                    border-radius: 15px;
                    border-bottom-left-radius: 3px;
                }}
            """)

        # The label inside the bubble should have a transparent background
        self.label.setStyleSheet(f"color: {text_color}; background-color: transparent;")

    def append_text(self, text_chunk):
        """Appends a chunk of text to the label."""
        self.label.setText(self.label.text() + text_chunk)
        # Recalculate the size hint of the wrapper
        self.wrapper.adjustSize()
        self.wrapper.parent().updateGeometry()


    def get_wrapper(self):
        """Returns the alignment wrapper widget."""
        return self.wrapper

    def finish_streaming(self):
        # This method is kept for API compatibility but the styling is now static
        pass


class AIAssistantTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent # GScapy main window instance
        self.thinking_widget = None
        self.current_ai_bubble = None
        self.ai_thread = None

        self.ai_prompts = {
            "Threat Detection & Analysis": {
                "Analyze Firewall Logs": "Analyze the following firewall logs and identify any unauthorized or suspicious inbound connections. Look for patterns of repeated denied connections from a single source, connections to non-standard ports, or traffic originating from known malicious IP addresses.",
                "Flag Abnormal Processes": "Monitor the following list of system processes and flag any abnormal behavior or potential malware indicators. Look for unusually named processes, processes with high CPU/memory usage, or processes making unexpected network connections.",
                "Deep Scan for Stealthy Malware": "Given the following network traffic dump, conduct a deep scan of the network to identify any hidden or stealthy malware infections. Look for covert channels, unusual DNS queries, or encrypted traffic to unknown endpoints.",
                "Detect Phishing Attempts": "Analyze the following email headers and content to detect phishing attempts or email spoofing. Check for mismatches in 'From' and 'Reply-To' fields, suspicious links, urgent language, and generic greetings.",
                "Review Web Server Logs for Attacks": "Review the following web server logs for any unusual HTTP requests or patterns indicative of an attack, such as SQL injection, cross-site scripting (XSS), or directory traversal attempts.",
                "Scan Database Logs for Breaches": "Scan the following database logs and identify any unauthorized access attempts or unusual data queries. Look for queries from unexpected IP addresses, unusually large data exports, or repeated failed login attempts.",
                "Detect DNS Hijacking": "Analyze the following DNS traffic and detect any signs of domain hijacking or DNS poisoning. Look for unexpected responses to DNS queries or traffic being redirected to suspicious IP addresses.",
                "Identify Network Misconfigurations": "Perform a vulnerability scan on the following list of network devices and identify any potential weaknesses or misconfigurations, such as open management ports, default credentials, or outdated firmware.",
                "Detect Data Exfiltration": "Analyze the following network traffic patterns to detect any large data exfiltration or unusual data transfers. Look for large, encrypted uploads to external sites or sustained outbound connections.",
                "Identify Brute-Force Attacks": "Monitor the following system login attempts and identify any brute-force attacks or login anomalies. Look for a high volume of failed logins from a single IP or for a single user account.",
            },
            "Incident Response": {
                "Fuzz for XML Files with Gobuster": "How can I fuzz for .xml files on a web server at {TARGET_URL} using gobuster?",
                "Guide Evidence Collection": "Guide an incident response team through collecting and preserving evidence from a compromised Windows server. Include steps for memory acquisition, disk imaging, and log collection.",
                "Ransomware Recovery Steps": "Assist in restoring systems from a backup to recover from a ransomware attack. Provide a step-by-step plan, including isolating the network, verifying backups, and safely reintroducing systems.",
                "DDoS Mitigation Plan": "Provide step-by-step instructions to mitigate the impact of a distributed denial-of-service (DDoS) attack targeting our main web server at {TARGET_IP}.",
                "Forensic Analysis Guide": "Assist in performing a forensic analysis on a compromised Linux system to identify the incident’s root cause. What are the first 5 steps I should take?",
                "Coordinate IR Team Communication": "Act as a facilitator for communication and collaboration among incident response team members during a major security incident. What are the key pieces of information to share?",
                "Contain a Spreading Malware": "Recommend and execute incident containment measures to minimize further damage from a malware infection that is spreading across the corporate network.",
                "Generate Incident Report": "Assist in generating an incident response report with detailed timelines, actions taken, and lessons learned from the provided data.",
                "Engage Law Enforcement": "Guide an incident response team through the process of notifying and engaging law enforcement agencies for a cybercrime event.",
                "Post-Incident Review Guide": "Assist in conducting a post-incident review to identify vulnerabilities and improve incident response procedures after a data breach.",
            },
            "Vulnerability Assessment & PenTesting": {
                "Scan for SMB Vulnerabilities with Nmap": "How can I scan for SMB vulnerabilities on the subnet {TARGET_SUBNET} using Nmap scripts?",
                "Simulate Phishing Campaign": "I need to simulate a phishing campaign targeting employees to assess their susceptibility and raise awareness. Provide three different email templates for this.",
                "Penetration Test Web Application": "Perform a penetration test on the following web application description to identify potential security flaws and suggest remediation measures. The application is a customer portal at {TARGET_URL}.",
                "Secure Wireless Network": "Analyze the following wireless network configuration and recommend security enhancements to prevent unauthorized access. The current setup uses WPA2-PSK with a known weak password.",
                "Harden Web Server": "Review the following Nginx server configuration and recommend hardening measures to protect against known vulnerabilities and exploits.",
                "Evaluate Physical Security": "Assess the effectiveness of physical security controls by simulating unauthorized access attempts to a restricted data center. What are common techniques to test?",
                "Test DDoS Resilience": "Evaluate the resilience of our network infrastructure against a DDoS attack. Propose three different mitigation strategies we could implement.",
                "Assess IoT Device Security": "Conduct a vulnerability assessment on an IoT camera at IP {TARGET_IP}. Identify potential entry points for attackers and recommend security measures.",
                "Audit Third-Party Vendor Security": "Assess the security posture of a third-party vendor by conducting a security audit. Provide a checklist of the top 10 things to review.",
                "Review Incident Response Plan": "Review our organization’s incident response plan and simulate a ransomware attack scenario to identify areas for improvement.",
                "Suggest Nmap Command": "Suggest a good Nmap command to run against a target. The target is: ",
                "Find Exploits for Service": "Find potential exploits for a service running 'Apache 2.4.41' on a Linux server.",
                "Analyze Nmap Scan": "Analyze the following Nmap scan results for potential vulnerabilities and suggest the next 3 steps for a penetration tester.",
                "Check for CVEs": "You are a vulnerability analysis expert. Analyze the following scan results for services and versions, then list any known CVEs for them.",
                "Explain Results to Non-Expert": "Explain the following scan results in simple, non-technical terms. What was the tool trying to do, and what do the results mean?",
            },
            "Scripting & Automation": {
                "Generate Nmap Port Scan Script": "Generate a bash script that automates port scanning with Nmap for a list of IPs in a file named 'targets.txt' and saves the output for each IP.",
                "Create Python Scapy Script": "Write a Python script using Scapy to send a TCP SYN packet to port 80 of a target IP address and print whether the port is open or closed.",
                "Automate Log Analysis with Python": "Write a Python script to parse an Apache access log file and identify the top 10 IP addresses with the most requests.",
                "PowerShell for User Audit": "Write a PowerShell script to audit all local user accounts on a Windows machine and flag any that have not been logged into for over 90 days.",
                "Bash Script to Check for Open Ports": "Create a simple bash script that uses 'netcat' to check if a specific port is open on a given host.",
                "Detect Registry Changes with ELK": "Provide an ELK query to detect changes in the Windows Registry, specifically focusing on keys related to startup programs.",
                "Python Script to Detect XSS": "Write a Python script that takes a URL as input and checks for basic reflected XSS vulnerabilities by testing common payloads in URL parameters.",
                "Automate Subdomain Enumeration": "Create a bash script that chains together 'subfinder' and 'httpx' to find live subdomains for a given domain.",
                "PowerShell to Disable Inactive Accounts": "Write a PowerShell script for Active Directory that finds user accounts that have been inactive for 60 days and disables them.",
                "Python Script for Password Strength": "Write a Python script that takes a password as input and rates its strength based on length, and inclusion of uppercase, lowercase, numbers, and symbols.",
            },
            "Policy & Compliance": {
                "Draft Data Protection Policy": "Provide guidance on drafting a data protection and privacy policy in accordance with GDPR for a small e-commerce company.",
                "Update Security Policies": "Review the following (outdated) security policy and suggest updates to align with modern industry best practices and the evolving threat landscape.",
                "Develop Password Management Policy": "Assist in developing a password management policy that promotes strong, unique passwords and the use of multi-factor authentication (MFA).",
                "Create Mobile Device Policy (BYOD)": "Offer recommendations for creating a mobile device management policy (MDM) to secure employee-owned devices (BYOD) and protect corporate data.",
                "Establish Network Access Control Policy": "Assist in establishing a network access control (NAC) policy to ensure only authorized and compliant devices can connect to the organization’s network.",
                "Outline Incident Response Policy": "Provide guidance on creating an incident response policy that clearly outlines roles, responsibilities, communication channels, and escalation procedures.",
                "Define Patch Management Policy": "Help define a patch management policy that ensures timely updates and vulnerability remediation across all systems and software, with a focus on critical assets.",
                "Develop Encryption Policy": "Assist in developing a data encryption policy to protect sensitive data at rest and in transit, specifying required algorithms and key management procedures.",
                "Create Employee Training Policy": "Guide the creation of an employee security training and awareness policy to promote a security-conscious culture within the organization.",
                "Generate ROE Report": "You are a senior penetration testing engagement manager. Based on the provided target scope, generate a formal Rules of Engagement (ROE) document in Markdown format.",
            },
        }

        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # --- Left Panel: Prompts ---
        self.prompt_tree = QTreeWidget()
        self.prompt_tree.setHeaderHidden(True)
        self.prompt_tree.itemClicked.connect(self._on_prompt_selected)
        self._populate_prompts()
        splitter.addWidget(self.prompt_tree)

        # --- Right Panel: Chat ---
        chat_container = QWidget()
        chat_layout = QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(10, 10, 10, 10)
        chat_layout.setSpacing(6) # Reduced spacing

        # Header
        header = QTextBrowser()
        header.setHtml("""
            <div align="center">
                <h2>GScapy + AI Assistant</h2>
                <p>Your smart, context-aware cybersecurity assistant.</p>
            </div>
        """)
        header.setFixedHeight(80)
        header.setStyleSheet("QTextBrowser { border: none; background: transparent; }")
        chat_layout.addWidget(header)

        # Chat message list
        self.chat_list = QListWidget(self)
        self.chat_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.chat_list.setStyleSheet("QListWidget { border: none; background-color: transparent; }")
        self.chat_list.setSpacing(5) # Spacing between bubbles
        chat_layout.addWidget(self.chat_list)

        # Typing indicator
        self.typing_indicator = TypingIndicator(self)
        self.typing_indicator.setFixedHeight(30)
        self.typing_indicator.hide()
        chat_layout.addWidget(self.typing_indicator)

        # Bottom input controls
        bottom_controls_layout = QHBoxLayout()
        self.input_frame = QFrame(self)
        self.input_frame.setObjectName("inputFrame")
        input_frame_layout = QHBoxLayout(self.input_frame)
        input_frame_layout.setContentsMargins(15, 5, 5, 5)
        input_frame_layout.setSpacing(10)

        self.user_input = QLineEdit(self)
        self.user_input.setPlaceholderText("Ask the AI Assistant...")
        self.user_input.setStyleSheet("border: none; background-color: transparent; font-size: 14px;")
        input_frame_layout.addWidget(self.user_input)

        self.send_button = QPushButton()
        self.send_button.setFixedSize(30, 30) # Slightly smaller
        self.send_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        self.send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_button.setToolTip("Send Message")
        input_frame_layout.addWidget(self.send_button)

        bottom_controls_layout.addWidget(self.input_frame)

        self.ai_settings_btn = QPushButton()
        self.ai_settings_btn.setToolTip("Configure & Select AI Models")
        self.ai_settings_btn.setFixedSize(40, 40)
        self.ai_settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_settings_btn.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        bottom_controls_layout.addWidget(self.ai_settings_btn)

        chat_layout.addLayout(bottom_controls_layout)
        splitter.addWidget(chat_container)
        splitter.setSizes([250, 750])

        # --- Connections ---
        self.send_button.clicked.connect(self.send_message)
        self.user_input.returnPressed.connect(self.send_message)
        self.ai_settings_btn.clicked.connect(self._show_ai_settings_menu)

        self.update_theme() # Set initial themed icons and styles

    def update_theme(self):
        """Updates the icon color and other theme-dependent widgets."""
        palette = self.palette()
        text_color = palette.color(QPalette.ColorRole.WindowText).name()
        base_color = palette.color(QPalette.ColorRole.Base).name()
        border_color = palette.color(QPalette.ColorRole.Mid).name()

        # Update icons
        self.ai_settings_btn.setIcon(create_themed_icon(os.path.join("icons", "gear.svg"), text_color))
        self.ai_settings_btn.setIconSize(QSize(24, 24))
        self.send_button.setIcon(create_themed_icon(os.path.join("icons", "paper-airplane.svg"), text_color))
        self.send_button.setIconSize(QSize(24, 24))

        # Update input bar style
        self.input_frame.setStyleSheet(f"""
            #inputFrame {{
                border: 1px solid {border_color};
                border-radius: 18px;
                background-color: {base_color};
            }}
        """)

        # Update any existing chat bubbles
        for i in range(self.chat_list.count()):
            item = self.chat_list.item(i)
            widget = self.chat_list.itemWidget(item)
            if widget:
                # The item widget is the wrapper, its child is the bubble
                bubble = widget.findChild(ChatBubble)
                if bubble:
                    bubble.set_stylesheet()
                thinking_widget = widget.findChild(ThinkingWidget)
                if thinking_widget:
                    thinking_widget.set_stylesheet()

    def _populate_prompts(self):
        for category, prompts in self.ai_prompts.items():
            category_item = QTreeWidgetItem(self.prompt_tree, [category])
            font = category_item.font(0)
            font.setBold(True)
            category_item.setFont(0, font)
            category_item.setFlags(category_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            for prompt_name, prompt_text in prompts.items():
                prompt_item = QTreeWidgetItem(category_item, [prompt_name])
                prompt_item.setData(0, Qt.ItemDataRole.UserRole, prompt_text)
                prompt_item.setToolTip(0, prompt_text)

    def _on_prompt_selected(self, item, column):
        if item and item.parent():
            prompt_text = item.data(0, Qt.ItemDataRole.UserRole)
            if prompt_text:
                self.user_input.setText(prompt_text)

    def _add_chat_bubble(self, message, is_user, is_streaming=False):
        # Create the bubble and its alignment wrapper
        bubble = ChatBubble(message, is_user, parent=self.chat_list)
        bubble_wrapper = bubble.get_wrapper()

        # Create a list item and associate the wrapper widget with it
        item = QListWidgetItem(self.chat_list)
        # Set the size hint based on the wrapper's preferred size
        item.setSizeHint(bubble_wrapper.sizeHint())

        self.chat_list.addItem(item)
        self.chat_list.setItemWidget(item, bubble_wrapper)

        # Scroll to the bottom to show the new message
        QTimer.singleShot(50, self.chat_list.scrollToBottom)

        if is_streaming:
            return bubble # Return the bubble instance for streaming updates
        return None

    def _show_typing_indicator(self, show=True):
        if show:
            self.typing_indicator.show()
            self.typing_indicator.start_animation()
        else:
            self.typing_indicator.hide()
            self.typing_indicator.stop_animation()

    def send_message(self):
        user_text = self.user_input.text().strip()
        if not user_text:
            return
        # Add the user's message to the chat
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
                self.thinking_widget = ThinkingWidget()
                item = QListWidgetItem(self.chat_list)
                item.setSizeHint(self.thinking_widget.sizeHint())
                self.chat_list.addItem(item)
                self.chat_list.setItemWidget(item, self.thinking_widget)
                self.thinking_widget.show()
            self.thinking_widget.append_text(chunk)
        else:
            if self.thinking_widget and not self.thinking_widget.is_collapsed():
                 self.thinking_widget.toggle_content()
            if self.thinking_widget and not self.thinking_widget.is_collapsed():
                 self.thinking_widget.toggle_content()
                 self.thinking_widget.hide()

            if self.current_ai_bubble is None:
                # Create the streaming bubble for the AI's response
                self.current_ai_bubble = self._add_chat_bubble("", is_user=False, is_streaming=True)

            if self.current_ai_bubble:
                self.current_ai_bubble.append_text(chunk)
                # We need to update the geometries to ensure the list item resizes
                self.chat_list.updateGeometries()
                QTimer.singleShot(50, self.chat_list.scrollToBottom)

    def on_ai_thread_finished(self):
        self._show_typing_indicator(False)
        if self.current_ai_bubble:
            self.current_ai_bubble.finish_streaming()
        self.thinking_widget = None
        self.current_ai_bubble = None

    def handle_ai_error(self, error_message):
        self._show_typing_indicator(False)
        self._add_chat_bubble(f"Error: {error_message}", is_user=False)
        if self.thinking_widget: self.thinking_widget.hide()
        self.thinking_widget = None
        self.current_ai_bubble = None

    def send_to_analyst(self, tool_name, results_data=None, context=None):
        formatted_results, header = "", ""
        if tool_name == "nmap":
            header = f"Nmap scan results for target: {context}"
            if results_data:
                try:
                    root = etree.fromstring(results_data.encode('utf-8'))
                    lines = [f"Host: {host.find('address').get('addr')}"]
                    for port in host.findall('ports/port'):
                        if port.find('state').get('state') == 'open':
                            service = port.find('service')
                            lines.append(f"  - Port {port.get('portid')}/{port.get('protocol')} ({service.get('name', 'n/a')}): {service.get('product', '')}")
                    formatted_results = "\n".join(lines)
                except Exception: formatted_results = results_data
            else: formatted_results = "No Nmap XML data available."
        elif tool_name == "subdomain":
            header, formatted_results = f"Subdomain scan for: {context}", "\n".join([results_data.topLevelItem(i).text(0) for i in range(results_data.topLevelItemCount())])
        elif tool_name == "port_scanner":
            header, formatted_results = f"Port scan for: {context}", "\n".join([f"Port {p} is {s} ({srv})" for p, s, srv in results_data])
        if not formatted_results.strip():
            QMessageBox.information(self, "No Data", "No data to send."); return
        full_text = f"Analyze the following from {tool_name} and summarize potential vulnerabilities or next steps.\n\n--- {header} ---\n{formatted_results}\n--- END ---"
        self.user_input.setText(full_text)
        self.parent.tab_widget.setCurrentWidget(self)

    def _show_ai_settings_menu(self):
        settings_file = "ai_settings.json"
        try:
            settings = {}
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f: settings = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            QMessageBox.warning(self, "Error", f"Could not load AI settings: {e}"); return
        menu = QMenu(self)
        provider_group = QActionGroup(self)
        provider_group.setExclusive(True)
        active_provider, active_model = settings.get("active_provider"), settings.get("active_model")

        # Local AI
        local_settings = settings.get("local_ai", {})
        if local_model_name := local_settings.get("model"):
            action = QAction(f"Local: {local_model_name}", self, checkable=True)
            if active_provider == "local_ai": action.setChecked(True)
            action.triggered.connect(lambda chk, p="local_ai", m=local_model_name: self._set_active_ai_provider(p, m))
            provider_group.addAction(action)
            menu.addAction(action)

        # Online Services
        online_menu = menu.addMenu("Online Services")
        online_settings = settings.get("online_ai", {})
        online_options_exist = False
        for name in ["OpenAI", "Gemini", "Grok", "DeepSeek", "Qwen"]:
            if (p_data := online_settings.get(name, {})) and p_data.get("api_key") and p_data.get("model"):
                online_options_exist = True
                action = QAction(f"{name}: {p_data['model']}", self, checkable=True)
                if active_provider == name: action.setChecked(True)
                action.triggered.connect(lambda chk, p=name, m=p_data['model']: self._set_active_ai_provider(p, m))
                provider_group.addAction(action)
                online_menu.addAction(action)
        online_menu.setEnabled(online_options_exist)

        menu.addSeparator()
        menu.addAction("Advanced Settings...", self.parent._show_ai_settings_dialog)
        menu.exec(self.ai_settings_btn.mapToGlobal(self.ai_settings_btn.rect().bottomLeft()))

    def _set_active_ai_provider(self, provider, model):
        settings_file = "ai_settings.json"
        try:
            settings = {}
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f: settings = json.load(f)
            settings['active_provider'] = provider
            settings['active_model'] = model
            with open(settings_file, 'w') as f: json.dump(settings, f, indent=4)
            QMessageBox.information(self, "AI Model Changed", f"Active model set to:\n{provider}: {model}")
            logging.info(f"AI Provider set to {provider} ({model})")
        except (IOError, json.JSONDecodeError) as e:
            QMessageBox.warning(self, "Error", f"Could not save AI settings: {e}")
