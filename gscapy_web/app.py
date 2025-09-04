import streamlit as st
import requests
import json
import pandas as pd

# --- Configuration ---
API_BASE_URL = "http://127.0.0.1:8000"

# --- Page Setup ---
st.set_page_config(
    page_title="GScapy Web",
    page_icon="🛡️",
    layout="wide"
)

# --- Main UI ---
st.title("GScapy Web Interface")
st.write("A web-based interface for the GScapy toolkit. More tools will be added incrementally.")

# --- Nmap Scanner Tool ---
st.header("Nmap Scanner")

with st.expander("Run Nmap Scan", expanded=True):
    nmap_target = st.text_input("Enter Target IP or Domain", "scanme.nmap.org", key="nmap_target")
    nmap_ports = st.text_input("Ports (optional)", "22,80,443", help="e.g., 22,80,443 or 1-1024", key="nmap_ports")
    nmap_arguments_str = st.text_input("Additional Arguments (optional)", "-sV", help="e.g., -sV -O --script=vuln", key="nmap_args")

    if st.button("Run Nmap Scan"):
        if not nmap_target:
            st.error("Target is a required field.")
        else:
            with st.spinner(f"Running Nmap scan on {nmap_target}... This may take a moment."):
                try:
                    arguments = [arg for arg in nmap_arguments_str.split(' ') if arg]
                    payload = {
                        "target": nmap_target,
                        "ports": nmap_ports if nmap_ports else None,
                        "arguments": arguments
                    }
                    response = requests.post(f"{API_BASE_URL}/api/nmap", json=payload, timeout=300)

                    if response.status_code == 200:
                        st.success("Nmap scan completed!")
                        results = response.json()
                        st.subheader("Raw Output")
                        st.text_area("Raw Nmap Output", results.get("raw_output", "No raw output."), height=300, key="nmap_raw_output")
                        if results.get("xml_output"):
                            st.subheader("XML Output")
                            st.code(results.get("xml_output"), language="xml", line_numbers=True)
                    else:
                        st.error(f"Error from API: {response.status_code}")
                        st.json(response.json())
                except requests.exceptions.RequestException as e:
                    st.error(f"Failed to connect to the backend API: {e}")
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")

# --- AI Assistant ---
st.header("AI Assistant")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Accept user input
if prompt := st.chat_input("What can I help you with?"):
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    # Display user message in chat message container
    with st.chat_message("user"):
        st.markdown(prompt)

    # Display assistant response in chat message container
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        full_response = ""
        try:
            # Stream the response from the API
            with requests.post(f"{API_BASE_URL}/api/ai/chat", json={"prompt": prompt}, stream=True, timeout=300) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=None, decode_unicode=True):
                    full_response += chunk
                    message_placeholder.markdown(full_response + "▌")
            message_placeholder.markdown(full_response)
        except requests.exceptions.RequestException as e:
            st.error(f"Failed to connect to the backend API: {e}")
            full_response = f"Error: Could not connect to the backend. {e}"
        except Exception as e:
            st.error(f"An unexpected error occurred: {e}")
            full_response = f"Error: {e}"

    # Add assistant response to chat history
    st.session_state.messages.append({"role": "assistant", "content": full_response})

# --- ARP Scanner Tool ---
st.header("ARP Scanner")

with st.expander("Run ARP Scan"):
    arp_target = st.text_input("Enter Target Network", "192.168.1.0/24", key="arp_target", help="e.g., 192.168.1.0/24")

    if st.button("Run ARP Scan"):
        if not arp_target:
            st.error("Target network is a required field.")
        else:
            with st.spinner(f"Running ARP scan on {arp_target}..."):
                try:
                    payload = {"target_network": arp_target}
                    response = requests.post(f"{API_BASE_URL}/api/arp", json=payload, timeout=60)

                    if response.status_code == 200:
                        st.success("ARP scan completed!")
                        results = response.json()
                        if results:
                            st.subheader("Discovered Hosts")
                            df = pd.DataFrame(results)
                            st.dataframe(df, use_container_width=True)
                        else:
                            st.info("No hosts responded to the ARP scan.")
                    else:
                        st.error(f"Error from API: {response.status_code}")
                        st.json(response.json())
                except requests.exceptions.RequestException as e:
                    st.error(f"Failed to connect to the backend API: {e}")
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")
