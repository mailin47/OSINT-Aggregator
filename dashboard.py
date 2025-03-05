project_name = "AI-Powered OSINT Aggregator"

# Required Imports
import os
import streamlit as st
import sqlite3
from main_script import (
    is_valid_ip, is_valid_url, is_valid_username, is_valid_hash,
    get_ip_info, get_domain_info, check_username_presence,
    get_hash_info, extract_image_metadata, perform_nlp_analysis
)

# Initialize Database
DATABASE = 'osint_data.db'
conn = sqlite3.connect(DATABASE)
c = conn.cursor()

# Streamlit UI Setup
st.set_page_config(page_title=project_name, page_icon="🔍")
st.title(project_name)
st.sidebar.title("OSINT Tool Navigation")
option = st.sidebar.selectbox("Select OSINT Operation:",
                              ('Home','IP & URL Analysis', 'Domain & WHOIS Lookup',
                               'Social Media Username Enumeration', 'File Hash Lookup',
                               'Image Metadata Extraction', 'Threat Intelligence NLP'))

# IP & URL Analysis
if option == "Home":
    st.header("Welcome to the OSINT Aggregator")
    st.write("""
        This tool helps in gathering **Open-Source Intelligence (OSINT)** for cybersecurity investigations. 
        You can analyze various entities like **IP addresses, domains, emails, usernames, file hashes, and images** 
        to gather intelligence from multiple sources.
    """)
    st.write("""
        OSINT is widely used by security professionals, ethical hackers, and researchers to uncover 
        potential threats and vulnerabilities from publicly available data.
    """)
elif option == 'IP & URL Analysis':
    st.header("IP Address Lookup")
    st.write("""
        Enter an **IP address** to retrieve threat intelligence from **Shodan, AbuseIPDB, and VirusTotal**. 
        This helps in identifying suspicious or malicious activity related to the IP.
    """)
    input_data = st.text_input("Enter an IP address or URL:")
    if st.button("Analyze"):
        if is_valid_ip(input_data):
            result = get_ip_info(input_data)
            st.write(result)
        elif is_valid_url(input_data):
            result = get_ip_info(input_data)
            st.write(result)
        else:
            st.error("Invalid IP or URL.")

# Domain & WHOIS Lookup
elif option == 'Domain & WHOIS Lookup':
    st.header("Domain Lookup")
    st.write("""
        Enter a **domain name** to get WHOIS information and related security insights. 
        WHOIS data provides registration details that help in identifying domain ownership and activity.
    """)
    domain = st.text_input("Enter a domain name:")
    if st.button("Get WHOIS Information"):
        result = get_domain_info(domain)
        st.write(result)

# Social Media Username Enumeration
elif option == 'Social Media Username Enumeration':
    st.header("Username Lookup")
    st.write("""
        Enter a **username** to check for its presence on various social media and online platforms. 
        This helps in OSINT investigations related to digital footprint tracking.
    """)
    username = st.text_input("Enter a social media username:")
    if st.button("Check Username"):
        result = check_username_presence(username)
        st.write(result)

# File Hash Lookup
elif option == 'File Hash Lookup':
    st.header("File Hash Analysis")
    st.write("""
        Enter a **file hash (MD5, SHA-1, or SHA-256)** to check its presence in **VirusTotal**. 
        This helps in identifying whether a file has been marked as malicious.
    """)
    file_hash = st.text_input("Enter a file hash (MD5, SHA-1, SHA-256):")
    if st.button("Check File Hash"):
        result = get_hash_info(file_hash)
        st.write(result)

# Image Metadata Extraction
elif option == 'Image Metadata Extraction':
    st.header("Image Metadata Extraction")
    st.write("""
        Upload an **image file** to extract its metadata. Metadata includes details like 
        camera model, GPS coordinates, and other hidden information stored within the image.
    """)
    uploaded_file = st.file_uploader("Upload an image file:", type=['jpg', 'png', 'jpeg'])
    if uploaded_file is not None and st.button("Extract Metadata"):
        result = extract_image_metadata(uploaded_file)
        st.write(result)

# Threat Intelligence NLP
elif option == 'Threat Intelligence NLP':
    text_data = st.text_area("Enter text for NLP analysis:")
    if st.button("Analyze Text"):
        result = perform_nlp_analysis(text_data)
        st.write(result)

conn.close()
