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
                              ('IP & URL Analysis', 'Domain & WHOIS Lookup',
                               'Social Media Username Enumeration', 'File Hash Lookup',
                               'Image Metadata Extraction', 'Threat Intelligence NLP'))

# IP & URL Analysis
if option == 'IP & URL Analysis':
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
    domain = st.text_input("Enter a domain name:")
    if st.button("Get WHOIS Information"):
        result = get_domain_info(domain)
        st.write(result)

# Social Media Username Enumeration
elif option == 'Social Media Username Enumeration':
    username = st.text_input("Enter a social media username:")
    if st.button("Check Username"):
        result = check_username_presence(username)
        st.write(result)

# File Hash Lookup
elif option == 'File Hash Lookup':
    file_hash = st.text_input("Enter a file hash (MD5, SHA-1, SHA-256):")
    if st.button("Check File Hash"):
        result = get_hash_info(file_hash)
        st.write(result)

# Image Metadata Extraction
elif option == 'Image Metadata Extraction':
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