#===============================================================#

# NSCOM03 Network Simulation Study Project
# Threat Intelligence through APIs Visualization 

# Group 2 Members:
# Aaron Abaniel
# Luis Biacora
# Isha Zulueta

#===============================================================#

# Libraries

#===============================================================#
import requests
import matplotlib.pyplot as plt
import networkx as nx
import folium
import os
import time
from matplotlib.patches import Patch
import csv
import json

#===============================================================#

# To install dependencies:

# pip install requests matplotlib networkx folium os time

#===============================================================#

# API Configuration - Current keys are from Aaron Abaniel

#===============================================================#

def load_env_file(env_path=".env"):
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as e:
        print(f"Failed to load .env file: {e}")


load_env_file()

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# initialize keys into variables

HEADERS_VT = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
HEADERS_ABUSE = {"Key": ABUSE_API_KEY, "Accept": "application/json"} if ABUSE_API_KEY else {"Accept": "application/json"}
HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}



#===============================================================#

# Splash screen

#===============================================================#

def splash_screen():
    print("    ███        ▄█    █▄       ▄████████    ▄████████    ▄████████     ███      ▄█    █▄   ▄█   ▄███████▄   ")
    print("▀█████████▄   ███    ███     ███    ███   ███    ███   ███    ███ ▀█████████▄ ███    ███ ███  ██▀     ▄██   ")
    print("   ▀███▀▀██   ███    ███     ███    ███   ███    █▀    ███    ███    ▀███▀▀██ ███    ███ ███▌       ▄███▀  ")
    print("    ███   ▀  ▄███▄▄▄▄███▄▄  ▄███▄▄▄▄██▀  ▄███▄▄▄       ███    ███     ███   ▀ ███    ███ ███▌  ▀█▀▄███▀▄▄    ")
    print("    ███     ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ▀███████████     ███     ███    ███ ███▌   ▄███▀   ▀    ")
    print("    ███       ███    ███   ▀███████████   ███    █▄    ███    ███     ███     ███    ███ ███  ▄███▀        ")
    print("    ███       ███    ███     ███    ███   ███    ███   ███    ███     ███     ███    ███ ███  ███▄     ▄█ ")
    print("   ▄████▀     ███    █▀      ███    ███   ██████████   ███    █▀     ▄████▀    ▀██████▀  █▀    ▀████████▀   ")
    print("        ThreatViz v1         ███    ███   by @aabaniel, @biacora, @Ishlalalay                  \n\n")

# "Font" used and origin:
# patorjk.com - Text to ASCII Art Generator - Delta Corps Priest 1
