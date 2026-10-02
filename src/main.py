# Refactored entrypoint: hand off to the workflow layer and stop before the legacy monolith runs.
from src.workflow import main as _workflow_main

raise SystemExit(_workflow_main())

#===============================================================#

# Personal Project: Threat Intelligence through APIs Visualization
# Aaron Abaniel || aabaniel

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