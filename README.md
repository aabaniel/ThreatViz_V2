# ThreatViz: A Threat Intelligence Visualizer with APIs
 
This is a Network Simulation Study Project meant for exploratory analysis and will **primarily serve as an experimental work**, rather than a product.

By: @aabaniel, @biacora, @Ishlalalay

The program uses three APIs: VirusTotal, AbuseIPDB, and AlienVault OTX.

**_Made in Python 3.12.4_**

**Dependencies/Libraries to install:**

pip install -r requirements.txt

The project also uses standard-library modules such as `os`, `time`, `csv`, and `json`, which do not need separate installation.

# ThreatViz program flow:

**The program requires the user to input one of the following:**

1. IPv4 Address
2. 'exit'

**The program prints out the following:**

1. Horizontal Bar Chart of AbuseIPDB Report categories tagged with the IP address
2. Bar Chart of Comparison of Scores between VirusTotal, AbuseIPDB, and OTX
3. Bar Chart of VirusTotal Detection count (I.E., malicious, suspicious, harmless, undetected, timeout)
4. Pie Chart of VirusTotal Percentage of Detection categories 
5. Node Graph of VirusTotal of Resolutions related to the IP address
6. Node Graph of VirusTotal of WHOis Ownership/s of the IP address
7. Geological map of the IP address

Note:

_This program ThreatVIz was created with assistance from Copilot through debugging and documentation generation._
