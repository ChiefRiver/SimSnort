# SimSnort
Snort Rule Creator, integrates with SecurityOnion

This python file will take you through a stepped based approach to creating snort rules for a snort sensor. (currently only based on content match with modifiers)

SimSnort commandline arguments:

optional arguments:
  -h, --help            show this help message and exit
  -s SOURCES, --sources SOURCES
                        Input file of Source IPs, seperated by newlines
  -d DESTINATIONS, --destinations DESTINATIONS
                        Input file of Destination IPs, seperated by newlines


If ran with sudo privileges on a standalone or master SecurityOnion server you will be able to automatically append the rule to the SecurityOnion default local.rules file and have the choice to run rule-update to let your new rule take affect

The program is one standalone python file "SimSnort"
