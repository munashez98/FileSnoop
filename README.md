# FileSnoop

## A tool capable of conducting various static analysis operations to analyze a file. This tool comes with a built event monitor. 
Note for Windows users: This binary was designed for Unix-based systems, you may have to make some edits to the script for your system.

# Installation:
To run this binary navigate to the bin folder and run:
> pip install -r requirements.txt


# Running 
To run this script input snoop.py followed by the relevant command on your command-line. The commands below are used to run this tool:

## --help

Displays the help menu

## hash [file]

Returns a SHA256 hash of the file

## entropy [file]

Calculates and returns the entropy of a file

## strings [file]

Pulls strings from the file and outputs them to another

## domains [file]

searches for domains and IP addresses in the file

## searchvt [file]

Search for the file on VirusTotal to see how many databases have it flagged as malicious

## repcheck [file]

Search the reputation of domains and IP addresses found in a file

## dynamic

Starts the event monitor. If no folder is specified it will scan the entire system


# Issues
`
ImportError: urllib3 v2.0 only supports OpenSSL 1.1.1+, currently the 'ssl' module is compiled with 'OpenSSL 1.1.0h 
`
Upgrade python or downgrade urllib. I used 1.26.15
