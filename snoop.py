
#imports
try:
    import sys
    import os
    from pathlib import Path
    import math
    import string
    import re
    import requests
    import json
    import vt
    import time

    import logging
    from hashlib import sha256
    from py_vmdetect import VMDetect
    from pprint import pprint
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    from watchdog.events import LoggingEventHandler
    from multiprocessing import Process

except Exception as e: print(e)

#global variables
BloCKSIZE = 655356  # global variable that defines max block size that may be read for hashing

def manual():
    manual = """
    Format: snoop.py [command] [file]
    
    Command: \t \t Description
    hash [file] \t Returns a SHA256 hash of your file
    entropy [file] \t Calculates the file entropy
    strings [file] \t Pulls the strings from a file
    domains [file] \t Pull domains and IP addresses from the file
    searchvt [file] \t Search the file on VirusTotal
    repcheck [file] \t Search for the reputation of IP addresses and domains
    dynamic \t \t Monitor Processes and file activity in realtime (If no path is provided when prompted, entire file system will be monitored)

    """

    print(manual)


def hash(file2hash):
    '''
    This function will take the file that needs to be hashed and return the relevant SHA256 hash value
    '''
    #Find the file first
    file_existance = os.path.exists(file2hash)

    if not file_existance:
        raise FileNotFoundError("File not found!")
    else:
        try:
            file_hash = sha256()
            with open(file2hash, 'rb') as HF:
                FileBlock = HF.read(BloCKSIZE)
                while len(FileBlock) > 0:
                    file_hash.update(FileBlock)
                    FileBlock = HF.read(BloCKSIZE)

            return file_hash.hexdigest()

        # if an object is not hashable return this error
        except AttributeError:
            print("Error! Function cannot operate on this object type")

def fileEntropy(filename):
    '''
    This function will take the file and calculate entropy
    '''
    # Find the file first
    file_existance = os.path.exists(filename)

    if not file_existance:
        raise FileNotFoundError("File not found!")
    else:
        try:
            with open(filename, "rb") as file:
                counters = {byte: 0 for byte in range(2 ** 8)}  # start all counters with zeros

                for byte in file.read():  # read in chunks for large files
                    counters[byte] += 1  # increase counter for specified byte

                filesize = file.tell()  # we can get file size by reading current position

                probabilities = [counter / filesize for counter in
                                 counters.values()]  # calculate probabilities for each byte

                entropy = -sum(probability * math.log2(probability) for probability in probabilities if
                               probability > 0)  # final sum

            return entropy

        # if entropy can't be calculated return error
        except AttributeError:
            print("Error! Function cannot operate on this object type")

def strings(filename, min=1):
    """
    This function will extract strings from the file
    """
    with open(filename, errors="ignore") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

def DomainSearch(filename):
    '''
    This function will take the file and return domains and IP addresses
    '''

    file_existance = os.path.exists(filename)
    target_file = str(filename)

    if not file_existance:
        raise FileNotFoundError("File not found!")
    else:
        # Open the target file in Read mode
        target_open = open(target_file, 'r')

        # Read the text from the file
        text = target_open.read()

        urls = re.findall('(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+', text)

        return urls #return domains and IPs found

def virusTotalFull(file2VT):
    '''
    This function will take the file and search it up on virustotal
    '''

    # Find the file first
    file_existance = os.path.exists(file2VT)
    target_file = str(os.path.abspath(file2VT))
    filehash = hash(file2VT)

    if not file_existance:
        raise FileNotFoundError("File not found!")
    else:

        try:
            client = vt.Client("Your VT Key Here") #virustotal key ahould be put here
            file = client.get_object("/files/" + filehash)

            print("Virus databases report:")
            pprint(file.last_analysis_stats) #print reports from virus total databases
            client.close()
        except Exception as e:
            print("File not found on VirusTotal")

def domainRep(file2Domain):

    """
    This function will search all found domains in a file on virustotal and return whether they have been flagged as malicious
    """

    file_existance = os.path.exists(file2Domain)
    filehash = hash(file2Domain)
    API_key = "Your VT Key Here" #virustotal key here
    VTurl = 'https://www.virustotal.com/vtapi/v2/url/report'



    if not file_existance:
        raise FileNotFoundError("File not found!")
    else:
        Domains = DomainSearch(file2Domain)

        parameters = {'apikey': API_key, 'resource': Domains}

        for i in Domains:
            parameters = {'apikey': API_key, 'resource': i}

            response = requests.get(url=VTurl, params=parameters)
            json_response = json.loads(response.text)

            if json_response['response_code'] <= 0:
                print(i + ": Domain not found, scan manually \n")
            elif json_response['response_code'] >= 1:

                if json_response['positives'] <= 0:
                    print(i + ": Not malicious \n")
                else:
                    with open('Virustotal Malicious result.txt', 'a') as malicious:
                        print(i + ": Flagged malicious and found by: " + str(json_response['positives']) + "  Solutions\n")

            time.sleep(15)

def dynamicAnalysisLog():
    """
    This function will monitor events occuring in the specified folder or system
    """

    vmd = VMDetect() #detect whether it is being run in VM


    if vmd.is_vm() == False:
        print("WARNING! You are not in a sandbox, if this is malware it can harm your computer.")
        execPrompt = input("Continue? [y/n]: ")
        if execPrompt.lower() == "yes" or execPrompt.lower() == "y":
            print("[+] Dynamic Analysis Running...")
        else:
            exit()


    class dynamicHandler(FileSystemEventHandler):



        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(message)s - %(process)d - %(processName)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        home_dir = str(Path.home())
        input_path = input("Path to watch: ")

        if len(input_path) == 0:
            path = home_dir
        else:
            path = os.path.abspath(input_path)

        file_existance = os.path.exists(path)

        if not file_existance:
            raise FileNotFoundError("File not found!")
        else:
            logging.info(f'start watching directory {path!r}')
            print("Time \t - \t       Operation \t - \t        Process ID \t - \t       ProcessName")

            event_handler = LoggingEventHandler()
            observer = Observer()
            observer.schedule(event_handler, path, recursive=True)
            observer.start()
            try:
                while True:
                    time.sleep(1)
            finally:
                observer.stop()
                observer.join()





#---------Main function-------------------------------------------#
if __name__ == '__main__':

    print("Welcome to FileSnoop:\nA program by: Munashe Zanza\n Enter ' --help as argument for manual '\n")

#-----------------------------------------------------------------#
#                       Command line arguments                    #
#-----------------------------------------------------------------#

    if (str(sys.argv[1]) == "hash") and (len(sys.argv) == 3): #calculate file hash
        file = sys.argv[2]
        fileHashValue = hash(file)

        print("The hash for %s is: %s" % (str(file), fileHashValue))

    elif (str(sys.argv[1]) == "entropy") and (len(sys.argv) == 3): #calculate entropy
        file = sys.argv[2]
        fileEntropyValue = fileEntropy(file)

        if ((fileEntropyValue > 4) and (fileEntropyValue <= 8)):
            print("Note: The closer to 8 entropy is, the more likely it is to be encrypted")
            print("The entropy for %s is: %s this file is likely to use encryption" % (str(file), fileEntropyValue))
        elif ((fileEntropyValue <= 4) and (fileEntropyValue >= 0)):
            print("Note: The closer to 8 entropy is, the more likely it is to be encrypted")
            print("The entropy for %s is: %s this file is less likely to use encryption" % (str(file), fileEntropyValue))
        else:
            print("Entropy cannot be establishes")

    elif (str(sys.argv[1]) == "strings") and (len(sys.argv) == 3): #pull strings from file
        file = sys.argv[2]
        user_strings_file = input("Enter output file name with extension (txt recommended): ")
        OutputFile = open(user_strings_file, "w")
        for s in strings(file,2):
            OutputFile.writelines("%s \n" % str(s))
        OutputFile.close()

    elif (str(sys.argv[1]) == "domains") and (len(sys.argv) == 3): #get domains and IP addresses
        file2Domain = str(sys.argv[2])
        present_Domains = DomainSearch(file2Domain)

        if len(present_Domains) >= 1:
            for domains in present_Domains:
                print(domains)
        else:
            print("No IP addresses or domains found")

    elif (str(sys.argv[1]) == "searchvt") and (len(sys.argv) == 3):
        fileVT = str(sys.argv[2])
        virusTotalFull(fileVT)

    elif (str(sys.argv[1]) == "--help") and (len(sys.argv) == 2):
        manual()

    elif (str(sys.argv[1]) == "repcheck") and (len(sys.argv) == 3):
        fileSU = str(sys.argv[2])
        domainRep(fileSU)

    elif (str(sys.argv[1]) == "dynamic") and (len(sys.argv) == 2):
        dynamicAnalysisLog()

    else:
        print("Improper use of arguments! \n Please refer to the readme or the manual")
