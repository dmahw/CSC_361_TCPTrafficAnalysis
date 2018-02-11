import pcapy, sys

VERBOSE = 1

def main():
    if VERBOSE:
        print("********** Hello, Starting Traffic Analysis")

    traceFileName = sys.argv[2]
    
    if VERBOSE:
        print("********** Input form user " + traceFileName)
    # Main code

