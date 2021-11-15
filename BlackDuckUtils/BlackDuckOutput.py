import argparse
import glob
import hashlib
import json
import os
import random
import re
import shutil
import sys
import zipfile
import globals

from blackduck import Client

def get_blackduck_status(output_dir):
    bd_output_status_glob = glob.glob(output_dir + "/runs/*/status/status.json")
    if (len(bd_output_status_glob) == 0):
        print("ERROR: Unable to find output scan files in: " + output_dir + "/runs/*/status/status.json")
        sys.exit(1)

    bd_output_status = bd_output_status_glob[0]

    print("INFO: Parsing Black Duck Scan output from " + bd_output_status)
    with open(bd_output_status) as f:
        output_status_data = json.load(f)

    detected_package_files = []
    for detector in output_status_data['detectors']:
        # Reverse order so that we get the priority from detect
        for explanation in reversed(detector['explanations']):
            if (str.startswith(explanation, "Found file: ")):
                package_file = explanation[len("Found file: "):]
                if (os.path.isfile(package_file)):
                    detected_package_files.append(package_file)
                    if (globals.debug): print(f"DEBUG: Explanation: {explanation} File: {package_file}")

    # Find project name and version to use in looking up baseline data
    project_baseline_name = output_status_data['projectName']
    project_baseline_version = output_status_data['projectVersion']

    return project_baseline_name, project_baseline_version, detected_package_files

def get_rapid_scan_results(output_dir, bd):
    # Parse the Rapid Scan output, assuming there is only one run in the directory
    bd_rapid_output_file_glob = glob.glob(output_dir + "/runs/*/scan/*.json")
    if (len(bd_rapid_output_file_glob) == 0):
        print("ERROR: Unable to find output scan files in: " + output_dir + "/runs/*/scan/*.json")
        sys.exit(1)

    bd_rapid_output_file = bd_rapid_output_file_glob[0]
    print("INFO: Parsing Black Duck Rapid Scan output from " + bd_rapid_output_file)
    with open(bd_rapid_output_file) as f:
        output_data = json.load(f)

    developer_scan_url = output_data[0]['_meta']['href'] + "?limit=5000"
    if (globals.debug): print("DEBUG: Developer scan href: " + developer_scan_url)

    # Handle limited lifetime of developer runs gracefully
    try:
        rapid_scan_results = bd.get_json(developer_scan_url)
    except:
        print(
            f"ERROR: Unable to fetch developer scan '{developer_scan_url}' - note that these are limited lifetime and this process must run immediately following the rapid scan")
        raise

    # TODO: Handle error if can't read file
    if (globals.debug): print("DEBUG: Developer scan data: " + json.dumps(rapid_scan_results, indent=4) + "\n")

    return rapid_scan_results

