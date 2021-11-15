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

import NpmUtils
import MavenUtils

import networkx as nx

from blackduck import Client

import subprocess

def remove_cwd_from_filename(path):
    cwd = os. getcwd()
    cwd = cwd + "/"
    new_filename = path.replace(cwd, "")
    return new_filename


def run_detect(jarfile, runargs):
    print('INFO: Running Black Duck Detect')

    args = ['java', '-jar', jarfile]
    args += runargs
    print("DEBUG: Command = ")
    print(args)

    proc = subprocess.Popen(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pvurl = ''
    projname = ''
    vername = ''
    while True:
        outp = proc.stdout.readline()
        if proc.poll() is not None and outp == '':
            break
        if outp:
            print(outp.strip())
            bomstr = ' --- Black Duck Project BOM:'
            projstr = ' --- Project name:'
            verstr = ' --- Project version:'
            # noinspection PyTypeChecker
            if outp.find(bomstr) > 0:
                pvurl = outp[outp.find(bomstr) + len(bomstr) + 1:].rstrip()
            if outp.find(projstr) > 0:
                projname = outp[outp.find(projstr) + len(projstr) + 1:].rstrip()
            if outp.find(verstr) > 0:
                vername = outp[outp.find(verstr) + len(verstr) + 1:].rstrip()
    retval = proc.poll()

    if retval != 0:
        print('ERROR: detect_wrapper - Detect returned non-zero value')
        # sys.exit(2)

    if projname == '' or vername == '':
        print('ERROR: detect_wrapper - No project or version identified from Detect run')
        # sys.exit(3)

    return '/'.join(pvurl.split('/')[:8]), projname, vername, retval


def parse_component_id(component_id):
    comp_ns = component_id.split(':')[0]
    comp_name = ""
    comp_version = ""

    if (comp_ns == "npmjs"):
        comp_ns, comp_name, comp_version = NpmUtils.parse_component_id(component_id)
    elif (comp_ns == "maven"):
        comp_ns, comp_name, comp_version = MavenUtils.parse_component_id(component_id)
    else:
        print(f"ERROR: Package domain '{comp_ns}' is unsupported at this time")
        sys.exit(1)

    return comp_ns, comp_name, comp_version

def get_upgrade_guidance(bd, componentIdentifier):
    # Get component upgrade advice
    if (globals.debug): print(f"DEBUG: Search for component '{componentIdentifier}'")
    params = {
            'q': [ componentIdentifier ]
            }
    search_results = bd.get_items('/api/components', params=params)
    # There should be exactly one result!
    # TODO: Error checking?
    for result in search_results:
        component_result = result
    if (globals.debug): print("DEBUG: Component search result=" + json.dumps(component_result, indent=4) + "\n")

    # Get component upgrade data
    if (globals.debug): print(f"DBEUG: Looking up upgrade guidance for component '{component_result['componentName']}'")
    component_upgrade_data = bd.get_json(component_result['version'] + "/upgrade-guidance")
    if (globals.debug): print("DEBUG: Component upgrade data=" + json.dumps(component_upgrade_data, indent=4) + "\n")

    if ("longTerm" in component_upgrade_data.keys()):
        longTerm = component_upgrade_data['longTerm']['versionName']
    else:
        longTerm = None

    if ("shortTerm" in component_upgrade_data.keys()):
        shortTerm = component_upgrade_data['shortTerm']['versionName']
    else:
        shortTerm = None

    return shortTerm, longTerm


def line_num_for_phrase_in_file(phrase, filename):
    try:
        with open(filename,'r') as f:
            for (i, line) in enumerate(f):
                if phrase.lower() in line.lower():
                    return i
    except:
        return -1
    return -1


def detect_package_file(detected_package_files, componentIdentifier, componentName):
    comp_ns, comp_name, version = parse_component_id(componentIdentifier)

    for package_file in detected_package_files:
        if (globals.debug): print(f"DEBUG: Searching in '{package_file}' for '{comp_name}'")
        line = line_num_for_phrase_in_file(comp_name, package_file)
        if (globals.debug): print(f"DEBUG: line={line}'")
        if (line > 0):
            return remove_cwd_from_filename(package_file), line

    return "Unknown", 1
