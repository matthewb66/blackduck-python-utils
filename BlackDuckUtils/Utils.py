# import argparse
# import glob
# import hashlib
import json
import os
# import random
# import re
# import shutil
import sys
# import zipfile
import globals
import requests
from pathlib import Path

from BlackDuckUtils import NpmUtils
from BlackDuckUtils import MavenUtils

# import networkx as nx
# from blackduck import Client

import subprocess


def remove_cwd_from_filename(path):
    cwd = os.getcwd()
    cwd = cwd + "/"
    new_filename = path.replace(cwd, "")
    return new_filename


def run_detect(jarfile, runargs):
    if jarfile == '' or not os.path.isfile(jarfile):
        jarfile = get_detect_jar()

    print('INFO: Running Black Duck Detect')

    args = ['java', '-jar', jarfile]
    args += runargs
    globals.printdebug("DEBUG: Command = ")
    globals.printdebug(args)

    retval = 1
    pvurl = ''
    projname = ''
    vername = ''
    try:
        proc = subprocess.Popen(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

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
    except OSError:
        print('ERROR: Unable to run Detect')
    except Exception as e:
        print(f'ERROR: {str(e)}')
    else:
        retval = proc.poll()

    if retval != 0:
        print('ERROR: Detect returned non-zero value')
        # sys.exit(2)

    if projname == '' or vername == '':
        print('ERROR: No project or version identified from Detect run')
        # sys.exit(3)

    return '/'.join(pvurl.split('/')[:8]), projname, vername, retval


def parse_component_id(component_id):
    comp_ns = component_id.split(':')[0]
    comp_name = ""
    comp_version = ""

    if comp_ns == "npmjs":
        comp_ns, comp_name, comp_version = NpmUtils.parse_component_id(component_id)
    elif comp_ns == "maven":
        comp_ns, comp_name, comp_version = MavenUtils.parse_component_id(component_id)
    else:
        print(f"ERROR: Package domain '{comp_ns}' is unsupported at this time")
        sys.exit(1)

    return comp_ns, comp_name, comp_version


def get_upgrade_guidance(bd, componentIdentifier):
    # Get component upgrade advice
    globals.printdebug(f"DEBUG: Search for component '{componentIdentifier}'")
    params = {
        'q': [componentIdentifier]
    }
    try:
        search_results = bd.get_items('/api/components', params=params)
    except Exception as e:
        return '', ''

    # There should be exactly one result!
    # TODO: Error checking?
    component_result = ''
    for result in search_results:
        component_result = result

    globals.printdebug("DEBUG: Component search result=" + json.dumps(component_result, indent=4) + "\n")

    # Get component upgrade data
    globals.printdebug(f"DBEUG: Looking up upgrade guidance for component '{component_result['componentName']}'")
    component_upgrade_data = bd.get_json(component_result['version'] + "/upgrade-guidance")
    globals.printdebug("DEBUG: Component upgrade data=" + json.dumps(component_upgrade_data, indent=4) + "\n")

    if "longTerm" in component_upgrade_data.keys():
        longTerm = component_upgrade_data['longTerm']['versionName']
    else:
        longTerm = None

    if "shortTerm" in component_upgrade_data.keys():
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
        globals.printdebug(f"DEBUG: Searching in '{package_file}' for '{comp_name}'")
        line = line_num_for_phrase_in_file(comp_name, package_file)
        globals.printdebug(f"DEBUG: line={line}'")
        if line > 0:
            return remove_cwd_from_filename(package_file), line

    return "Unknown", 1


def get_comps(bd, pv):
    comps = bd.get_json(pv + '/components?limit=5000')
    newcomps = []
    complist = []
    for comp in comps['items']:
        if 'componentVersionName' not in comp:
            continue
        cname = comp['componentName'] + '/' + comp['componentVersionName']
        if comp['ignored'] is False and cname not in complist:
            newcomps.append(comp)
            complist.append(cname)
    return newcomps


def get_projver(bd, projname, vername):
    params = {
        'q': "name:" + projname,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)
    if projects['totalCount'] == 0:
        return ''
    # projects = bd.get_resource('projects', params=params)
    for proj in projects['items']:
        versions = bd.get_resource('versions', parent=proj, params=params)
        for ver in versions:
            if ver['versionName'] == vername:
                return ver['_meta']['href']
    print("ERROR: Version '{}' does not exist in project '{}'".format(projname, vername))
    return ''


def get_detect_jar():
    if globals.detect_jar != '' and os.path.isfile(globals.detect_jar):
        return globals.detect_jar

    detect_jar_download_dir = os.getenv('DETECT_JAR_DOWNLOAD_DIR')
    dir = ''
    if detect_jar_download_dir is None or not os.path.isdir(detect_jar_download_dir):
        dir = os.path.join(str(Path.home()), "synopsys-detect")
        if not os.path.isdir(dir):
            os.mkdir(dir)
        dir = os.path.join(dir, 'download')
        if not os.path.isdir(dir):
            os.mkdir(dir)
        # outfile = os.path.join(dir, "detect7.jar")

    url = "https://sig-repo.synopsys.com/api/storage/bds-integrations-release/com/synopsys/integration/\
synopsys-detect?properties=DETECT_LATEST_7"
    r = requests.get(url, allow_redirects=True)
    if not r.ok:
        print('ERROR: detect_wrapper - Unable to load detect config {}'.format(r.reason))
        return ''

    rjson = r.json()
    if 'properties' in rjson and 'DETECT_LATEST_7' in rjson['properties']:
        djar = rjson['properties']['DETECT_LATEST_7'][0]
        if djar != '':
            fname = djar.split('/')[-1]
            jarpath = os.path.join(dir, fname)
            if os.path.isfile(jarpath):
                globals.detect_jar = jarpath
                return jarpath
            print('INFO: detect_wrapper - Downloading detect jar file')

            j = requests.get(djar, allow_redirects=True)
            # if globals.proxy_host != '' and globals.proxy_port != '':
            #     j.proxies = {'https': '{}:{}'.format(globals.proxy_host, globals.proxy_port),}
            if j.ok:
                open(jarpath, 'wb').write(j.content)
                if os.path.isfile(jarpath):
                    globals.detect_jar = jarpath
                    return jarpath
    print('ERROR: detect_wrapper - Unable to download detect jar file')
    return ''


def attempt_indirect_upgrade(comp_ns, comp_version, direct_name, direct_version, detect_jar):
    print('utils_upgrade_indirect()')
    if comp_ns == 'npmjs':
        NpmUtils.attempt_indirect_upgrade(comp_ns, comp_version, direct_name, direct_version, detect_jar)
    elif comp_ns == 'maven':
        MavenUtils.attempt_indirect_upgrade(comp_ns, comp_version, direct_name, direct_version, detect_jar)
    else:
        globals.printdebug(f'Cannot provide upgrade guidance for namepsace {comp_ns}')
    return
