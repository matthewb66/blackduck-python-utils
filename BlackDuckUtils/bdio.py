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

import networkx as nx

import BlackDuckUtils as bu
import NpmUtils
import MavenUtils

from blackduck import Client

def read_json_object(filepath):
    with open(filepath) as jsonfile:
        data = json.load(jsonfile)
        return data

def zip_extract_files(zip_file, dir_name):
    print("Extracting content of {} into {}".format(zip_file, dir_name))
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(dir_name)

def bdio_read(bdio_in, inputdir):
    zip_extract_files(bdio_in, inputdir)
    filelist = os.listdir(inputdir)
    for filename in filelist:
        #print ("processing {}".format(filename))
        if (filename.startswith("bdio-entry")):
            filepath_in = os.path.join(inputdir, filename)
            data = read_json_object(filepath_in)
            return data

def get_bdio_dependency_graph(output_dir):
    # Parse BDIO file into network graph
    bd_rapid_output_bdio_glob = glob.glob(output_dir + "/runs/*/bdio/*.bdio")
    if (len(bd_rapid_output_bdio_glob) == 0):
        print("ERROR: Unable to find output scan files in: " + output_dir + "/runs/*/bdio/*.bdio")
        sys.exit(1)

    bd_rapid_output_bdio = bd_rapid_output_bdio_glob[0]

    bd_rapid_output_bdio_dir = glob.glob(output_dir + "/runs/*/bdio")[0]
    # TODO is there a case where there would be more than one BDIO file?
    bdio_data = bdio_read(bd_rapid_output_bdio, bd_rapid_output_bdio_dir)
    if (globals.debug):
        print(f"DEBUG: BDIO Dump: " + json.dumps(bdio_data, indent=4))

    # Construct dependency graph
    G = nx.DiGraph()

    if (globals.debug): print("DEBUG: Create dependency graph...")
    # Save project for later so we can find the direct dependencies
    projects = []
    for node in bdio_data['@graph']:
        parent = node['@id']
        if (globals.debug): print(f"DEBUG: Parent {parent}")

        nx_node = None

        if "https://blackducksoftware.github.io/bdio#hasDependency" in node:
            if (isinstance(node['https://blackducksoftware.github.io/bdio#hasDependency'], list)):
                for dependency in node['https://blackducksoftware.github.io/bdio#hasDependency']:
                    child = dependency['https://blackducksoftware.github.io/bdio#dependsOn']['@id']
                    if (globals.debug): print(f"DEBUG:   Dependency on {child}")
                    nx_node = G.add_edge(parent, child)
            else:
                child = node['https://blackducksoftware.github.io/bdio#hasDependency'][
                    'https://blackducksoftware.github.io/bdio#dependsOn']['@id']
                if (globals.debug): print(f"DEBUG:   (2) Dependency on {child}")
                nx_node = G.add_edge(parent, child)

            if node['@type'] == "https://blackducksoftware.github.io/bdio#Project":
                projects.append(parent)
                if (globals.debug): print(f"DEBUG:   Project name is {parent}")
                G.add_node(parent, project=1)
        else:
            nx_node = G.add_node(parent)

    return G, projects


def get_dependency_type(bdio_graph, bdio_projects, componentIdentifier):
    comp_ns, comp_name, comp_version = bu.parse_component_id(componentIdentifier)    # Matching in the BDIO requires an http: prefix

    dependency_type = "Direct"

    if (comp_ns == "npmjs"):
        comp_http_name = NpmUtils.convert_to_bdio(componentIdentifier)
    elif (comp_ns == "maven"):
        comp_http_name = MavenUtils.convert_to_bdio(componentIdentifier)
    else:
        print(f"ERROR: Domain '{comp_ns}' not supported yet")
        sys.exit(1)

    if (globals.debug): print(f"DEBUG: Looking for {comp_http_name}")
    ans = nx.ancestors(bdio_graph, comp_http_name)
    ans_list = list(ans)
    if (globals.debug): print(f"DEBUG:   Ancestors are: {ans_list}")
    pred = nx.DiGraph.predecessors(bdio_graph, comp_http_name)
    pred_list = list(pred)
    if (globals.debug): print(f"DEBUG:   Predecessors are: {ans_list}")
    if (len(ans_list) != 1):
        dependency_type = "Transitive"

    return dependency_type
