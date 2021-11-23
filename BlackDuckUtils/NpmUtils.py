import os
import re
import shutil
# import sys

import globals
import tempfile

from BlackDuckUtils import Utils as bu


def parse_component_id(component_id):
    # Example: npmjs:trim-newlines/2.0.0
    comp_ns = component_id.split(':')[0]
    comp_name_and_version = component_id.split(':')[1]
    comp_name = comp_name_and_version.split('/')[0]
    comp_version = comp_name_and_version.split('/')[1]

    return comp_ns, comp_name, comp_version


def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id, 1)
    return bdio_name


def upgrade_npm_dependency(package_file, component_name, current_version, component_version):
    # Key will be actual name, value will be local filename
    files_to_patch = dict()

    dirname = tempfile.TemporaryDirectory()
    # dirname = "snps-patch-" + component_name + "-" + component_version

    # use temp_dir, and when done:
    # os.mkdir(dirname)
    shutil.copy2(package_file, dirname + "/" + package_file)
    origdir = os.getcwd()
    print(dirname.path)
    os.chdir(dirname.path)

    cmd = "npm install " + component_name + "@" + component_version
    print(f"INFO: Executing NPM to update component: {cmd}")
    err = os.system(cmd)
    if (err > 0):
        print(f"ERROR: Error {err} executing NPM command")
        os.chdir(origdir)
        dirname.cleanup()
        return None

    os.chdir(origdir)
    # Keep files so we can commit them!
    #shutil.rmtree(dirname)

    files_to_patch["package.json"] = dirname + "/package.json"
    files_to_patch["package-lock.json"] = dirname + "/package-lock.json"

    return files_to_patch


def attempt_indirect_upgrade(node_name, node_version, direct_name, direct_version, detect_jar):
    print(f"INFO: Attempting to upgrade indirect dependency {node_name}@{node_version} via {direct_name}@{direct_version}")

    get_detect_jar = True
    if detect_jar != '' and os.path.isfile(detect_jar):
        get_detect_jar = False
    elif globals.detect_jar != '' and os.path.isfile(detect_jar):
        get_detect_jar = False

    if get_detect_jar:
        globals.detect_jar = bu.get_detect_jar()

    dirname = tempfile.TemporaryDirectory()
    # dirname = "snps-upgrade-" + direct_name + "-" + direct_version
    origdir = os.getcwd()
    print(dirname.name)
    os.chdir(dirname.name)

    cmd = "npm install " + direct_name + "@" + direct_version
    print(f"INFO: Executing NPM to install component: {cmd}")
    err = os.system(cmd)
    if (err > 0):
        print(f"ERROR: Error {err} executing NPM command")
        os.chdir(origdir)
        dirname.cleanup()
        return False

    pvurl, projname, vername, retval = bu.run_detect(globals.detect_jar,
                                                     ["--blackduck.url=https://testing.blackduck.synopsys.com",
        "--blackduck.api.token=MDI0YTUxNzEtNWRlOS00ZWVjLWExMjgtYWJiODk4YjRjYjJlOjM4Mzk5Y2ZlLTJmOWItNDg1NC1hZTM4LWE4YjQwYjA4YzE2Yg==",
        "--detect.blackduck.scan.mode=rapid"])

    os.chdir(origdir)

    #sys.exit(1)

    if (retval > 0):
        return False

    return True
