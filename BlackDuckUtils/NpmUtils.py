import os
import re
import shutil

import globals
import tempfile
import json

from BlackDuckUtils import Utils as bu
from BlackDuckUtils import BlackDuckOutput as bo


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
    shutil.copy2(package_file, dirname.name + "/" + package_file)
    origdir = os.getcwd()
    # print(dirname.name)
    os.chdir(dirname.name)

    cmd = "npm install " + component_name + "@" + component_version
    print(f"INFO: Executing NPM to update component: {cmd}")
    err = os.system(cmd)
    if err > 0:
        print(f"ERROR: Error {err} executing NPM command")
        os.chdir(origdir)
        dirname.cleanup()
        return None

    os.chdir(origdir)
    # Keep files so we can commit them!
    # shutil.rmtree(dirname)

    files_to_patch["package.json"] = dirname.name + "/package.json"
    files_to_patch["package-lock.json"] = dirname.name + "/package-lock.json"

    return files_to_patch


def attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, detect_connection_opts, bd):
    # Need to test the short & long term upgrade guidance separately
    detect_connection_opts.append("--detect.blackduck.scan.mode=RAPID")
    detect_connection_opts.append("--detect.output.path=upgrade-tests")
    detect_connection_opts.append("--detect.cleanup=false")

    print('POSSIBLE UPGRADES:')
    print(json.dumps(upgrade_dict, indent=4))

    # vulnerable_upgrade_list = []
    test_dirdeps = deps_list
    good_upgrades = {}
    for ind in range(0, 3):
        print(f'\nDETECT RUN TO TEST {len(test_dirdeps)} UPGRADES')
        test_upgrade_list = []
        test_origdeps_list = []
        #
        # Look for upgrades to test
        installed_packages = []
        package_deps_installed = []
        for dep in test_dirdeps:
            arr = dep.split(':')
            forge = arr[0]
            arr2 = arr[1].split('/')
            comp = arr2[0]
            ver = arr2[1]
            dstring = f'{forge}:{comp}/{ver}'
            if dstring not in upgrade_dict.keys() or len(upgrade_dict[dstring]) <= ind:
                # print(f'No Upgrade {ind} available for {dstring}')
                continue

            upgrade_version = upgrade_dict[dstring][ind]
            if upgrade_version == '':
                continue
            # print(f'DEBUG: Upgrade dep = {comp}@{version}')

            cmd = f"npm install {comp}@{upgrade_version} --package-lock-only >/dev/null 2>&1"
            print(cmd)
            ret = os.system(cmd)

            if ret == 0:
                installed_packages.append([comp, upgrade_version])
                package_deps_installed.append(dep)

        if len(installed_packages) == 0:
            # print('No upgrades to test')
            continue

        pvurl, projname, vername, retval = bu.run_detect('upgrade-tests', detect_connection_opts, False)

        if retval == 3:
            # Policy violation returned
            rapid_scan_data, dep_dict, direct_deps_vuln, pm = bu.process_scan('upgrade-tests', bd, [], False, False)

            # print(f'MYDEBUG: Vuln direct deps = {direct_deps_vuln}')
            last_vulnerable_dirdeps = []
            for vulndep in direct_deps_vuln:
                arr = vulndep.split(':')
                compname = arr[2]
                #
                # find comp in depver_list
                for upgradepkg, origdep in zip(installed_packages, package_deps_installed):
                    # print(f'MYDEBUG: {compname} is VULNERABLE - {upgradepkg}, {origdep}')
                    if upgradepkg[0] == compname:
                        last_vulnerable_dirdeps.append(origdep)
                        break
        elif retval != 0:
            last_vulnerable_dirdeps = []
            for upgradepkg, origdep in zip(installed_packages, package_deps_installed):
                # print(f'MYDEBUG: {compname} is VULNERABLE - {upgradepkg}, {origdep}')
                last_vulnerable_dirdeps.append(origdep)
        else:
            # Detect returned 0
            # All tested upgrades not vulnerable
            last_vulnerable_dirdeps = []

        os.remove('package.json')
        os.remove('package-lock.json')
        # rapid_scan_data = bo.get_rapid_scan_results('upgrade-tests', bd)

        # Process good upgrades
        for dep, upgrade in zip(test_origdeps_list, test_upgrade_list):
            if dep not in last_vulnerable_dirdeps:
                good_upgrades[dep] = upgrade[2]

        test_dirdeps = last_vulnerable_dirdeps

    print('GOOD UPGRADES:')
    print(json.dumps(good_upgrades, indent=4))
    return good_upgrades


def normalise_dep(dep):
    #
    # Replace / with :
    # return dep.replace('/', ':').replace('http:', '')
    dep = dep.replace('http:', '').replace('npmjs/', 'npmjs:')
    # Check format matches 'npmjs:component/version'
    colon = dep.split(':')
    if len(colon) == 2:
        slash = colon[1].split('/')
        if len(slash) == 2:
            newver = bu.normalise_version(slash[1])
            if slash[1] == newver:
                return dep
    return ''