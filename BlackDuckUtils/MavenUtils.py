import os
import re
# import shutil
import globals
# import sys
import tempfile
import json

import xml.etree.ElementTree as ET

# from BlackDuckUtils import run_detect
from BlackDuckUtils import Utils as bu
from BlackDuckUtils import BlackDuckOutput as bo


class MyTreeBuilder(ET.TreeBuilder):
    def comment(self, data):
        self.start(ET.Comment, {})
        self.data(data)
        self.end(ET.Comment)


def parse_component_id(component_id):
    # Example: maven:org.springframework:spring-webmvc:4.2.3.RELEASE
    comp_ns = component_id.split(':')[0]
    comp_org = component_id.split(':')[1]
    comp_name = component_id.split(':')[2]
    comp_version = component_id.split(':')[3]

    return comp_ns, comp_name, comp_version


def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id)
    return bdio_name


def upgrade_maven_dependency(package_file, component_name, current_version, component_version):
    # Key will be actual name, value will be local filename
    files_to_patch = dict()

    # dirname = "snps-patch-" + component_name + "-" + component_version
    dirname = tempfile.TemporaryDirectory()

    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))

    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")

    tree = ET.parse(package_file, parser=ET.XMLParser(target=MyTreeBuilder()))
    root = tree.getroot()

    nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

    globals.printdebug(f"DEBUG: Search for maven dependency {component_name}@{component_version}")

    for dep in root.findall('.//m:dependencies/m:dependency', nsmap):
        groupId = dep.find('m:groupId', nsmap).text
        artifactId = dep.find('m:artifactId', nsmap).text
        version = dep.find('m:version', nsmap).text

        # TODO Also include organization name?
        if artifactId == component_name:
            globals.printdebug(f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} Version={version}")
            dep.find('m:version', nsmap).text = component_version

    xmlstr = ET.tostring(root, encoding='utf8', method='xml')
    with open(dirname.name + "/" + package_file, "wb") as fp:
        fp.write(xmlstr)

    print(f"INFO: Updated Maven component in: {package_file}")

    files_to_patch[package_file] = dirname.name + "/" + package_file

    return files_to_patch


def create_pom(deps):
    if os.path.isfile('pom.xml'):
        print('ERROR: Maven pom.xml file already exists')
        return False

    dep_text = ''
    for dep in deps:
        groupid = dep[0]
        artifactid = dep[1]
        version = dep[2]

        dep_text += f'''    <dependency>
        <groupId>{groupid}</groupId>
        <artifactId>{artifactid}</artifactId>
        <version>{version}</version>
    </dependency>
'''

    pom_contents = f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>sec</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>

    <dependencies>
    {dep_text}
    </dependencies>
</project>'''
    try:
        with open('pom.xml', "w") as fp:
            fp.write(pom_contents)
    except Exception as e:
        print(e)
        return False
    return True


def attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, detect_connection_opts, bd):
    # create a pom.xml with all possible future direct_deps versions
    # run rapid scan to check
    output = 'blackduck-output'
    # print(f'Vuln Deps = {json.dumps(deps_list, indent=4)}')

    get_detect_jar = True
    if detect_jar != '' and os.path.isfile(detect_jar):
        get_detect_jar = False
    elif globals.detect_jar != '' and os.path.isfile(detect_jar):
        get_detect_jar = False

    if get_detect_jar:
        globals.detect_jar = bu.get_detect_jar()

    # dirname = "snps-upgrade-" + direct_name + "-" + direct_version
    dirname = tempfile.TemporaryDirectory()
    # os.mkdir(dirname)
    origdir = os.getcwd()
    os.chdir(dirname.name)

    # Need to test the short & long term upgrade guidance separately
    detect_connection_opts.append("--detect.blackduck.scan.mode=RAPID")
    detect_connection_opts.append("--detect.detector.buildless=true")
    detect_connection_opts.append("--detect.maven.buildless.legacy.mode=false")
    detect_connection_opts.append(f"--detect.output.path={output}")
    detect_connection_opts.append("--detect.cleanup=false")

    print('POSSIBLE UPGRADES:')
    print(json.dumps(upgrade_dict, indent=4))

    good_upgrade_dict = upgrade_dict.copy()
    for ind in [0, 1, 2]:
        # print(f'\nDETECT RUN TO TEST UPGRADES - {ind}')
        depver_list = []
        origdeps_list = []
        for dep in deps_list:
            if dep not in upgrade_dict.keys() or upgrade_dict[dep] is None or len(upgrade_dict[dep]) <= ind:
                continue
            version = upgrade_dict[dep][ind]
            if version == '':
                continue
            arr = dep.split(':')
            # forge = arr[0]
            groupid = arr[1]
            artifactid = arr[2]
            depver_list.append([groupid, artifactid, version])
            origdeps_list.append(dep)

        if len(depver_list) == 0:
            # print('No upgrades to test')
            continue

        if not create_pom(depver_list):
            os.chdir(origdir)
            return None

        # print('DEPS TO TEST:')
        # print(depver_list)
        pvurl, projname, vername, retval = bu.run_detect(output, detect_connection_opts, False)

        if retval == 3:
            # Policy violation returned
            rapid_scan_data, dep_dict, direct_deps_vuln, pm = bu.process_scan(output, bd, [], False, False)

            # print(f'MYDEBUG: Vuln direct deps = {direct_deps_vuln}')
            for vulndep in direct_deps_vuln:
                arr = vulndep.split(':')
                compname = arr[2]
                #
                # find comp in depver_list
                for upgradedep, origdep in zip(depver_list, origdeps_list):
                    # print(f'MYDEBUG: {compname} is VULNERABLE - {upgradedep}, {origdep}')
                    if artifactid == compname:
                        good_upgrade_dict[origdep].pop(ind)
                        break
        elif retval != 0:
            for upgradedep, origdep in zip(depver_list, origdeps_list):
                # print(f'MYDEBUG: VULNERABLE - {upgradedep}, {origdep}')
                good_upgrade_dict[origdep].pop(ind)
        else:
            # Detect returned 0
            # All tested upgrades not vulnerable
            pass

        os.remove('pom.xml')

    print('GOOD UPGRADES:')
    print(json.dumps(good_upgrade_dict, indent=4))

    os.chdir(origdir)
    dirname.cleanup()
    return good_upgrade_dict


def normalise_dep(dep):
    #
    # Replace / with :
    if dep.find('http:') == 0:
        dep = dep.replace('http:', '')
    return dep.replace('/', ':')
