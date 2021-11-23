import os
import re
# import shutil
import globals
# import sys
import tempfile

import xml.etree.ElementTree as ET

# from BlackDuckUtils import run_detect
from BlackDuckUtils import Utils as bu


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
        if (artifactId == component_name):
            globals.printdebug(f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} Version={version}")
            dep.find('m:version', nsmap).text = component_version

    xmlstr = ET.tostring(root, encoding='utf8', method='xml')
    with open(dirname + "/" + package_file, "wb") as fp:
        fp.write(xmlstr)

    print(f"INFO: Updated Maven component in: {package_file}")

    files_to_patch[package_file] = dirname + "/" + package_file

    return files_to_patch


def create_pom(comp, version):
    if os.path.isfile('pom.xml'):
        print('ERROR: Maven pom.xml file already exists')
        return False

    arr = comp.split('.')
    if len(arr) > 2:
        groupid = '.'.join(arr[0:-1])
        artifactid = arr[-1]
    else:
        groupid = comp
        artifactid = comp

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
    <dependency>
        <groupId>{groupid}</groupId>
        <artifactId>{artifactid}</artifactId>
        <version>{version}</version>
    </dependency>
    </dependencies>
</project>'''
    try:
        with open('pom.xml', "w") as fp:
            fp.write(pom_contents)
    except Exception as e:
        print(e)
        return False
    return True


def attempt_indirect_upgrade(node_name, node_version, direct_name, direct_version, detect_jar):
    print(f"INFO: Attempting to upgrade indirect dependency {node_name}@{node_version} via {direct_name}@{direct_version}")

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

    if not create_pom(direct_name, direct_version):
        os.chdir(origdir)
        return False

    pvurl, projname, vername, retval = bu.run_detect(detect_jar, [ "--blackduck.url=https://testing.blackduck.synopsys.com",
        "--blackduck.api.token=MDI0YTUxNzEtNWRlOS00ZWVjLWExMjgtYWJiODk4YjRjYjJlOjM4Mzk5Y2ZlLTJmOWItNDg1NC1hZTM4LWE4YjQwYjA4YzE2Yg==",
        "--detect.blackduck.scan.mode=RAPID"])

    if (retval > 0):
        os.chdir(origdir)
        return False

    os.chdir(origdir)
    dirname.cleanup()
    return True
