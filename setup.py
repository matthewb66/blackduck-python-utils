import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="blackduck-python-utils",
    version="0.1.4",
    description="Python wrapper for common patterns used with Black Duck.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/synopsys-sig-community/BlackDuckUtils",
    author="James Croall",
    author_email="jcroall@synopsys.com",
    license="Apache",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    packages=["BlackDuckUtils"],
    include_package_data=True,
    install_requires=["blackduck", "networkx", "requests", "semver", "aiohttp"]
)
