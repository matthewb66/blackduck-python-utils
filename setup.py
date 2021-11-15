import setuptools
import platform

platform_system = platform.system()

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="blackduck-python-utils",
    version="0.1.0",
    author="James Croall",
    author_email="jcroall@synopsys.com",
    description="Python wrapper for common patterns used with Black Duck.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/synopsys-sig-community/blackduck-python-utils",
    packages=setuptools.find_packages(),
    install_requires=['blackduck>=1.0.4',
                      'networkx'
                      ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.0'
)
