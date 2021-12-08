rm -rf dist build blackduck_python_utils.egg-info
python3 setup.py sdist bdist_wheel
pip3 uninstall -y blackduck-python-utils
pip3 install dist/blackduck_python_utils-0.1.4-py3-none-any.whl