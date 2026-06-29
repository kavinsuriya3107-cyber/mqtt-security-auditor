from setuptools import setup, find_packages

setup(
    name="mqtt-security-auditor",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "paho-mqtt>=1.6.1",
        "click>=8.1.3",
        "rich>=13.4.2",
        "jinja2>=3.1.2",
        "pyyaml>=6.0",
        "cryptography>=41.0.1",
    ],
    entry_points={
        "console_scripts": [
            "mqtt-auditor=mqtt_auditor.cli:main",
        ],
    },
)
