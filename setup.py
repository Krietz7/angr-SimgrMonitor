from setuptools import setup

setup(
    name="angr-simgr-monitor",
    version="1.1.0",
    description="Non-intrusive real-time monitor for angr SimulationManager",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Krietz7",
    py_modules=["angr_simgr_monitor"],
    install_requires=[
        "angr>=9.0",
        "aspectlib>=1.5",
        "rich>=12.0",
        "psutil>=5.9"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Debuggers",
        "Framework :: angr",
    ],
    python_requires=">=3.10",
    url="https://github.com/Krietz7/angr-SimgrMonitor",
)