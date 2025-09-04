from setuptools import setup, find_packages

setup(
    name="gscapy_web",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        # The requirements will be installed from requirements.txt in the Dockerfile,
        # but this is good practice for local development.
        "fastapi",
        "uvicorn[standard]",
        "streamlit",
        "requests",
        "pandas",
        "scapy",
        "psutil",
        "numpy",
        "lxml",
        "pyqtgraph",
        "gputil",
        "reportlab",
        "python-docx",
        "qt-material",
        "dnspython",
    ],
    entry_points={
        'console_scripts': [
            'gscapy_api=gscapy_web.api.main:app',
            'gscapy_frontend=streamlit.cli:main',
        ],
    },
)
