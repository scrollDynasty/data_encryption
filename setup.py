from setuptools import setup, find_packages

try:
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = """
    File Encryption Tool

    Secure file encryption tool with a graphical interface.

    Possibilities:
    - Encrypting files using Fernet and AES algorithms
    - User-friendly graphical interface
    - Progress indicator for large files
    - Transaction logging system
    - Password validation
    """

setup(
    name="file_encryption",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'cryptography>=41.0.7',
        'cffi>=1.16.0',
    ],
    author="scrollDynasty",
    description="File encryption tool with a graphical interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/scrollDynasty/data_encryption",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Natural Language :: Russian",
    ],
    entry_points={
        'console_scripts': [
            'file_encryption=main:main',
        ],
    },
    python_requires='>=3.8',
    include_package_data=True,
    zip_safe=False,
    keywords=['encryption', 'security', 'cryptography', 'file', 'GUI'],
)