from setuptools import setup, find_packages

setup(
    name="file_encryption",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'cryptography==41.0.7',
        'cffi==1.16.0',
    ],
    author="scrollDynasty",
    description="Инструмент для шифрования файлов",
    python_requires='>=3.8',
)