from setuptools import setup, find_packages

setup(
    name="secretsweep",
    version="1.0.0",
    description="Find leaked secrets before they leak. Fast, focused, developer-friendly.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="CipherShield",
    author_email="security@ciphershield.co.ke",
    url="https://github.com/sn01mukangai/secretsweep",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "secretsweep=secretsweep:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
