import os
from setuptools import setup, find_packages

this_dir = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_dir, "README.md"), "r") as f:
    long_description = f.read()

# More information on properties: https://packaging.python.org/distributing
setup(
    name="httpx_auth",
    version=open("httpx_auth/version.py").readlines()[-1].split()[-1].strip("\"'"),
    author="Colin Bounouar",
    author_email="colin.bounouar.dev@gmail.com",
    maintainer="Colin Bounouar",
    maintainer_email="colin.bounouar.dev@gmail.com",
    url="https://colin-b.github.io/httpx_auth/",
    description="Authentication for HTTPX",
    long_description=long_description,
    long_description_content_type="text/markdown",
    download_url="https://pypi.org/project/httpx-auth/",
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Build Tools",
    ],
    keywords=["authentication", "oauth2", "aws", "okta", "aad"],
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        # Used for Base Authentication and to communicate with OAuth2 servers
        "httpx==0.17.*"
    ],
    extras_require={
        "testing": [
            # Used to generate test tokens
            "pyjwt==1.*",
            # Used to mock httpx
            "pytest_httpx==0.11.*",
            # Used to check coverage
            "pytest-cov==2.*",
        ]
    },
    python_requires=">=3.6",
    project_urls={
        "GitHub": "https://github.com/Colin-b/httpx_auth",
        "Changelog": "https://github.com/Colin-b/httpx_auth/blob/master/CHANGELOG.md",
        "Issues": "https://github.com/Colin-b/httpx_auth/issues",
    },
    platforms=["Windows", "Linux"],
)
