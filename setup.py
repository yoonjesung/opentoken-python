import setuptools

with open("README.md", "r") as f:
    readme = f.read()

packages = ['opentoken']

with open("requirements.txt", "r") as f:
    requires = f.read().split("\n")

test_requirements = [
    "pytest==5.3.2"
]

setuptools.setup(
    name="opentoken",
    version="2.2.0",
    description="OpenToken support for python.",
    long_description=readme,
    long_description_content_type='text/markdown',
    author="Jason Yoon",
    url="https://github.com/yoonjesung/opentoken-python",
    packages=packages,
    package_dir={"opentoken": "opentoken"},
    python_requires=">=3.5",
    install_requires=requires,
    license="MIT",
    tests_require=test_requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
)
