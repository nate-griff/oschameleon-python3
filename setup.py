from setuptools import find_packages, setup

import oschameleon

setup(
    packages=find_packages(),
    name=oschameleon.__title__,
    version=oschameleon.__version__,
    author="MushMush",
    author_email="glaslos@gmail.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    package_data={
        "": ["*.txt", "*.md"],
    },
    include_package_data=True,
    long_description=open("README.md", encoding="utf-8").read(),
    url="https://github.com/mushorg/oschameleon",
    description="OS Fingerprint Obfuscation for modern Linux Kernels",
    python_requires=">=3.8",
    tests_require=["pytest"],
    zip_safe=False,
    install_requires=open("requirements.txt").read().splitlines(),
)
