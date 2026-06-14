"""
Setup configuration for llm-triage.
"""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    install_requires = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#") and not line.startswith("pytest") and not line.startswith("responses")
    ]

setup(
    name="llm-triage",
    version="0.1.0",
    author="Vincent Plessy",
    author_email="vincent.plessy12@gmail.com",
    description="LLM-assisted security incident triage for financial institutions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vplessy/llm-triage",
    packages=find_packages(exclude=["tests*"]),
    package_data={
        "": ["prompts/*.txt"],
    },
    include_package_data=True,
    python_requires=">=3.11",
    install_requires=install_requires,
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "responses>=0.25.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "llm-triage=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="security incident triage llm anthropic openai soc cybersecurity fintech",
)
