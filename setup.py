"""Setup configuration for llm-triage."""

from setuptools import find_packages, setup

setup(
    name="llm-triage",
    version="0.1.0",
    description="LLM-assisted security incident triage for financial institutions",
    author="Vincent Plessy",
    author_email="vincent.plessy12@gmail.com",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.11",
    install_requires=[
        "anthropic>=0.28.0",
        "openai>=1.30.0",
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "jinja2>=3.1.0",
    ],
    extras_require={
        "dev": [
            "responses>=0.25.0",
            "pytest>=8.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "llm-triage=main:main",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
    ],
)
