from setuptools import setup, find_packages

setup(
    name="safeagent",
    version="1.0.0",
    description="Token safety checks for AI agents. Honeypot detection, scam patterns, LP lock verification across 6 EVM chains.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="CryptoGen Security",
    author_email="Cryptogen@zohomail.eu",
    url="https://github.com/CryptoGenesisSecurity/erc-token-safety-score",
    packages=find_packages(),
    python_requires=">=3.8",
    keywords=["token-safety", "honeypot", "scam-detection", "ai-agent", "defi", "erc20", "mcp", "web3", "crypto"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    license="MIT",
)
