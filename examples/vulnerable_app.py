# Intentionally insecure sample used to demonstrate the scanner. Do not reuse this code.
import hashlib
import pickle
import subprocess

import requests
import yaml

API_KEY = "example-not-a-real-key"


def run(command):
    return subprocess.run(command, shell=True)


def load_config(data):
    return yaml.load(data)


def load_session(blob):
    return pickle.loads(blob)


def calculate(expression):
    return eval(expression)


def fingerprint(text):
    return hashlib.md5(text.encode()).hexdigest()


def fetch(url):
    return requests.get(url, verify=False)
