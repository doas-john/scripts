#!/usr/bin/env python3
"""Converts CSV file to raw JSON file"""
import csv
import json


def csv_to_json(csv_filepath, json_filepath):
    """Prompt for csv to open and json for writing"""
    with open(csv_filepath, "r") as csv_file:
        reader = csv.DictReader(csv_file)
        rows = [row for row in reader]
    with open(json_filepath, "w") as json_file:
        json.dump(rows, json_file)


csv_filepath = input("Please enter the CSV path of the file to be converted: ")
json_filepath = input("Please enter the path for the converted JSON file: ")
csv_to_json(csv_filepath, json_filepath)
