# packet-capture-compare
Python Script to compare two packet captures.

## Summary
This script will take two packet captures formatted as JSON, compare them, and write the results to an XLSX file. Please note only TCP comparison is supported at this tume.

The key aim is to determine if any packets have been dropped between source and destination, additional functionality will be added soon.

## Requirements

Please ensure you have Python 3.8 or later installed.
You will also need to install the XLSX Writer library as follows:

pyrhon3 -m pip install XlsxWriter

## Usage

To run the script, first ensure the variables at the start match the names of your json files. Then:

python3 pc-compare.py.

this will generate the xlsx in the same folder the script is run.

