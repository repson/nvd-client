#!/usr/bin/python3

import argparse
import requests
import pprint

CVE_API = 'https://services.nvd.nist.gov/rest/json/cve/1.0/'
CVES_API = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
CPE_API = 'https://services.nvd.nist.gov/rest/json/cpes/1.0'


def launch_query(
        resultsPerPage=None,
        keyword=None,
        cvssV3Severity=None,
        cpeMatchString=None,
        cveid=None
    ):
    """Launch query."""
    res, API_URL = None, None
    parameters = {}

    if cveid:
        API_URL = f'{CVE_API}/{cveid}'
    else:
        API_URL = CVES_API
        parameters = {
            "resultsPerPage": resultsPerPage,
            "keyword": keyword,
            "cvssV3Severity": cvssV3Severity,
            "cpeMatchString": cpeMatchString 
        }

    try:
        res = requests.get(
            API_URL,
            params=parameters)
    except requests.exceptions.RequestException as e:
        print(e)

    if res:
        pprint.pprint(res.json())
    else:
        print('Result not found.')


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='API Client for NVD API.')
    parser.add_argument(
        '-i',
        '--cveid',
        help='CVE Id.',
        action='store',
        type=str,
        dest='cveid',
        required=False
    )
    parser.add_argument(
        '-k',
        '--keyword',
        help='Free text keyword search.',
        action='store',
        type=str,
        dest='keyword',
        required=False
    )
    parser.add_argument(
        '-s',
        '--severity',
        help='CVE having base severity score',
        action='store',
        type=str,
        dest='severity',
        required=False
    )
    parser.add_argument(
        '-c',
        '--cpe',
        help='CPE product applicability',
        action='store',
        type=str,
        dest='cpe',
        required=False
    )
    parser.add_argument(
        '-r',
        '--results',
        help='Results per page.',
        action='store',
        type=str,
        dest='results',
        required=False
    )

    args = parser.parse_args()

    print(args)

    launch_query(
        cveid=args.cveid,
        keyword=args.keyword,
        cvssV3Severity=args.severity,
        cpeMatchString=args.cpe,
        resultsPerPage=args.results,
    )

if __name__ == '__main__':
    main()
