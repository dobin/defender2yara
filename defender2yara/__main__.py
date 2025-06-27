import sys
from .main import main
import toml
from pathlib import Path

from defender2yara.util.logging import setup_logger, suppress_logging
from defender2yara.util.utils import is_validate_filesize


def get_version():
    pyproject_path = Path(__file__).parent.parent / 'pyproject.toml'
    pyproject_data = toml.load(pyproject_path)
    return pyproject_data['tool']['poetry']['version']


def run():
    import argparse
    parser = argparse.ArgumentParser(
        description="Convert Microsoft Defender Antivirus Signatures(VDM) to DB.",
        usage="defender2db [options]")

    parser.add_argument('-v', '--version', action='store_true', help="show defender2db version")

    parser.add_argument('-d','--download',action='store_true' ,required=False,default=False,help="download the latest signature database")
    parser.add_argument('-c', '--convert', action='store_true', required=False, default=False, help="convert downloaded signatures to DB format")
    parser.add_argument('-a', '--asr', action='store_true', required=False, default=False, help="Extract ASR rules from VDM")

    parser.add_argument('--topickle', action='store_true', default=False, help="write VDM cache files. to be used with --cacheonly")
    parser.add_argument('--frompickle', action='store_true', default=False, help="Load VDM cache files")

    parser.add_argument('--header_check',action='store_true',default=False,help="add file header check to generated YARA rules")
    parser.add_argument('--filesize_check',required=False,type=str,default="20MB",help="add filesize check to generated YARA rules")
    parser.add_argument('--no_filesize_check',action='store_true',required=False,default=False,help="remove filesize check from generated YARA rules")
    
    parser.add_argument('--proxy',help="use a proxy to download signatures (e.g. http://localhost:8000)")
    parser.add_argument('--debug', action='store_true', default=False, help="print detailed logs")
    parser.add_argument('--suppress', action='store_true', default=False, help="suppress all logs")

    
    args = parser.parse_args()
    
    if args.version:
        print(f"version: {get_version()}")
        sys.exit(0)

    if args.suppress and args.debug:
        sys.stderr.write("[!] --suppress option and --debug option can not use together.")
        parser.print_help()
        sys.exit(1)

    if not is_validate_filesize(args.filesize_check):
        sys.stderr.write("[!] Invalid filesize format. Use integer with postfix KB or MB.")
        parser.print_help()
        sys.exit(1)

    if args.no_filesize_check:
        # remove filesize check from generated yara rules.
        args.filesize_check = ""

    setup_logger(__package__, args.debug)

    if args.suppress:
        suppress_logging(__package__)

    main(args)


if __name__ == "__main__":
    run()