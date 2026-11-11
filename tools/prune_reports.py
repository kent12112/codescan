"""Preview removal of generated reports older than a retention window; --apply deletes."""
import argparse
from pathlib import Path
import re
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=Path(__file__).resolve().parents[1]/'reports')
    parser.add_argument('--days',type=int,default=30)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    if args.days<1:
        parser.error('retention must be at least one day')
    threshold=time.time()-args.days*86400
    for path in sorted(args.directory.glob('codescan-*')):
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'codescan-[a-f0-9]{12}\.(json|failed\.log)',path.name):
            continue
        if path.stat().st_mtime<threshold:
            print(('Removing ' if args.apply else 'Would remove ')+str(path))
            if args.apply:
                path.unlink()


if __name__=='__main__':
    main()
