"""Official-source-only dataset staging; no auto-generated findings or labels.

Usage on Kali:
  python tools/research_dataset.py verify-matrix
  python tools/research_dataset.py fetch-asvs
  python tools/research_dataset.py import-cwe ~/Downloads/1000.csv.zip
  python tools/research_dataset.py verify-receipts
"""
import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / 'research'
DATA = RESEARCH / 'datasets' / 'external'
MATRIX = RESEARCH / 'chk01_chk12_traceability.csv'
MANIFEST = RESEARCH / 'source_manifest.json'
MAX_BYTES = 25 * 1024 * 1024
ASVS_NAME = 'OWASP_Application_Security_Verification_Standard_5.0.0_en.csv'
ASVS_URL = 'https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/docs_en/' + ASVS_NAME


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def matrix_rows():
    with MATRIX.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def verify_matrix():
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    sources = {r['key']:r for r in manifest['sources']}
    assert all(k in sources for k in ('WSTG', 'ASVS', 'CWE', 'TOP10'))
    assert sources['WSTG']['version'] == '4.2'
    assert sources['ASVS']['version'] == '5.0.0'
    assert sources['CWE']['version'] == '5.0'
    rows = matrix_rows()
    expected = {f'CHK{i:02d}' for i in range(1,13)}
    assert {r['chk_id'] for r in rows} == expected and len(rows) == 12
    for row in rows:
        assert (ROOT / row['implementation_path']).is_file(), row['chk_id']
        assert row['reference_url'].startswith('https://wstg.owasp.org/v4.2/')
        assert row['ground_truth_status'] == 'not_yet_benchmarked'
        for ref in filter(None, row['wstg_v42_scenario'].split(';')):
            assert ref.startswith('WSTG-v42-'), (row['chk_id'], ref)
        assert not row['asvs_exact_requirement'] and not row['cwe_exact_id']
    print('PASS: 12 CHK records; verified source versions and local implementation paths; no fabricated ASVS/CWE IDs.')


def receipt_file(path, label, url=None):
    receipt = {'source': label, 'filename': path.name, 'bytes': path.stat().st_size,
               'sha256': sha256(path), 'retrieved_from': url, 'validation': 'downloaded_bytes_only; semantic_review_pending'}
    out = path.with_name(path.name + '.receipt.json')
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
    print(f'Imported {path.name} ({receipt["bytes"]} bytes; SHA-256 {receipt["sha256"]})')
    print('Receipt:', out)


def fetch_asvs():
    DATA.mkdir(parents=True, exist_ok=True)
    target = DATA / ASVS_NAME
    tmp = DATA / (ASVS_NAME + '.partial')
    if target.exists():
        raise SystemExit('ASVS target exists. Remove manually before new download (no silent overwrite).')
    try:
        req = Request(ASVS_URL, headers={'User-Agent':'OWASP-Web-Auditor-research/0.2'})
        with urlopen(req, timeout=45) as resp, tmp.open('wb') as f:
            if urlsplit(resp.url).hostname not in {'github.com','raw.githubusercontent.com','objects.githubusercontent.com','release-assets.githubusercontent.com'}:
                raise ValueError('Unexpected download host')
            size=0
            while chunk := resp.read(65536):
                size+=len(chunk)
                if size>MAX_BYTES: raise ValueError('Dataset exceeded size ceiling')
                f.write(chunk)
        with tmp.open(encoding='utf-8-sig', newline='') as f:
            reader = csv.reader(f)
            first=next(reader, [])
            if len(first)<2 or '404' in str(first): raise ValueError('Not a recognized CSV document')
        tmp.rename(target)
        receipt_file(target,'OWASP ASVS 5.0.0 official CSV',ASVS_URL)
    finally:
        tmp.unlink(missing_ok=True)


def import_cwe(source):
    source=Path(source).expanduser().resolve()
    if not source.is_file() or source.suffix.lower() not in ('.zip','.csv','.xml'):
        raise ValueError('Choose the official CWE 5.0 .zip/.csv/.xml export downloaded manually')
    if source.stat().st_size > MAX_BYTES: raise ValueError('Dataset exceeds size ceiling')
    DATA.mkdir(parents=True,exist_ok=True)
    target=DATA / ('cwe-5.0-'+source.name)
    if target.exists(): raise FileExistsError('No silent overwrite: '+str(target))
    shutil.copyfile(source,target)
    receipt_file(target,'User-provided CWE 5.0 export; origin/version must be manually verified','https://cwe.mitre.org/data/downloads')


def verify_receipts():
    if not DATA.is_dir():
        print('No downloaded datasets or receipts available; not claiming import.')
        return
    count=0
    for r in DATA.glob('*.receipt.json'):
        receipt=json.loads(r.read_text())
        target=DATA / receipt['filename']
        assert target.is_file() and sha256(target)==receipt['sha256'], str(r)
        assert target.stat().st_size==receipt['bytes']
        count+=1
    print(f'PASS: {count} receipt(s) match local bytes.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='cmd',required=True)
    for name in ('verify-matrix','fetch-asvs','verify-receipts'): sub.add_parser(name)
    sub.add_parser('import-cwe').add_argument('file')
    args=p.parse_args()
    if args.cmd=='verify-matrix': verify_matrix()
    elif args.cmd=='fetch-asvs': fetch_asvs()
    elif args.cmd=='import-cwe': import_cwe(args.file)
    elif args.cmd=='verify-receipts': verify_receipts()

if __name__=='__main__': main()
