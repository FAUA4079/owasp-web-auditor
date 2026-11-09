"""Validate manually reviewed ID candidates against the user's actual ASVS 5.0 and CWE 5.0 downloads.

This confirms membership, *not* semantic applicability or detector accuracy.
"""
import argparse,csv,json,zipfile,xml.etree.ElementTree as ET,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAP=ROOT/'research/phase2_exact_mapping.csv'
DATA=ROOT/'research/datasets/external'
ASVS='OWASP_Application_Security_Verification_Standard_5.0.0_en.csv'
CWE='cwe-5.0-cwec_latest.xml.zip'

def load_asvs(path):
    with open(path,encoding='utf-8-sig',newline='') as stream:
        rows=list(csv.DictReader(stream))
    if not rows or not {'req_id','req_description'}<=set(rows[0]):
        raise ValueError('Unrecognized ASVS CSV columns')
    result={r['req_id']:r['req_description'] for r in rows}
    if len(result)!=len(rows):raise ValueError('Duplicate ASVS requirement IDs')
    return result

def load_cwe(path):
    with zipfile.ZipFile(path) as z:
        names=[n for n in z.namelist() if n.endswith('.xml') and not n.startswith('__MACOSX')]
        if len(names)!=1: raise ValueError('Expected one CWE XML entry')
        with z.open(names[0]) as f:
            tree=ET.parse(f)
    root=tree.getroot()
    if root.attrib.get('Version')!='5.0':raise ValueError('Expected CWE 5.0 catalog')
    out={}
    for elem in root.iter():
        if elem.tag.rsplit('}',1)[-1]=='Weakness' and elem.get('ID'):
            out['CWE-'+elem.get('ID')]=elem.get('Name','')
    if not out:raise ValueError('No CWE Weakness entries')
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--asvs',type=Path,default=DATA/ASVS);p.add_argument('--cwe',type=Path,default=DATA/CWE)
    args=p.parse_args()
    asvs=load_asvs(args.asvs);cwe=load_cwe(args.cwe)
    with MAP.open(newline='',encoding='utf-8') as f:rows=list(csv.DictReader(f))
    issues=[];details=[]
    for row in rows:
        entry={'chk_id':row['chk_id'],'ASVS':[],'CWE':[]}
        for field,known,key in [('asvs_v5_req_ids',asvs,'ASVS'),('cwe_v5_ids',cwe,'CWE')]:
            for ident in filter(None,row[field].split(';')):
                if ident not in known:issues.append(row['chk_id']+' missing '+ident)
                else:entry[key].append({'id':ident,'official_name_or_description':known[ident]})
        details.append(entry)
    receipt={'validation':'exact_identifier_membership_only','status':'PASS' if not issues else 'FAIL',
             'datasets':{'asvs_sha256':hashlib.sha256(args.asvs.read_bytes()).hexdigest(),'cwe_sha256':hashlib.sha256(args.cwe.read_bytes()).hexdigest()},
             'records':details,'errors':issues,
             'warning':'This does not validate semantic fit or establish ground-truth vulnerability observations.'}
    out=ROOT/'research/phase2_mapping_membership_receipt.json'
    out.write_text(json.dumps(receipt,indent=2)+'\n')
    print(f"{receipt['status']}: {len(details)} CHKs; {sum(map(lambda x:len(x['ASVS']),details))} ASVS and {sum(map(lambda x:len(x['CWE']),details))} CWE referenced IDs; {len(issues)} unresolved")
    print('Receipt:',out)
    for issue in issues:print('ERROR:',issue)
    return 0 if not issues else 1

if __name__=='__main__':raise SystemExit(main())
