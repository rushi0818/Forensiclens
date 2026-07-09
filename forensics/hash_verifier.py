import os
import hashlib
import json
import requests
from datetime import datetime


VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"


def compute_file_hashes(file_path):
    """
    Compute MD5, SHA1, and SHA256 of a file.
    All three are computed because:
    - MD5    : Fast, widely used (but weak for security)
    - SHA1   : Medium strength
    - SHA256 : Industry standard for forensics
    """
    if not os.path.exists(file_path):
        return {'error': 'File not found'}

    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            'md5'    : md5.hexdigest(),
            'sha1'   : sha1.hexdigest(),
            'sha256' : sha256.hexdigest(),
            'file'   : os.path.basename(file_path),
            'size'   : f"{round(os.path.getsize(file_path)/1024, 2)} KB",
            'computed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    except Exception as e:
        return {'error': str(e)}


def verify_hash(file_path, expected_hash, hash_type="sha256"):
    """
    Verify a file against a known good hash.
    Used to confirm evidence integrity.
    If hashes don't match - evidence may be tampered!
    """
    hashes = compute_file_hashes(file_path)

    if 'error' in hashes:
        return {'verified': False, 'error': hashes['error']}

    computed = hashes.get(hash_type, '')
    match    = computed.lower() == expected_hash.lower().strip()

    return {
        'verified'       : match,
        'hash_type'      : hash_type,
        'expected_hash'  : expected_hash,
        'computed_hash'  : computed,
        'verdict'        : '✅ INTEGRITY VERIFIED' if match else '❌ HASH MISMATCH - POSSIBLE TAMPERING',
        'file'           : os.path.basename(file_path),
    }


def check_virustotal(file_hash):
    """Check hash against VirusTotal."""
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {
            'checked' : False,
            'note'    : 'Add VirusTotal API key in hash_verifier.py',
            'hash'    : file_hash
        }

    try:
        headers  = {'x-apikey': VT_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{file_hash}',
            headers=headers, timeout=10
        )

        if response.status_code == 404:
            return {'checked': True, 'found': False,
                    'note': 'Not in VirusTotal database'}

        if response.status_code == 200:
            data      = response.json()
            stats     = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total     = sum(stats.values())

            return {
                'checked'    : True,
                'found'      : True,
                'malicious'  : malicious,
                'total'      : total,
                'verdict'    : 'MALICIOUS' if malicious > 3 else
                               'SUSPICIOUS' if malicious > 0 else 'CLEAN',
                'confidence' : round((malicious/total)*100, 1) if total > 0 else 0
            }

    except Exception as e:
        return {'checked': False, 'error': str(e)}

    return {'checked': False}


def create_evidence_log(file_path, case_number="CASE-001", analyst="Ritesh Vijay Bavaskar"):
    """
    Create a formal Chain of Custody evidence log.
    This is required in real forensic investigations
    to prove evidence was not tampered with.
    """
    hashes = compute_file_hashes(file_path)

    if 'error' in hashes:
        return {'error': hashes['error']}

    vt_result = check_virustotal(hashes.get('sha256', ''))

    evidence_log = {
        'case_number'    : case_number,
        'analyst'        : analyst,
        'tool'           : 'ForensicLens v1.0',
        'collected_at'   : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'evidence'       : {
            'filename'   : hashes['file'],
            'file_size'  : hashes['size'],
            'md5'        : hashes['md5'],
            'sha1'       : hashes['sha1'],
            'sha256'     : hashes['sha256'],
        },
        'vt_result'      : vt_result,
        'custody_note'   : (
            f"Evidence collected on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
            f"by {analyst} using ForensicLens. "
            f"Hash verified at time of collection. "
            f"Case: {case_number}"
        )
    }

    return evidence_log
