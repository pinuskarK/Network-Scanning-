#!/usr/bin/env python3
import nvdlib
import os

os.environ['NVD_API_KEY'] = '##################################'

# Search for OpenSSH CVEs
print("Searching for OpenSSH CVEs...")
results = nvdlib.searchCVE(cpeName="cpe:2.3:a:openbsd:openssh:6.6p1", limit=3)

for cve in results:
    print(f"\n✅ {cve.id}")
    if hasattr(cve, 'score') and cve.score:
        if hasattr(cve.score, 'cvssV3') and cve.score.cvssV3:
            print(f"   Score: {cve.score.cvssV3.get('baseScore', 'N/A')}")
    if hasattr(cve, 'descriptions') and cve.descriptions:
        print(f"   Desc: {cve.descriptions[0].value[:100]}...")

