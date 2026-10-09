"""Turn a pytest junit file into GitHub annotations (::error), so a failing job names its tests without a log download."""
import sys
import xml.etree.ElementTree as ET

for case in ET.parse(sys.argv[1]).getroot().iter("testcase"):
    for bad in list(case.findall("failure")) + list(case.findall("error")):
        msg = " ".join((bad.get("message") or "").split())[:400].replace("%", "%25")
        print(f"::error title={case.get('classname')}::{case.get('name')[:120]} -> {msg}")
