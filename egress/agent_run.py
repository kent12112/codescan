from codescan.cve_agent import analyze_dependencies
reqs = "requests==2.19.0\nflask==0.12.2\n"
print(analyze_dependencies(reqs))
