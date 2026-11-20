# Ghidra headless post-script: write function list as JSON (Yellow ghidra-mcp contract).
# @runtime Jython
import json
from java.io import FileWriter

out_path = None
try:
    args = getScriptArgs()
    if args and len(args) > 0:
        out_path = args[0]
except Exception:
    out_path = None
if not out_path:
    out_path = currentProgram.getExecutablePath() + ".ghidra-functions.json"

funcs = []
fm = currentProgram.getFunctionManager()
func = fm.getFunctions(True)
while func.hasNext():
    f = func.next()
    xref = 0
    try:
        xref = f.getSymbol().getReferenceCount()
    except Exception:
        pass
    funcs.append({
        "name": f.getName(),
        "address": str(f.getEntryPoint()),
        "xref_count": int(xref),
    })

payload = {
    "success": True,
    "name": currentProgram.getName(),
    "language": str(currentProgram.getLanguageID()),
    "function_count": len(funcs),
    "functions": funcs,
}
w = FileWriter(out_path)
try:
    w.write(json.dumps(payload))
finally:
    w.close()
