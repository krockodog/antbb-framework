from . import android, dos, dotnet, dynamic_lab, elf, hexfw, pe, triage

REGISTRY = {
    "triage": triage.run,
    "pe": pe.run,
    "dotnet": dotnet.run,
    "android": android.run,
    "elf": elf.run,
    "hex": hexfw.run,
    "carve": hexfw.run_carve,
    "dos": dos.run,
    "dynamic": dynamic_lab.run,
}
