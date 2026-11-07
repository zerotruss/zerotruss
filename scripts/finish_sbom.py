"""Tidy the CycloneDX SBOM that cyclonedx-py wrote from the runtime-only environment.

Run it with the python of that same environment, so it can read the packages' own metadata:
    ENV/bin/python scripts/finish_sbom.py sbom.cdx.json

It does two things, and uses only the standard library:
1. Makes the zerotruss component the main component of the SBOM (type application). The
   dependency graph keeps pointing at it, so the graph stays complete.
2. Fills in a missing license from the package's own metadata (its free-text License field),
   so a dependency that declares a license is not shown without one. It never invents a license:
   a package that declares nothing stays without one.
"""
import importlib.metadata
import json
import sys


def normal(name):
    return name.lower().replace("_", "-")


# The single-line License field a package declares in its own metadata, or "" if there is none
def declared_license(name):
    try:
        text = importlib.metadata.metadata(name).get("License", "") or ""
    except importlib.metadata.PackageNotFoundError:
        return ""
    text = text.strip()
    return text if text and "\n" not in text and len(text) <= 100 else ""


def main(path):
    with open(path) as file:
        bom = json.load(file)

    # 1. the application becomes the main component
    others = []
    for component in bom["components"]:
        if normal(component["name"]) == "zerotruss":
            component["type"] = "application"
            bom["metadata"]["component"] = component
        else:
            others.append(component)
    if "component" not in bom["metadata"]:
        raise SystemExit("the zerotruss package is not in the environment")
    bom["components"] = others

    # 2. fill in missing licenses from the packages' own metadata
    filled = []
    for component in others:
        if not component.get("licenses"):
            text = declared_license(component["name"])
            if text:
                component["licenses"] = [{"license": {"name": text}}]
                filled.append(f"{component['name']}: {text}")

    with open(path, "w") as file:
        json.dump(bom, file, indent=2)
        file.write("\n")
    print(f"main component: {bom['metadata']['component']['name']} {bom['metadata']['component']['version']}")
    print(f"components: {len(others)}; licenses filled from package metadata: {filled or 'none needed'}")
    print("components still without a license:", [c["name"] for c in others if not c.get("licenses")] or "none")


if __name__ == "__main__":
    main(sys.argv[1])
