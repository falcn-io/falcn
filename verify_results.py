import json
import os
import sys

def main():
    filepath = "supply_chain_result.json"
    if not os.path.exists(filepath):
        print("File not found")
        sys.exit(1)

    content = ""
    content_raw = b""
    with open(filepath, "rb") as f:
        content_raw = f.read()

    # Try UTF-16LE
    try:
        content = content_raw.decode("utf-16-le")
    except:
        # Try UTF-8
        try:
            content = content_raw.decode("utf-8")
        except:
            print("Failed to decode file")
            sys.exit(1)

    # Sanitize content: find start of JSON '{'
    idx = content.find('{')
    if idx == -1:
        print("No JSON object found")
        sys.exit(1)
    
    json_text = content[idx:]
    
    try:
        data = json.loads(json_text)
        metadata = data.get("metadata", {})
        
        gtr = "gtr_results" in metadata
        runt = "runt_results" in metadata
        dirt = "dirt_assessments" in metadata
        
        print(f"GTR Results: {gtr}")
        print(f"RUNT Results: {runt}")
        print(f"DIRT Assessments: {dirt}")
        
        if gtr and runt:
            print("VERIFICATION SUCCESS")
        else:
            print("VERIFICATION FAILURE")
            print("Metadata keys:", list(metadata.keys()))

    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
        print(json_text[:200])
        sys.exit(1)

if __name__ == "__main__":
    main()
