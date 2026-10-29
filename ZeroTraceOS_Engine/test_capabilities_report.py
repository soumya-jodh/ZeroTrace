from app.capabilities import detect_capabilities

caps = detect_capabilities("/dev/sdb", "HDD")
assert caps.media_type == "HDD"
assert caps.utility == "N/A"
assert caps.capability_query_succeeded is True
assert caps.supported_methods == []
assert caps.recommended_method is None
print("PASS: HDD capability discovery is explicitly treated as not applicable.")
