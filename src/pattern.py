class Pattern:
    def __init__(self, vuln_type, entries, sanitizers, sinks):
        self.type = vuln_type
        self.entries = entries
        self.sanitizers = sanitizers
        self.sinks = sinks
