import streamlit as st
import re
from collections import defaultdict
import pandas as pd

# ----- LogEntry class definition -----
class LogEntry:
    def __init__(self, index, timestamp, event_type, payload_raw, file_source="unknown"):
        self.index = index
        self.timestamp = int(timestamp)
        self.event_type = event_type
        self.payload_raw = payload_raw
        self.short_type = event_type.split("-")[-1]
        self.payload_data = self._parse_payload(payload_raw)
        self.source_file = file_source

    def _parse_payload(self, payload):
        try:
            if self.short_type == "CONN":
                return {"ip": payload.split(":")[1]}
            elif self.short_type == "SHDW":
                return {"pid": int(payload.split(":")[1].replace("pid", ""))}
            else:
                user, path = payload.split("=>")
                return {
                    "user": user.split(":")[1],
                    "path": path
                }
        except Exception:
            return {"error": "Malformed payload"}

    def to_dict(self):
        return {
            "File": self.source_file,
            "Index": self.index,
            "Timestamp": self.timestamp,
            "EventType": self.event_type,
            "ShortType": self.short_type,
            "PayloadRaw": self.payload_raw,
            **self.payload_data  # Merge parsed payload fields
        }

# ----- Parser Function -----
def parse_log_lines(lines, filename):
    parsed_entries = []
    error_lines = []

    for i, line in enumerate(lines, 1):
        line = line.strip()
        try:
            match = re.match(r"(0x[0-9A-F]+)\[ts:(\d+)\]\|EVNT:(\S+)!@(.+)", line)
            if match:
                idx, ts, event, payload = match.groups()
                log = LogEntry(idx, ts, event, payload, file_source=filename)
                parsed_entries.append(log.to_dict())
            else:
                raise ValueError("Pattern mismatch")
        except Exception as e:
            error_lines.append({
                "File": filename,
                "LineNumber": i,
                "Line": line,
                "Error": str(e)
            })

    return parsed_entries, error_lines

# ----- Streamlit UI -----
st.set_page_config(page_title="Forensic Log Parser - Day 2", layout="wide")
st.title("🧪 Day 2: Data Extraction Parser in Python")

uploaded_files = st.file_uploader("Upload one or more `.vlog` files", type=["vlog"], accept_multiple_files=True)

if uploaded_files:
    all_entries = []
    all_errors = []

    for file in uploaded_files:
        content = file.read().decode("utf-8").splitlines()
        parsed, errors = parse_log_lines(content, file.name)
        all_entries.extend(parsed)
        all_errors.extend(errors)

    st.success(f"Parsed {len(all_entries)} entries from {len(uploaded_files)} file(s).")
    st.info(f"🛠️ Found {len(all_errors)} malformed/corrupt line(s).")

    # Parsed Entries Table
    if st.checkbox("✅ Show Parsed Log Entries"):
        st.dataframe(pd.DataFrame(all_entries))

    # Error Entries Table
    if st.checkbox("⚠️ Show Malformed Lines"):
        st.dataframe(pd.DataFrame(all_errors))

    # CSV Download
    st.subheader("📥 Export")
    df_export = pd.DataFrame(all_entries)
    st.download_button("Download Parsed Data as CSV", data=df_export.to_csv(index=False).encode(),
                       file_name="parsed_logs_day2.csv", mime="text/csv")
else:
    st.info("📂 Please upload `.vlog` file(s) to start parsing.")
