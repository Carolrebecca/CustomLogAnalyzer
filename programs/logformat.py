import streamlit as st
import re
from collections import defaultdict
import pandas as pd

st.set_page_config(page_title="Forensic Log Parser", layout="wide")
st.title("🔍 Forensic Artifact Parser and Analyzer")

uploaded_files = st.file_uploader(
    "Upload one or more `.vlog` files", type=["vlog"], accept_multiple_files=True
)

if uploaded_files:
    event_summary = defaultdict(list)
    all_entries = []

    for uploaded_file in uploaded_files:
        content = uploaded_file.read().decode("utf-8")
        log_lines = content.strip().splitlines()

        for line in log_lines:
            match = re.match(r"(0x[0-9A-F]+)\[ts:(\d+)\]\|EVNT:(\S+)!@(.+)", line)
            if match:
                idx, timestamp, event_type, payload = match.groups()
                event_type_base = event_type.split("-")[-1]
                parsed_entry = {
                    "File": uploaded_file.name,
                    "Index": idx,
                    "Timestamp": timestamp,
                    "EventType": event_type,
                    "Payload": payload,
                    "ShortType": event_type_base
                }
                event_summary[event_type_base].append(parsed_entry)
                all_entries.append(parsed_entry)

    st.success(f"✅ {len(uploaded_files)} file(s) parsed successfully!")

    # Display summary
    st.header("📊 Event Summary")
    for event_type, entries in event_summary.items():
        with st.expander(f"Event Type: `{event_type}` ({len(entries)} entries)", expanded=False):
            st.write("Sample Payloads:")
            for entry in entries[:5]:
                st.code(f"{entry['File']} [{entry['Timestamp']}] {entry['Payload']}", language='text')

    if st.checkbox("Show full parsed data"):
        st.subheader("🧾 Full Parsed Entries")
        st.dataframe(pd.DataFrame(all_entries))

    # Export option
    st.header("📤 Export Merged Data")
    df = pd.DataFrame(all_entries)
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download Merged Data as CSV",
        data=csv,
        file_name="merged_parsed_logs.csv",
        mime="text/csv"
    )

else:
    st.info("📂 Please upload one or more `.vlog` files to begin analysis.")
