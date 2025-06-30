import streamlit as st
import pandas as pd
import re
from collections import defaultdict
import io
import zipfile
import plotly.express as px
import plotly.io as pio

# Streamlit config
st.set_page_config(page_title="Forensic Artifact Analyzer", layout="wide")
st.title("🧰 Forensic Artifact Parser & Visual Dashboard")

uploaded_files = st.file_uploader("📂 Upload one or more `.vlog` log files", type=["vlog"], accept_multiple_files=True)

parsed_logs = []
summary_stats = defaultdict(int)
df_logs = pd.DataFrame()
df_anomalies = pd.DataFrame()

# Anomaly rules
def detect_anomalies(df):
    results = []
    df = df.sort_values("Timestamp")
    for user in df["user"].dropna().unique():
        user_df = df[df["user"] == user]
        for i in range(len(user_df) - 1):
            curr = user_df.iloc[i]
            nxt = user_df.iloc[i + 1]
            if curr["ShortType"] == "EXEC" and nxt["ShortType"] == "FILE" and "passwd" in str(nxt.get("path", "")):
                results.append({"Rule": "R1", "User": user, "Description": "Exec then passwd mod", "Time": nxt["Timestamp"]})
            if curr["ShortType"] == "EXEC" and nxt["ShortType"] == "SHDW":
                results.append({"Rule": "R2", "User": user, "Description": "Exec then kill", "Time": nxt["Timestamp"]})
            if curr["ShortType"] == "FILE" and nxt["ShortType"] == "DEL" and curr.get("path") == nxt.get("path"):
                results.append({"Rule": "R5", "User": user, "Description": "Mod then del same file", "Time": nxt["Timestamp"]})
    for _, row in df[df["ShortType"] == "DEL"].iterrows():
        if any(s in row.get("path", "") for s in ["/etc/passwd", "/opt/secure.shd"]):
            results.append({"Rule": "R4", "User": row["user"], "Description": f"Deleted sensitive file: {row['path']}", "Time": row["Timestamp"]})
    return pd.DataFrame(results)

# File processing
if uploaded_files:
    for uploaded in uploaded_files:
        content = uploaded.read().decode("utf-8").splitlines()
        for line in content:
            m = re.match(r"(0x[0-9A-F]+)\[ts:(\d+)\]\|EVNT:(\S+)!@(.+)", line)
            if not m:
                continue
            idx, ts, etype, payload = m.groups()
            short = etype.split("-")[-1]
            log_entry = {
                "File": uploaded.name,
                "Index": idx,
                "Timestamp": int(ts),
                "Event": etype,
                "ShortType": short,
                "Payload": payload
            }
            if "usr:" in payload:
                log_entry["user"] = payload.split("usr:")[1].split("=>")[0]
            if "=>" in payload:
                log_entry["path"] = payload.split("=>")[1]
            if "IP:" in payload:
                log_entry["ip"] = payload.split("IP:")[1]
            if "pid" in payload:
                log_entry["pid"] = payload.split("pid")[-1]
            parsed_logs.append(log_entry)
            summary_stats[short] += 1

    df_logs = pd.DataFrame(parsed_logs).sort_values("Timestamp")
    df_anomalies = detect_anomalies(df_logs)

    st.success("✅ Logs parsed and analyzed.")

    # Summary
    with st.expander("📊 Summary Report"):
        for k, v in summary_stats.items():
            st.write(f"🔸 {k}: {v} events")

    if st.checkbox("📈 Show Timeline Table"):
        st.dataframe(df_logs, use_container_width=True)

    st.subheader("🚨 Detected Anomalies")
    if not df_anomalies.empty:
        st.dataframe(df_anomalies, use_container_width=True)
    else:
        st.info("No anomalies found.")

    # Export
    st.subheader("📤 Export Reports")
    timeline_csv = df_logs.to_csv(index=False).encode("utf-8")
    anomaly_csv = df_anomalies.to_csv(index=False).encode("utf-8")
    summary_text = "\n".join([f"{k}: {v}" for k, v in summary_stats.items()])

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a") as zipf:
        zipf.writestr("timeline.csv", timeline_csv)
        zipf.writestr("anomaly_report.csv", anomaly_csv)
        zipf.writestr("summary.txt", summary_text)
    st.download_button("📦 Download All Reports (ZIP)", zip_buffer.getvalue(), "forensic_reports.zip", mime="application/zip")

    # Day 7 Visuals
    st.header("📊 Day 7: Visual Analytics")

    st.subheader("📊 Event Frequency Over Time")
    freq_fig = px.histogram(df_logs, x="Timestamp", color="ShortType", nbins=30,
                            title="Event Frequency", labels={"Timestamp": "Time", "ShortType": "Type"})
    st.plotly_chart(freq_fig, use_container_width=True)

    st.subheader("👤 User Activity Timeline")
    user_df = df_logs.dropna(subset=["user"])
    user_fig = px.strip(user_df, x="Timestamp", y="user", color="ShortType",
                        title="User Actions Over Time", stripmode="overlay")
    st.plotly_chart(user_fig, use_container_width=True)

    if not df_anomalies.empty:
        st.subheader("🚨 Anomaly Highlights")
        anomaly_fig = px.scatter(df_anomalies, x="Time", y="User", color="Rule",
                                 hover_data=["Description"], title="Anomalies Detected")
        st.plotly_chart(anomaly_fig, use_container_width=True)

    # Export Plots
    st.subheader("📥 Download Plots")

    def export_plot(fig, name):
        img_bytes = fig.to_image(format="png", width=1000, height=600)
        html_bytes = fig.to_html(full_html=False).encode("utf-8")
        st.download_button(f"⬇️ {name}.png", img_bytes, file_name=f"{name}.png", mime="image/png")
        st.download_button(f"⬇️ {name}.html", html_bytes, file_name=f"{name}.html", mime="text/html")

    export_plot(freq_fig, "event_frequency")
    export_plot(user_fig, "user_activity")
    if not df_anomalies.empty:
        export_plot(anomaly_fig, "anomaly_plot")
else:
    st.info("👆 Upload multiple `.vlog` files to begin full forensic analysis.")
