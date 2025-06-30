import streamlit as st
import pandas as pd

# ----------- Streamlit UI Setup ------------
st.set_page_config(page_title="Day 4: Suspicious Activity Detection", layout="wide")
st.title("🚨 Day 4: Suspicious Activity Detection Engine")

uploaded_file = st.file_uploader("📂 Upload timeline CSV (from Day 3)", type=["csv"])

# ----------- Rule Matching Logic ------------
def detect_anomalies(df):
    anomalies = []
    df['Timestamp'] = df['Timestamp'].astype(int)
    df = df.sort_values("Timestamp")

    # Rule R3 - Multiple IPs
    conn_counts = df[df["ShortType"] == "CONN"].groupby("File")["ip"].nunique()
    for file, count in conn_counts.items():
        if count >= 5:
            anomalies.append({
                "Rule": "R3",
                "Description": f"{count} distinct IPs contacted in file {file}",
                "User": "-",
                "File": file,
                "Time": "-"
            })

    for user in df["user"].dropna().unique():
        user_df = df[df["user"] == user].sort_values("Timestamp")

        for i in range(len(user_df) - 1):
            curr = user_df.iloc[i]
            nxt = user_df.iloc[i + 1]

            if curr["ShortType"] == "EXEC" and nxt["ShortType"] == "FILE":
                if "passwd" in nxt.get("path", ""):
                    anomalies.append({
                        "Rule": "R1",
                        "User": user,
                        "Description": f"{user} executed then modified passwd.",
                        "File": curr["File"],
                        "Time": nxt["Timestamp"]
                    })

            if curr["ShortType"] == "EXEC" and nxt["ShortType"] == "SHDW":
                anomalies.append({
                    "Rule": "R2",
                    "User": user,
                    "Description": f"{user} executed then killed a process.",
                    "File": curr["File"],
                    "Time": nxt["Timestamp"]
                })

            if curr["ShortType"] == "FILE" and nxt["ShortType"] == "DEL":
                if curr.get("path") == nxt.get("path"):
                    anomalies.append({
                        "Rule": "R5",
                        "User": user,
                        "Description": f"{user} modified then deleted `{curr['path']}`",
                        "File": curr["File"],
                        "Time": nxt["Timestamp"]
                    })

    # Rule R4 - Deletion of sensitive files
    sensitive_deletes = df[df["ShortType"] == "DEL"]
    for _, row in sensitive_deletes.iterrows():
        if any(s in row.get("path", "") for s in ["/etc/passwd", "/opt/secure.shd"]):
            anomalies.append({
                "Rule": "R4",
                "User": row.get("user", "unknown"),
                "Description": f"Deleted sensitive file: {row['path']}",
                "File": row["File"],
                "Time": row["Timestamp"]
            })

    return pd.DataFrame(anomalies)

# ----------- Main App Logic ------------
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success("✅ Timeline loaded. Running detection rules...")

    anomaly_df = detect_anomalies(df)

    st.subheader("🚩 Detected Anomalies")
    if anomaly_df.empty:
        st.success("🎉 No anomalies detected based on current rules.")
    else:
        st.dataframe(anomaly_df, use_container_width=True)
        csv = anomaly_df.to_csv(index=False).encode()
        st.download_button("📥 Download Anomaly Report", data=csv, file_name="anomaly_report.csv", mime="text/csv")

    st.markdown("---")
    with st.expander("📘 Detection Rules Used", expanded=False):
        st.markdown("""
        - **R1:** Execution followed by passwd file modification  
        - **R2:** Execution followed by process kill  
        - **R3:** ≥5 unique IP connections in a single file  
        - **R4:** Deletion of `/etc/passwd` or `/opt/secure.shd`  
        - **R5:** Modification and deletion of the same file  
        """)

else:
    st.info("📂 Please upload the `log_timeline.csv` file to begin anomaly analysis.")
