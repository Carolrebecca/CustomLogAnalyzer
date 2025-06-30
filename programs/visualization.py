import streamlit as st
import pandas as pd
import plotly.express as px
from io import BytesIO
import plotly.io as pio

st.set_page_config(page_title="Day 5: Forensic Log Visualization", layout="wide")
st.title("📈 Day 5: Visualization Dashboard")

# File upload
timeline_file = st.file_uploader("📂 Upload timeline CSV file", type=["csv"])
anomaly_file = st.file_uploader("🚨 Upload anomaly report CSV file", type=["csv"])

if timeline_file and anomaly_file:
    df = pd.read_csv(timeline_file)
    anomalies = pd.read_csv(anomaly_file)

    df["Timestamp"] = pd.to_numeric(df["Timestamp"], errors="coerce")
    df = df.sort_values("Timestamp")

    anomalies["Timestamp"] = pd.to_numeric(anomalies["Time"], errors="coerce")
    anomalies = anomalies.dropna(subset=["Timestamp"])

    # Chart 1: Event frequency
    st.subheader("📊 Event Frequency Over Time")
    freq_fig = px.histogram(df, x="Timestamp", color="ShortType", nbins=30,
                            title="Event Frequency", labels={"Timestamp": "Time", "ShortType": "Type"})
    st.plotly_chart(freq_fig, use_container_width=True)

    # Chart 2: User Activity
    st.subheader("👤 User Activity Timeline")
    user_df = df.dropna(subset=["user"])
    user_fig = px.strip(user_df, x="Timestamp", y="user", color="ShortType",
                        title="User Actions Over Time", stripmode="overlay")
    st.plotly_chart(user_fig, use_container_width=True)

    # Chart 3: Anomalies
    st.subheader("🚨 Highlighted Anomalies")
    anomaly_fig = px.scatter(anomalies, x="Timestamp", y="User", color="Rule",
                             hover_data=["Description"], title="Anomaly Events")
    st.plotly_chart(anomaly_fig, use_container_width=True)

    # Exports
    st.subheader("📥 Download Charts")
    def download_plot(fig, name):
        img_bytes = fig.to_image(format="png", width=1000, height=600, scale=2)
        html_bytes = fig.to_html(full_html=False).encode("utf-8")
        st.download_button(f"⬇️ Download {name} (PNG)", img_bytes, file_name=f"{name}.png", mime="image/png")
        st.download_button(f"⬇️ Download {name} (HTML)", html_bytes, file_name=f"{name}.html", mime="text/html")

    download_plot(freq_fig, "event_frequency")
    download_plot(user_fig, "user_activity")
    download_plot(anomaly_fig, "anomaly_plot")

else:
    st.info("📂 Please upload both the timeline CSV and anomaly report CSV to generate visualizations.")
