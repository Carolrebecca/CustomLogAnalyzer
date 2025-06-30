import streamlit as st
import pandas as pd
import json
from io import BytesIO

# Set up page
st.set_page_config(page_title="Day 3: Categorization & Timeline", layout="wide")
st.title("📆 Day 3: Log Categorization & Timeline Generator")

uploaded_file = st.file_uploader("📂 Upload parsed log CSV file (from Day 2)", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # Map ShortType to Category
    CATEGORY_MAP = {
        "EXEC": "User Activity",
        "DEL": "User Activity",
        "FILE": "User Activity",
        "LOG": "User Activity",
        "SHDW": "Process Control",
        "CONN": "Network Activity"
    }

    df["Category"] = df["ShortType"].map(CATEGORY_MAP).fillna("Unknown")

    # Sort by timestamp for timeline
    df_timeline = df.sort_values("Timestamp")

    st.success("✅ Timeline generated and categorized!")

    # Optional Filter
    st.subheader("🔍 Filter Options")
    selected_category = st.multiselect(
        "Select event categories to filter (optional):",
        options=df_timeline["Category"].unique(),
        default=list(df_timeline["Category"].unique())
    )

    filtered_df = df_timeline[df_timeline["Category"].isin(selected_category)]

    st.subheader("🕒 Event Timeline (Chronological)")
    st.dataframe(filtered_df, use_container_width=True)

    # Export Buttons
    st.subheader("📤 Export Timeline")
    csv_data = filtered_df.to_csv(index=False).encode()
    st.download_button("📥 Download CSV", csv_data, file_name="log_timeline.csv", mime="text/csv")

    # Convert to JSON for export
    json_data = filtered_df.to_dict(orient="records")
    json_bytes = BytesIO(json.dumps(json_data, indent=2).encode("utf-8"))
    st.download_button("📥 Download JSON", json_bytes, file_name="log_timeline.json", mime="application/json")

else:
    st.info("👆 Upload a `.csv` file generated from Day 2 to generate timeline and categories.")
