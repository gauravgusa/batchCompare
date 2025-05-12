import streamlit as st
import difflib
import re
import os
import zipfile
from io import BytesIO
from datetime import datetime
import pandas as pd

# --- Utility Functions ---

def parse_edi(edi_content):
    try:
        isa_segment = next(seg for seg in edi_content.split('~') if seg.startswith('ISA'))
    except StopIteration:
        raise ValueError("No ISA segment found in EDI content")
    data_element_sep = isa_segment[3]
    sub_element_sep = isa_segment[-2] if len(isa_segment) >= 106 else ':'
    results = {
        'separators': {
            'data_element': data_element_sep,
            'sub_element': sub_element_sep,
            'segment': '~'
        },
        'isa': {},
        'gs': {},
        'inner_payload': []
    }
    segments = edi_content.split('~')
    capture_payload = False
    for segment in segments:
        elements = segment.split(data_element_sep)
        if not elements or not elements[0]:
            continue
        if elements[0] == 'ISA':
            results['isa'] = {
                'sender_qualifier': elements[5] if len(elements) > 5 else '',
                'sender_id': elements[6].strip() if len(elements) > 6 else '',
                'receiver_qualifier': elements[7] if len(elements) > 7 else '',
                'receiver_id': elements[8].strip() if len(elements) > 8 else '',
                'control_number': elements[13] if len(elements) > 13 else ''
            }
        elif elements[0] == 'GS':
            results['gs'] = {
                'gs01': elements[1] if len(elements) > 1 else '',
                'gs02': elements[2] if len(elements) > 2 else '',
                'gs03': elements[3] if len(elements) > 3 else ''
            }
        elif elements[0] == 'ST':
            capture_payload = True
        elif elements[0] == 'SE':
            capture_payload = False
        elif capture_payload and segment:
            results['inner_payload'].append(segment)
    return results

def mask_dates_times(segments, data_element_sep):
    masked_segments = []
    for seg in segments:
        elements = seg.split(data_element_sep)
        if not elements:
            continue
        tag = elements[0]
        try:
            if tag == "BEG" and len(elements) > 5:
                elements[5] = "#" * len(elements[5])
            elif tag == "DTM":
                if len(elements) > 2 and elements[2]:
                    elements[2] = "#" * len(elements[2])
                if len(elements) > 3 and elements[3]:
                    elements[3] = "#" * len(elements[3])
        except IndexError:
            continue
        masked_segments.append(data_element_sep.join(elements))
    return masked_segments

def generate_diff_html(content1, content2, desc1="File 1", desc2="File 2"):
    return difflib.HtmlDiff(tabsize=4, wrapcolumn=80).make_file(
        content1.split('\n'), 
        content2.split('\n'),
        fromdesc=desc1,
        todesc=desc2
    )

def generate_summary_html_report(
    file1_name, file2_name,
    isa1, isa2, gs1, gs2,
    isa_match, gs_match, masked_match,
    isa_ctrl1, isa_ctrl2, gs_ctrl1, gs_ctrl2
):
    today = datetime.now().strftime("%Y-%m-%d %H:%M")
    def row(label, val1, val2):
        return f"<tr><td>{label}</td><td>{val1}</td><td>{val2}</td></tr>"
    html = f"""
    <html>
    <head>
    <title>EDI Comparison Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
        .pass {{ color: green; font-weight: bold; }}
        .fail {{ color: red; font-weight: bold; }}
    </style>
    </head>
    <body>
    <h2>EDI Comparison Report</h2>
    <p><b>Generated:</b> {today}</p>
    <table>
        <tr>
            <th>File 1</th>
            <th>File 2</th>
            <th>ISA Control Number</th>
            <th>GS Control Number</th>
        </tr>
        <tr>
            <td>{file1_name}</td>
            <td>{file2_name}</td>
            <td>{isa_ctrl1} / {isa_ctrl2}</td>
            <td>{gs_ctrl1} / {gs_ctrl2}</td>
        </tr>
    </table>
    <br>
    <table>
        <tr><th>Segment</th><th>File 1</th><th>File 2</th></tr>
        {row("ISA Sender Qualifier", isa1.get('sender_qualifier',''), isa2.get('sender_qualifier',''))}
        {row("ISA Sender ID", isa1.get('sender_id',''), isa2.get('sender_id',''))}
        {row("ISA Receiver Qualifier", isa1.get('receiver_qualifier',''), isa2.get('receiver_qualifier',''))}
        {row("ISA Receiver ID", isa1.get('receiver_id',''), isa2.get('receiver_id',''))}
        {row("GS01", gs1.get('gs01',''), gs2.get('gs01',''))}
        {row("GS02", gs1.get('gs02',''), gs2.get('gs02',''))}
        {row("GS03", gs1.get('gs03',''), gs2.get('gs03',''))}
    </table>
    <br>
    <table>
        <tr><th>Check</th><th>Result</th></tr>
        <tr>
            <td>ISA Segment Match</td>
            <td class="{ 'pass' if isa_match else 'fail' }">{ 'PASS' if isa_match else 'FAIL' }</td>
        </tr>
        <tr>
            <td>GS Segment Match</td>
            <td class="{ 'pass' if gs_match else 'fail' }">{ 'PASS' if gs_match else 'FAIL' }</td>
        </tr>
        <tr>
            <td>Masked Payload Match</td>
            <td class="{ 'pass' if masked_match else 'fail' }">{ 'PASS' if masked_match else 'FAIL' }</td>
        </tr>
    </table>
    </body>
    </html>
    """
    return html

def generate_final_report_html(results_data):
    today = datetime.now().strftime("%Y-%m-%d %H:%M")
    rows = ""
    for data in results_data:
        file1 = data['file1_name']
        file2 = data['file2_name']
        isa_result = "**PASS**" if data['isa_match'] else "**FAIL**"
        gs_result = "**PASS**" if data['gs_match'] else "**FAIL**"
        masked_result = "**PASS**" if data['masked_match'] else "**FAIL**"

        
        rows += f"""
        <tr>
            <td>{file1}</td>
            <td>{file2}</td>
            <td>{data['isa_sender_qualifier']}</td>
            <td>{data['isa_sender_id']}</td>
            <td>{data['isa_receiver_qualifier']}</td>
            <td>{data['isa_receiver_id']}</td>
            <td>{data['gs01']}</td>
            <td>{data['gs02']}</td>
            <td>{data['gs03']}</td>
            <td class='{"pass" if data["isa_match"] else "fail"}'>{isa_result}</td>
            <td class='{"pass" if data["gs_match"] else "fail"}'>{gs_result}</td>
            <td class='{"pass" if data["masked_match"] else "fail"}'>{masked_result}</td>
        </tr>
        """
    
    html = f"""
    <html>
    <head>
    <title>EDI Comparison Final Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .pass {{ color: green; font-weight: bold; }}
        .fail {{ color: red; font-weight: bold; }}
        h1, h2 {{ color: #4CAF50; }}
        .summary {{ margin-bottom: 20px; }}
    </style>
    </head>
    <body>
    <h1>EDI Comparison Final Report</h1>
    <p class="summary"><b>Generated:</b> {today}</p>
    <p class="summary"><b>Total Comparisons:</b> {len(results_data)}</p>
    
    <table>
        <tr>
            <th>File 1</th>
            <th>File 2</th>
            <th>ISA Sender Qualifier</th>
            <th>ISA Sender ID</th>
            <th>ISA Receiver Qualifier</th>
            <th>ISA Receiver ID</th>
            <th>GS01</th>
            <th>GS02</th>
            <th>GS03</th>
            <th>ISA Segment Match</th>
            <th>GS Segment Match</th>
            <th>Masked Payload Match</th>
        </tr>
        {rows}
    </table>
    </body>
    </html>
    """
    return html

def compare_pair(file1_name, file2_name, file1_content, file2_content):
    parsed1 = parse_edi(file1_content)
    parsed2 = parse_edi(file2_content)
    # ISA/GS match
    isa_fields = ['sender_qualifier','sender_id','receiver_qualifier','receiver_id']
    isa_match = all(parsed1['isa'].get(k,'') == parsed2['isa'].get(k,'') for k in isa_fields)
    gs_fields = ['gs01','gs02','gs03']
    gs_match = all(parsed1['gs'].get(k,'') == parsed2['gs'].get(k,'') for k in gs_fields)
    # Masked payload match
    sep1 = parsed1['separators']['data_element']
    sep2 = parsed2['separators']['data_element']
    masked1 = '\n'.join(mask_dates_times(parsed1['inner_payload'], sep1))
    masked2 = '\n'.join(mask_dates_times(parsed2['inner_payload'], sep2))
    masked_match = masked1 == masked2
    # Control numbers
    isa_ctrl1 = parsed1['isa'].get('control_number','')
    isa_ctrl2 = parsed2['isa'].get('control_number','')
    gs_ctrl1 = parsed1['gs'].get('gs03','')
    gs_ctrl2 = parsed2['gs'].get('gs03','')
    # Summary HTML
    summary_html = generate_summary_html_report(
        file1_name, file2_name,
        parsed1['isa'], parsed2['isa'],
        parsed1['gs'], parsed2['gs'],
        isa_match, gs_match, masked_match,
        isa_ctrl1, isa_ctrl2, gs_ctrl1, gs_ctrl2
    )
    
    # For final report data
    report_data = {
        'file1_name': file1_name,
        'file2_name': file2_name,
        'isa_sender_qualifier': parsed1['isa'].get('sender_qualifier',''),
        'isa_sender_id': parsed1['isa'].get('sender_id',''),
        'isa_receiver_qualifier': parsed1['isa'].get('receiver_qualifier',''),
        'isa_receiver_id': parsed1['isa'].get('receiver_id',''),
        'gs01': parsed1['gs'].get('gs01',''),
        'gs02': parsed1['gs'].get('gs02',''),
        'gs03': parsed1['gs'].get('gs03',''),
        'isa_match': isa_match,
        'gs_match': gs_match,
        'masked_match': masked_match
    }
    
    return {
        'isa_match': isa_match,
        'gs_match': gs_match,
        'masked_match': masked_match,
        'summary_html': summary_html,
        'original_diff': generate_diff_html(file1_content, file2_content, file1_name, file2_name),
        'masked_diff': generate_diff_html(masked1, masked2, file1_name+" (masked)", file2_name+" (masked)"),
        'report_data': report_data
    }

# --- Streamlit UI ---

st.set_page_config(layout="wide", page_title="EDI File Compare", page_icon="🔍")
st.title("EDI File Compare & HTML Summary Report")

mode = st.sidebar.radio("Select Mode", ["Single File Compare", "Batch Folder Processing"])

if mode == "Single File Compare":
    file1 = st.file_uploader("Upload first EDI file", type=['edi','txt'])
    file2 = st.file_uploader("Upload second EDI file", type=['edi','txt'])
    if file1 and file2:
        file1_content = re.sub(r'\r?\n', '', file1.getvalue().decode("utf-8"))
        file2_content = re.sub(r'\r?\n', '', file2.getvalue().decode("utf-8"))
        compare = compare_pair(file1.name, file2.name, file1_content, file2_content)
        # Show summary
        st.components.v1.html(compare['summary_html'], height=350, scrolling=True)
        # Use tabs instead of nested expanders
        tab1, tab2 = st.tabs(["Original Content Diff", "Masked Content Diff"])
        with tab1:
            st.components.v1.html(compare['original_diff'], height=600, scrolling=True)
        with tab2:
            st.components.v1.html(compare['masked_diff'], height=600, scrolling=True)
        # Download summary
        st.download_button(
            label="Download HTML Summary Report",
            data=compare['summary_html'],
            file_name="edi_comparison_report.html",
            mime="text/html"
        )

elif mode == "Batch Folder Processing":
    st.subheader("Batch Folder Processing")
    st.markdown("""
    1. Upload all files from your **fromData** folder
    2. Upload all files from your **toData** folder
    3. Files will be matched by UUID in their filenames
    """)
    col1, col2 = st.columns(2)
    with col1:
        from_files = st.file_uploader("Upload FROMDATA files", 
                                    type=['txt', 'edi'],
                                    accept_multiple_files=True,
                                    key="from_data")
    with col2:
        to_files = st.file_uploader("Upload TODATA files", 
                                  type=['txt', 'edi'],
                                  accept_multiple_files=True,
                                  key="to_data")
    if from_files and to_files:
        to_files_map = {os.path.basename(f.name): f for f in to_files}
        results = {}
        all_report_data = []
        
        with st.spinner(f"Processing {len(from_files)} file pairs..."):
            for from_file in from_files:
                filename = os.path.basename(from_file.name)
                if "_" not in filename:
                    continue
                parts = filename.split("_")
                if len(parts) < 2:
                    continue
                uuid = parts[-1].split(".")[0]
                matching_to_name = f"{parts[0]}bla_{uuid}.txt"
                if matching_to_name not in to_files_map:
                    continue
                from_content = re.sub(r'\r?\n', '', from_file.getvalue().decode("utf-8"))
                to_content = re.sub(r'\r?\n', '', to_files_map[matching_to_name].getvalue().decode("utf-8"))
                compare = compare_pair(filename, matching_to_name, from_content, to_content)
                results[uuid] = {
                    'summary_html': compare['summary_html'],
                    'original_diff': compare['original_diff'],
                    'masked_diff': compare['masked_diff'],
                    'from_name': filename,
                    'to_name': matching_to_name
                }
                # Add report data for final report
                all_report_data.append(compare['report_data'])
        
        if not results:
            st.warning("No matching file pairs found!")
            st.stop()
            
        st.success(f"Processed {len(results)} file pairs")
        
        # Generate and display final report
        if all_report_data:
            final_report_html = generate_final_report_html(all_report_data)
            
            st.subheader("Final Comparison Report")
            st.components.v1.html(final_report_html, height=400, scrolling=True)
            
            # Download final report
            st.download_button(
                label="📄 Download Final Report",
                data=final_report_html,
                file_name="edi_final_comparison_report.html",
                mime="text/html"
            )
        
        # Show individual comparisons
        st.subheader("Individual Comparisons")
        for uuid, result in results.items():
            with st.expander(f"Comparison: {result['from_name']} vs {result['to_name']}", expanded=False):
                st.components.v1.html(result['summary_html'], height=350, scrolling=True)
                # Use tabs instead of nested expanders
                tab1, tab2 = st.tabs(["Original Content Diff", "Masked Content Diff"])
                with tab1:
                    st.components.v1.html(result['original_diff'], height=400, scrolling=True)
                with tab2:
                    st.components.v1.html(result['masked_diff'], height=400, scrolling=True)
        
        # Download all summaries as zip
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add final report
            if all_report_data:
                zip_file.writestr("final_report.html", final_report_html)
            # Add individual reports    
            for uuid, result in results.items():
                zip_file.writestr(f"{uuid}_summary.html", result['summary_html'])
        
        zip_buffer.seek(0)
        st.download_button(
            label="📥 Download All Reports (ZIP)",
            data=zip_buffer,
            file_name="edi_comparison_reports.zip",
            mime="application/zip"
        )
