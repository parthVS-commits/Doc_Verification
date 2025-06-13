import streamlit as st
import base64
import json
from services.validation_service import DocumentValidationService
from api.document_validation_api import DocumentValidationAPI

st.title("Document Validation UI")

validation_api = DocumentValidationAPI()

def encode_file(file):
    if file is None:
        return None
    try:
        return base64.b64encode(file.read()).decode("utf-8")
    except Exception as e:
        return None

def display_results(response_data):
    st.subheader("📊 Validation Overview")
    col1, col2, col3 = st.columns(3)

    total_rules = len(response_data.get('validation_rules', {}))
    failed_rules = sum(1 for rule in response_data.get('validation_rules', {}).values()
                      if rule.get('status') == 'failed')

    with col1:
        st.metric("Total Validation Rules", total_rules)
    with col2:
        st.metric("Failed Rules", failed_rules, delta_color="inverse")
    with col3:
        overall_status = "Passed ✅" if failed_rules == 0 else "Failed ❌"
        st.metric("Overall Status", overall_status)

    st.subheader("🔍 Validation Rules Check")
    passed_rules = []
    failed_rules = []

    for rule_name, details in response_data.get('validation_rules', {}).items():
        if details.get('status') == 'passed':
            passed_rules.append(f"✅ {rule_name.replace('_', ' ').title()}")
        else:
            failed_rules.append(f"❌ {rule_name.replace('_', ' ').title()}: {details.get('error_message', '')}")

    if failed_rules:
        with st.expander("❌ Failed Validation Rules", expanded=True):
            for item in failed_rules:
                st.write(item)

    if passed_rules:
        with st.expander("✅ Passed Validation Rules", expanded=True):
            for item in passed_rules:
                st.write(item)

    st.subheader("👤 Director Document Status")
    directors = response_data.get('document_validation', {}).get('directors', {})
    for director_name, details in directors.items():
        with st.expander(f"{director_name.replace('_', ' ').title()} Documents", expanded=True):
            cols = st.columns(3)
            doc_statuses = []
            for doc_type, doc_details in details.get('documents', {}).items():
                status = doc_details.get('status', '')
                errors = doc_details.get('error_messages', [])
                if status.lower() == 'valid':
                    doc_statuses.append(f"✅ {doc_type.replace('_', ' ').title()}")
                else:
                    error_list = "\n".join([f"\u2022 {err}" for err in errors])
                    doc_statuses.append(f"\n❌ {doc_type.replace('_', ' ').title()}\n{error_list}")
            for i, status in enumerate(doc_statuses):
                cols[i % 3].write(status)

    st.subheader("🏢 Company Documents Status")
    company_docs = response_data.get('document_validation', {}).get('companyDocuments', {})
    for doc_type, details in company_docs.items():
        status = details.get('status', '')
        errors = details.get('error_messages', [])
        if status.lower() == 'valid':
            st.success(f"✅ {doc_type.replace('_', ' ').title()}")
        else:
            error_list = "\n".join([f"\u2022 {err}" for err in errors])
            st.error(f"\n❌ {doc_type.replace('_', ' ').title()}\n{error_list}")

    st.subheader("📥 Download Results")
    st.download_button(
        label="📁 Download JSON",
        data=json.dumps(response_data, indent=2),
        file_name="validation_results.json",
        mime="application/json"
    )

service_id = st.text_input("Service ID", value="1")
request_id = st.text_input("Request ID", value="req-12345")
num_directors = st.slider("Number of Directors", min_value=2, max_value=5, value=2)

directors = {}
for i in range(num_directors):
    st.subheader(f"Director {i+1}")
    nationality = st.selectbox(f"Nationality for Director {i+1}", options=["Indian", "Foreign"], key=f"nat_{i}")
    authorised = st.selectbox(f"Authorised for Director {i+1}", options=["Yes", "No"], key=f"auth_{i}")
    st.write("Upload documents for this director:")

    directors[f"director_{i+1}"] = {
        "nationality": nationality,
        "authorised": authorised,
        "documents": {
            "aadharCardFront": encode_file(st.file_uploader("Aadhar Front", key=f"aadharFront_{i}")),
            "aadharCardBack": encode_file(st.file_uploader("Aadhar Back", key=f"aadharBack_{i}")),
            "panCard": encode_file(st.file_uploader("PAN Card", key=f"pan_{i}")),
            "passportPhoto": encode_file(st.file_uploader("Passport Photo", key=f"passportPhoto_{i}")),
            "address_proof": encode_file(st.file_uploader("Address Proof", key=f"addressProof_{i}")),
            "signature": encode_file(st.file_uploader("Signature", key=f"signature_{i}")),
            "passport": encode_file(st.file_uploader("Passport (Foreign)", key=f"passport_{i}")),
            "drivingLicense": encode_file(st.file_uploader("Driving License", key=f"drivingLicense_{i}"))
        }
    }

st.subheader("Company Documents")
address_proof_type = st.text_input("Address Proof Type")
addressProof = encode_file(st.file_uploader("Company Address Proof"))
noc = encode_file(st.file_uploader("NOC Document"))

if st.button("Validate Documents"):
    payload = {
        "service_id": service_id,
        "request_id": request_id,
        "directors": directors,
        "companyDocuments": {
            "address_proof_type": address_proof_type,
            "addressProof": addressProof,
            "noc": noc
        }
    }
    try:
        api_response, _ = validation_api.validate_document(payload)
        st.success("✅ Validation Completed Successfully!")
        display_results(api_response)
        with st.expander("Show Raw Validation Response"):
            st.json(api_response)
    except Exception as e:
        st.error(f"🚨 Validation Error: {str(e)}")

