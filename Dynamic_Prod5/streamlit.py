import streamlit as st
import base64
import json
from services.validation_service import DocumentValidationService
from api.document_validation_api import DocumentValidationAPI

import os

# Load from secrets (Streamlit deployment)
if "ELASTICSEARCH_PASSWORD" in st.secrets:
    os.environ["ELASTICSEARCH_HOST"] = st.secrets["ELASTICSEARCH_HOST"]
    os.environ["ELASTICSEARCH_USERNAME"] = st.secrets["ELASTICSEARCH_USERNAME"]
    os.environ["ELASTICSEARCH_PASSWORD"] = st.secrets["ELASTICSEARCH_PASSWORD"]
    os.environ["OPENAI_API_KEY"] = st.secrets["OPENAI_API_KEY"]

st.title("Document Validation UI")

validation_api = DocumentValidationAPI()

def encode_file(file):
    if file is None:
        return None
    try:
        return base64.b64encode(file.read()).decode("utf-8")
    except Exception as e:
        return None

def display_results(response_data,_):
    #st.write(response_data["document_validation"]["companyDocuments"])
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
            cols = st.columns(2)
            doc_statuses = []
            expected_docs = [
                "aadharCardFront", "aadharCardBack", "panCard", "passportPhoto",
                "address_proof", "signature", "passport", "drivingLicense"
            ]
            actual_docs = details.get('documents', {})
            if details.get("nationality", "").lower() == "foreign":
                st.info("Passport or Driving License must be provided for foreign directors. Aadhaar is not applicable.")
            else:
                st.info("Aadhaar is required for Indian directors. Passport/Driving License is not mandatory.")

            # for doc_type in expected_docs:
            #     doc_details = actual_docs.get(doc_type, {})
            #     status = doc_details.get('status', 'Not Uploaded')
            #     errors = doc_details.get('error_messages', [])

            #     display_name = doc_type.replace('_', ' ').replace('Card', ' Card').title()
                
            #     if status.lower() == 'valid':
            #         doc_statuses.append(f"✅ {display_name}")
            #     else:
            #         if not errors and status == 'Not Uploaded':
            #             doc_statuses.append(f"❌ {display_name}\n• Document not uploaded")
            #         else:
            #             error_list = "\n".join([f"\u2022 {err}" for err in errors])
            #             doc_statuses.append(f"❌ {display_name}\n{error_list}")           
            for doc_type in expected_docs:
                display_name = doc_type.replace('_', ' ').replace('Card', ' Card').title()
                
                # Rules-based validation override for specific types
                rule_map = {
                    "passportPhoto": "passport_photo",
                    "signature": "signature",
                    "address_proof": "address_proof"
                }

                if doc_type in rule_map:
                    rule_id = rule_map[doc_type]
                    rule_data = response_data.get("validation_rules", {}).get(rule_id, {})
                    failed_directors = [
                        d["director"] for d in rule_data.get("details", []) if d.get("status") == "failed"
                    ]
                    matching_error = next(
                        (d["error_message"] for d in rule_data.get("details", []) if d["director"] == director_name), 
                        None
                    )
                    if director_name in failed_directors:
                        doc_statuses.append(f"❌ {display_name}\n• {matching_error or 'Validation failed'}")
                    
                    else:
                        doc_statuses.append(f"✅ {display_name}")
                else:
                    # fallback for all other docs
                    doc_details = actual_docs.get(doc_type, {})
                    status = doc_details.get('status', 'Not Uploaded')
                    errors = doc_details.get('error_messages', [])

                    if status.lower() == 'valid':
                        doc_statuses.append(f"✅ {display_name}")
                    else:
                        if not errors and status == 'Not Uploaded':
                            doc_statuses.append(f"❌ {display_name}\n• Document not uploaded")
                        else:
                            error_list = "\n".join([f"\u2022 {err}" for err in errors])
                            doc_statuses.append(f"❌ {display_name}\n{error_list}")

            for i, status in enumerate(doc_statuses):
                cols[i % 2].write(status)

    st.subheader("🏢 Company Documents Status")
    company_docs = _.get('document_validation', {}).get('companyDocuments', {})
    # for doc_type, details in company_docs.items():
    #     status = details.get('status', '')
    #     errors = details.get('error_messages', [])
    #     if status.lower() == 'valid':
    #         st.success(f"✅ {doc_type.replace('_', ' ').title()}")
    #     else:
    #         error_list = "\n".join([f"\u2022 {err}" for err in errors])
    #         st.error(f"\n❌ {doc_type.replace('_', ' ').title()}\n{error_list}")
    # for doc_type in ["addressProof", "noc"]:
    #     details = company_docs.get(doc_type, {})
    #     status = details.get('status', '')
    #     errors = details.get('error_messages', [])

    #     if status.lower() == 'valid':
    #         st.success(f"✅ {doc_type.replace('_', ' ').title()}")
    #     else:
    #         error_list = "\n".join([f"\u2022 {err}" for err in errors])
    #         st.error(f"❌ {doc_type.replace('_', ' ').title()}\n{error_list}")
    doc_display_names = {
        "addressProof": "Address Proof",
        "noc": "NOC (No Objection Certificate)"
    }
    #st.write(company_docs["addressProof"])
    for doc_type in ["addressProof", "noc"]:
        if doc_type in company_docs:
            details = company_docs.get(doc_type, {})
            status = details.get('status', 'Unknown')
            errors = details.get('error_messages', [])
            
            # Get display name
            display_name = doc_display_names.get(doc_type, doc_type.replace('_', ' ').title())
            
            if status.lower() == 'valid':
                st.success(f"✅ {display_name}")
            else:
                if errors:
                    error_list = "\n".join([f"• {err}" for err in errors])
                    st.error(f"❌ {display_name}\n{error_list}")
                else:
                    st.error(f"❌ {display_name}\nValidation failed")

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
    if nationality == "Foreign":
        st.info("Note: For foreign directors, Passport or Driving License is mandatory. Aadhaar is not required.")
    else:
        st.info("Note: For Indian directors, Aadhaar is required. Passport/Driving License is optional.")

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
address_proof_type = st.selectbox("Select Address Proof Type",options=["Electricity Bill", "NOC", "Gas Bill"])
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
        #st.write(api_response["document_validation"]["companyDocuments"])
        #st.write(_["document_validation"]["companyDocuments"])
        st.success("✅ Validation Completed Successfully!")
        display_results(api_response,_)
        with st.expander("Show Raw Validation Response"):
            st.json(api_response)
    except Exception as e:
        st.error(f"🚨 Validation Error: {str(e)}")
