"""
Updated extraction prompts for different document types to support
the new validation requirements
"""

def get_aadhar_extraction_prompt():
    """
    Generate Aadhar card extraction prompt with masking detection
    """
    return """
    Extract the following information from the Aadhar card:
    - Full Name
    - Date of Birth (in DD/MM/YYYY format)
    - Gender
    - Aadhar Number
    - Address (complete address)
    
    Also assess the following:
    - Is the Aadhar card masked? (Look for X's or *'s in the Aadhar number)
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    
    Return a JSON with these exact keys:
    {
        "name": "Full Name as on card",
        "dob": "DD/MM/YYYY",
        "gender": "M/F",
        "aadhar_number": "XXXX XXXX XXXX",
        "address": "Complete address",
        "is_masked": true/false,
        "clarity_score": 0.95
    }
    
    If a field is not found, use null.
    """

def get_pan_extraction_prompt():
    """
    Generate PAN card extraction prompt with age extraction
    """
    return """
    Extract the following information from the PAN card:
    - Full Name
    - Father's Name
    - Date of Birth (in DD/MM/YYYY format)
    - PAN Number
    
    Also assess the following:
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    
    Return a JSON with these exact keys:
    {
        "name": "Full Name as on card",
        "father_name": "Father's Name",
        "dob": "DD/MM/YYYY",
        "pan_number": "XXXXXXXXXX",
        "clarity_score": 0.95
    }
    
    If a field is not found, use null.
    """

def get_passport_extraction_prompt():
    """
    Generate passport extraction prompt with validity check
    """
    return """
    Extract the following information from the passport:
    - Full Name
    - Passport Number
    - Date of Birth (in DD/MM/YYYY format)
    - Nationality
    - Date of Issue (in DD/MM/YYYY format)
    - Date of Expiry (in DD/MM/YYYY format)
    
    Also assess the following:
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    - Is the passport currently valid? (Compare expiry date with current date)
    
    Return a JSON with these exact keys:
    {
        "name": "Full Name as in passport",
        "passport_number": "XXXXXXXXX",
        "dob": "DD/MM/YYYY",
        "nationality": "Country name",
        "issue_date": "DD/MM/YYYY",
        "expiry_date": "DD/MM/YYYY",
        "is_valid": true/false,
        "clarity_score": 0.95
    }
    
    If a field is not found, use null.
    """

def get_driving_license_extraction_prompt():
    """
    Generate driving license extraction prompt with validity check
    """
    return """
    Extract the following information from the driving license:
    - Full Name
    - License Number
    - Date of Birth (in DD/MM/YYYY format)
    - Address
    - Date of Issue (in DD/MM/YYYY format)
    - Date of Expiry (in DD/MM/YYYY format)
    
    Also assess the following:
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    - Is the license currently valid? (Compare expiry date with current date)
    
    Return a JSON with these exact keys:
    {
        "name": "Full Name as on license",
        "license_number": "XXXXXXXXX",
        "dob": "DD/MM/YYYY",
        "address": "Complete address",
        "issue_date": "DD/MM/YYYY",
        "expiry_date": "DD/MM/YYYY",
        "is_valid": true/false,
        "clarity_score": 0.95
    }
    
    If a field is not found, use null.
    """

def get_address_proof_extraction_prompt():
    """
    Generate address proof extraction prompt
    """
    return """
    Extract the following information from the address proof document:
    - Full Name (of the person whose address this is)
    - Complete Address
    - Document Type (what kind of document this is)
    - Date on Document (in DD/MM/YYYY format)
    - Issuing Authority
    
    Also assess the following:
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    - Is the complete address visible? (yes/no)
    
    Return a JSON with these exact keys:
    {
        "name": "Full Name",
        "address": "Complete address",
        "document_type": "Type of document",
        "date": "DD/MM/YYYY",
        "issuing_authority": "Authority name",
        "clarity_score": 0.95,
        "complete_address_visible": true/false
    }
    
    If a field is not found, use null.
    """

def get_bill_extraction_prompt():
    """
    Generate electricity/utility bill extraction prompt
    """
    return """
    Extract the following information from the utility bill:
    - Consumer Name
    - Bill Date (in DD/MM/YYYY format)
    - Due Date (in DD/MM/YYYY format)
    - Total Amount
    - Connection Address (complete address)
    - Type of Utility (electricity, water, gas, etc.)
    
    Also assess the following:
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    - Is the complete address visible? (yes/no)
    
    Return a JSON with these exact keys:
    {
        "consumer_name": "Name on bill",
        "bill_date": "DD/MM/YYYY",
        "due_date": "DD/MM/YYYY",
        "total_amount": "Amount",
        "address": "Complete address",
        "utility_type": "Type of utility",
        "clarity_score": 0.95,
        "complete_address_visible": true/false
    }
    
    If a field is not found, use null.
    """

def get_passport_photo_extraction_prompt():
    """
    Generate passport photo assessment prompt
    """
    return """
    Analyze this passport size photograph and assess the following:
    
    - Is it a clear photo of a person's face? (Rate clarity on a scale of 0 to 1)
    - Is it a recent-looking photo? (yes/no)
    - Is it a proper passport-style photo (formal, neutral background)? (yes/no)
    - Is the face clearly visible? (yes/no)
    
    Return a JSON with these exact keys:
    {
        "clarity_score": 0.95,
        "is_recent": true/false,
        "is_passport_style": true/false,
        "face_visible": true/false
    }
    """

def get_signature_extraction_prompt():
    """
    Generate signature assessment prompt
    """
    return """
    Analyze this signature and assess the following:
    
    - Is it a clear signature? (Rate clarity on a scale of 0 to 1)
    - Is it a handwritten signature (not typed or printed)? (yes/no)
    - Is it complete and not cut off? (yes/no)
    
    Return a JSON with these exact keys:
    {
        "clarity_score": 0.95,
        "is_handwritten": true/false,
        "is_complete": true/false
    }
    """

def get_noc_extraction_prompt():
    """
    Generate NOC (No Objection Certificate) extraction prompt
    """
    return """
    Extract the following information from this No Objection Certificate (NOC):
    
    - Property Owner's Name
    - Property Address
    - Tenant/Applicant Name
    - Date of NOC (in DD/MM/YYYY format)
    - Purpose of NOC
    
    Also assess the following:
    - Is there a signature on the document? (yes/no)
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    - Does it appear to be a valid NOC document? (yes/no)
    
    Return a JSON with these exact keys:
    {
        "owner_name": "Property owner's name",
        "property_address": "Complete property address",
        "applicant_name": "Tenant/applicant name",
        "date": "DD/MM/YYYY",
        "purpose": "Purpose of NOC",
        "has_signature": true/false,
        "clarity_score": 0.95,
        "is_valid_noc": true/false
    }
    
    If a field is not found, use null.
    """

def get_generic_extraction_prompt():
    """
    Generic document extraction prompt
    """
    return """
    Extract key information from this document.
    
    Identify what type of document this is, and then extract relevant fields.
    
    Also assess the following:
    - Is the document clear and readable? (Rate clarity on a scale of 0 to 1)
    - Is the document valid and not expired? (yes/no)
    
    Return a JSON with the extracted fields and assessment.
    Focus on names, dates, addresses, and identification numbers.
    
    Include a "clarity_score" field with a value between 0 and 1.
    
    If a field is not found, use null.
    """

# def get_aadhar_extraction_prompt():
#     return """
#     Analyze this Aadhar card image and extract the following information in JSON format:
    
#     {
#         "name": "Full name on the card",
#         "aadhar_number": "12-digit Aadhar number",
#         "dob": "Date of birth in DD/MM/YYYY format",
#         "gender": "Male/Female",
#         "address": "Complete address",
#         "is_masked": "true if Aadhar number is masked (contains XXXX), false otherwise",
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity",
#         "document_type": "aadhar_front or aadhar_back"
#     }
    
#     If any information is not clearly visible or extractable, use "Not Extracted" as the value.
#     Ensure the clarity_score reflects the overall readability of the document.
#     """

# def get_pan_extraction_prompt():
#     return """
#     Analyze this PAN card image and extract the following information in JSON format:
    
#     {
#         "name": "Full name on the card",
#         "pan_number": "10-character PAN number",
#         "dob": "Date of birth in DD/MM/YYYY format",
#         "father_name": "Father's name",
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity"
#     }
    
#     If any information is not clearly visible or extractable, use "Not Extracted" as the value.
#     Ensure the PAN number follows the format: 5 letters, 4 digits, 1 letter.
#     """

# def get_passport_extraction_prompt():
#     return """
#     Analyze this passport image and extract the following information in JSON format:
    
#     {
#         "name": "Full name",
#         "passport_number": "Passport number",
#         "dob": "Date of birth in DD/MM/YYYY format",
#         "expiry_date": "Expiry date in DD/MM/YYYY format",
#         "country_code": "Country code",
#         "nationality": "Nationality",
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity"
#     }
    
#     If any information is not clearly visible or extractable, use "Not Extracted" as the value.
#     """

# def get_driving_license_extraction_prompt():
#     return """
#     Analyze this driving license image and extract the following information in JSON format:
    
#     {
#         "name": "Full name",
#         "license_number": "License number",
#         "dob": "Date of birth in DD/MM/YYYY format",
#         "expiry_date": "Expiry date in DD/MM/YYYY format",
#         "address": "Address",
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity"
#     }
    
#     If any information is not clearly visible or extractable, use "Not Extracted" as the value.
#     """

# def get_address_proof_extraction_prompt():
#     return """
#     Analyze this address proof document and extract the following information in JSON format:
    
#     {
#         "name": "Name of the person/consumer",
#         "address": "Complete address",
#         "date": "Document date in DD/MM/YYYY format",
#         "document_type": "Type of document (electricity bill, bank statement, etc.)",
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity",
#         "complete_address_visible": "true if complete address is clearly visible, false otherwise"
#     }
    
#     If any information is not clearly visible or extractable, use "Not Extracted" as the value.
#     """

# def get_bill_extraction_prompt():
#     return """
#     Analyze this utility bill image and extract the following information in JSON format:
    
#     {
#         "consumer_name": "Name of the consumer",
#         "address": "Service address",
#         "bill_date": "Bill date in DD/MM/YYYY format",
#         "due_date": "Due date in DD/MM/YYYY format",
#         "bill_amount": "Bill amount",
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity"
#     }
    
#     If any information is not clearly visible or extractable, use "Not Extracted" as the value.
#     """

# def get_passport_photo_extraction_prompt():
#     return """
#     Analyze this passport-style photograph and provide the following assessment in JSON format:
    
#     {
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity",
#         "is_passport_style": "true if it meets passport photo standards, false otherwise",
#         "face_visible": "true if face is clearly visible, false otherwise",
#         "background_appropriate": "true if background is plain and appropriate, false otherwise",
#         "resolution_adequate": "true if resolution is sufficient, false otherwise"
#     }
    
#     Passport photo standards: plain background, face clearly visible, appropriate lighting, no shadows.
#     """

# def get_signature_extraction_prompt():
#     return """
#     Analyze this signature image and provide the following assessment in JSON format:
    
#     {
#         "clarity_score": "Float between 0.0 and 1.0 indicating signature clarity",
#         "is_handwritten": "true if appears to be handwritten, false otherwise",
#         "is_complete": "true if signature appears complete, false otherwise",
#         "background_clean": "true if background is clean, false otherwise"
#     }
    
#     Assess the overall quality and authenticity indicators of the signature.
#     """

# def get_noc_extraction_prompt():
#     return """
#     Analyze this No Objection Certificate (NOC) document and extract the following information in JSON format:
    
#     {
#         "owner_name": "Property owner's name",
#         "property_address": "Property address",
#         "applicant_name": "Name of the applicant seeking NOC",
#         "date": "Document date in DD/MM/YYYY format",
#         "purpose": "Purpose for which NOC is granted",
#         "has_signature": "true if owner's signature is present, false otherwise",
#         "clarity_score": "Float between 0.0 and 1.0 indicating document clarity",
#         "is_valid_noc": "true if document appears to be a valid NOC, false otherwise"
#     }
    
#     If any information is not clearly visible or extractable, use "Not Extracted" as the value.
#     Look for key NOC elements: property owner consent, clear property description, purpose statement.
#     """

# def get_generic_extraction_prompt():
#     return """
#     Analyze this document image and extract any clearly visible text information in JSON format:
    
#     {
#         "document_type": "Identified type of document if recognizable",
#         "extracted_text": "Any clearly visible text content",
#         "clarity_score": "Float between 0.0 and 1.0 indicating image clarity",
#         "is_readable": "true if document is generally readable, false otherwise"
#     }
    
#     Focus on extracting any structured information that might be useful for document validation.
#     """