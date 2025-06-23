from datetime import datetime
import json
import traceback
from typing import Dict, Any, Tuple
import base64
from services.validation_service import DocumentValidationService
from models.document_models import (
    ValidationResult, 
    DocumentValidationError
)
from utils.logging_utils import logger
from config.settings import Config

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('document_validation.log'),
        logging.StreamHandler()
    ]
)

class DocumentValidationAPI:
    """
    Document Validation API Endpoint
    """
    
    def __init__(
        self, 
        validation_service: DocumentValidationService = None
    ):
        """
        Initialize API endpoint
        
        Args:
            validation_service (DocumentValidationService, optional): 
                Custom validation service
        """
        self.logger = logging.getLogger(__name__)
        self.validation_service = validation_service or DocumentValidationService()
    
    def validate_document(self, input_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Main document validation endpoint
        
        Args:
            input_data (dict): Input document data
        
        Returns:
            tuple: (standard_result, detailed_result)
        """
        try:
            # Validate input structure
            self._validate_input_structure(input_data)
            
            # Extract parameters
            service_id = input_data.get('service_id', '1')
            request_id = input_data.get('request_id', '')
            
            # Perform validation
            result, detailed_result = self.validation_service.validate_documents(
                service_id, 
                request_id, 
                input_data
            )
            
            # Format the result for API response
            formatted_result = self._format_api_response(result, detailed_result)
            
            # Return both the API formatted result and the detailed result
            return formatted_result, detailed_result
        
        except Exception as e:
            self.logger.error(f"Validation API error: {str(e)}", exc_info=True)
            
            # Create error response
            error_response = {
                "validation_rules": {
                    "global_error": {
                        "status": "failed",
                        "error_message": str(e)
                    }
                },
                "document_validation": {
                    "directors": {},
                    "companyDocuments": {}
                }
            }
            
            # Create detailed error response
            detailed_error = {
                "validation_rules": {
                    "global_error": {
                        "status": "failed",
                        "error_message": str(e),
                        "stacktrace": traceback.format_exc()
                    }
                },
                "document_validation": {
                    "directors": {},
                    "companyDocuments": {}
                },
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e)
                }
            }
            
            return error_response, detailed_error
    
    def _validate_input_structure(self, input_data: Dict[str, Any]):
        """
        Validate the structure of input data
        
        Args:
            input_data (dict): Input document data
        
        Raises:
            DocumentValidationError: If input structure is invalid
        """
        # Debug print
        print("DEBUG: Validating input structure")
        print("DEBUG: Input data keys:", list(input_data.keys()))
        
        # Check for required top-level keys
        required_keys = ['directors']
        
        for key in required_keys:
            if key not in input_data:
                raise DocumentValidationError(
                    f"Missing required input field: {key}"
                )
        
        # Validate directors structure
        directors = input_data['directors']
        print("DEBUG: Number of directors:", len(directors))
        
        if not isinstance(directors, dict):
            raise DocumentValidationError(
                "Directors must be a dictionary"
            )
        
        # Allow optional companyDocuments
        company_docs = input_data.get('companyDocuments', {})
        print("DEBUG: Company documents:", company_docs)
        
        # Validate each director
        for director_key, director_info in directors.items():
            print(f"DEBUG: Validating director {director_key}")
            
            # Ensure director_info is a dictionary
            if not isinstance(director_info, dict):
                raise DocumentValidationError(
                    f"Director {director_key} must be a dictionary"
                )
            
            # Print director info for debugging
            print(f"DEBUG: Director {director_key} info:", director_info)
            
            # Check for required director keys
            required_director_keys = [
                'nationality', 
                'authorised', 
                'documents'
            ]
            
            for req_key in required_director_keys:
                if req_key not in director_info:
                    raise DocumentValidationError(
                        f"Missing required field for director {director_key}: {req_key}"
                    )
            
            # Validate documents
            documents = director_info.get('documents', {})
            if not isinstance(documents, dict):
                raise DocumentValidationError(
                    f"Documents for director {director_key} must be a dictionary"
                )
            
            # Optional: Add more specific document validation if needed
            for doc_key, doc_content in documents.items():
                if doc_content is not None and not isinstance(doc_content, str):
                    raise DocumentValidationError(
                        f"Document URL for {doc_key} in director {director_key} must be a base64-encoded string"
                    )
                try:
                    if doc_content:
                        base64.b64decode(doc_content)
                except Exception:
                    raise DocumentValidationError(
                        f"Invalid base64 content for document {doc_key} in director {director_key}"
                    )
        # Optional: Validate company documents structure if present
        if company_docs:
            if not isinstance(company_docs, dict):
                raise DocumentValidationError(
                    "Company documents must be a dictionary"
                )
            for key, content in company_docs.items():
                if key == "address_proof_type":  # this is not a document
                    continue
                if content is not None and not isinstance(content, str):
                    raise DocumentValidationError(
                        f"Company document {key} must be a base64-encoded string"
                    )
                try:
                    if content:
                        base64.b64decode(content)
                except Exception:
                    raise DocumentValidationError(f"Invalid base64 content in {key}")
            
    
    def _format_api_response(self, result: Dict[str, Any], detailed_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format the validation results into the required API response schema
        
        Args:
            result (dict): Original validation result
            detailed_result (dict): Detailed validation result
                
        Returns:
            dict: Formatted API response
        """
        # Debug logging
        self.logger.debug(f"Formatting API response from validation results")
        
        # Initialize the response structure
        api_response = {
            "validation_rules": {},
            "document_validation": {
                "directors": {},
                "companyDocuments": {}
            }
        }
        
        # Print detailed info for debugging
        print("DEBUG: Standard result validation rules:", json.dumps(result.get('validation_rules', {}), indent=2))
        print("DEBUG: Detailed result:", json.dumps(detailed_result.get('metadata', {}), indent=2))
        
        # Use validation rules directly from the result if available
        validation_rules = result.get('validation_rules', {})
        
        # Add validation rules to API response
        api_response["validation_rules"] = validation_rules
        
        # Process directors with robust error handling
        directors_data = result.get('document_validation', {}).get('directors', {})
        if not isinstance(directors_data, dict):
            self.logger.error(f"Expected directors_data to be a dictionary, got {type(directors_data)}")
            directors_data = {}  # Convert to empty dict to avoid further errors
        
        for director_id, director_data in directors_data.items():
            # Skip special keys like 'global_errors' or 'rule_validations'
            if director_id in ['global_errors', 'rule_validations']:
                continue
                
            # Type check for director_data
            if not isinstance(director_data, dict):
                self.logger.warning(f"Director data for {director_id} is not a dictionary, got {type(director_data)}. Skipping.")
                continue
            
            # Initialize director entry
            api_response["document_validation"]["directors"][director_id] = {
                "nationality": director_data.get('nationality', 'Unknown'),
                "documents": {}
            }
            
            # Add authorized status if available
            if 'is_authorised' in director_data:
                api_response["document_validation"]["directors"][director_id]["authorized"] = director_data.get('is_authorised', False)
            
            # Process director documents with type checking
            documents = director_data.get('documents', {})
            if not isinstance(documents, dict):
                self.logger.warning(f"Documents for director {director_id} is not a dictionary, got {type(documents)}. Skipping.")
                continue
                    
            for doc_id, doc_data in documents.items():
                # Type check for document data
                if not isinstance(doc_data, dict):
                    self.logger.warning(f"Document data for {doc_id} in director {director_id} is not a dictionary, got {type(doc_data)}. Skipping.")
                    continue
                    
                # Determine document status
                is_valid = doc_data.get('is_valid', False)
                status = "Valid" if is_valid else "Not Valid"
                
                # Get error messages
                error_messages = []
                if 'error' in doc_data:
                    error_messages.append(doc_data['error'])
                
                # Add extraction errors if available
                extracted_data = doc_data.get('extracted_data', {})
                if isinstance(extracted_data, dict) and 'error_message' in extracted_data:
                    error_messages.append(extracted_data['error_message'])
                
                # For invalid documents without specific errors, add a generic message
                if not is_valid and not error_messages:
                    error_messages.append("Verification failed")
                
                # Add document to response
                api_response["document_validation"]["directors"][director_id]["documents"][doc_id] = {
                    "status": status,
                    "error_messages": error_messages
                }
        
        # Process company documents with type checking
        company_docs = result.get('document_validation', {}).get('companyDocuments', {})
        if not isinstance(company_docs, dict):
            self.logger.warning(f"Company documents is not a dictionary, got {type(company_docs)}. Skipping.")
            company_docs = {}
        
        # Process address proof
        if 'addressProof' in company_docs:
            address_proof = company_docs.get('addressProof', {})
            if not isinstance(address_proof, dict):
                self.logger.warning(f"Address proof is not a dictionary, got {type(address_proof)}. Using default values.")
                address_proof = {}
                    
            status = "Valid" if address_proof.get('is_valid', False) else "Not Valid"
            
            error_messages = []
            if 'error' in address_proof:
                error_messages.append(address_proof['error'])
            
            # Add validation errors if available
            validation_errors = company_docs.get('validation_errors', [])
            for error in validation_errors:
                if error not in error_messages and "owner" not in error.lower():
                    error_messages.append(error)
            
            api_response["document_validation"]["companyDocuments"]["addressProof"] = {
                "status": status,
                "error_messages": error_messages
            }
        
        # Process NOC if available
        if 'noc' in company_docs:
            noc = company_docs.get('noc', {})
            if not isinstance(noc, dict):
                self.logger.warning(f"NOC is not a dictionary, got {type(noc)}. Using default values.")
                noc = {}
                    
            status = "Valid" if noc.get('is_valid', False) else "Not Valid"
            
            error_messages = []
            if 'error' in noc:
                error_messages.append(noc['error'])
            
            # Add owner-related validation errors
            validation_errors = company_docs.get('validation_errors', [])
            for error in validation_errors:
                if error not in error_messages and "owner" in error.lower():
                    error_messages.append(error)
            
            api_response["document_validation"]["companyDocuments"]["noc"] = {
                "status": status,
                "error_messages": error_messages
            }
        
        # Final logging
        self.logger.debug(f"API response formatted with {len(api_response['validation_rules'])} validation rules")
        print("DEBUG: Formatted API response:", json.dumps(api_response['validation_rules'], indent=2))
        
        return api_response
    
    def process_input_file(self, file_path: str) -> Dict[str, Any]:
        """
        Process input from a JSON file
        
        Args:
            file_path (str): Path to input JSON file
        
        Returns:
            dict: Validation results
        """
        try:
            with open(file_path, 'r') as file:
                input_data = json.load(file)
            
            api_response, _ = self.validate_document(input_data)
            return api_response
        
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in file: {file_path}")
            return self._create_error_response("Invalid JSON file")
        
        except FileNotFoundError:
            logger.error(f"Input file not found: {file_path}")
            return self._create_error_response("Input file not found")
        
        except Exception as e:
            logger.error(f"Error processing input file: {e}")
            return self._create_error_response(str(e))
    
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """
        Create a standardized error response
        
        Args:
            error_message (str): Error description
        
        Returns:
            dict: Formatted error response
        """
        return {
            "validation_rules": {
                "global_error": {
                    "status": "failed",
                    "error_message": error_message
                }
            },
            "document_validation": {
                "directors": {},
                "companyDocuments": {}
            }
        }

# from datetime import datetime
# import json
# import traceback
# import base64
# from typing import Dict, Any, Tuple
# from io import BytesIO

# from services.validation_service import DocumentValidationService
# from models.document_models import (
#     ValidationResult, 
#     DocumentValidationError
# )
# from utils.logging_utils import logger
# from config.settings import Config

# import logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('document_validation.log'),
#         logging.StreamHandler()
#     ]
# )

# class DocumentValidationAPI:
#     def __init__(self, validation_service: DocumentValidationService = None):
#         self.logger = logging.getLogger(__name__)
#         self.validation_service = validation_service or DocumentValidationService()

#     def validate_document(self, input_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
#         try:
#             self._validate_input_structure(input_data)
#             service_id = input_data.get('service_id', '1')
#             request_id = input_data.get('request_id', '')

#             result, detailed_result = self.validation_service.validate_documents(
#                 service_id, request_id, input_data
#             )

#             formatted_result = self._format_api_response(result, detailed_result)
#             return formatted_result, detailed_result

#         except Exception as e:
#             self.logger.error(f"Validation API error: {str(e)}", exc_info=True)

#             error_response = {
#                 "validation_rules": {
#                     "global_error": {
#                         "status": "failed",
#                         "error_message": str(e)
#                     }
#                 },
#                 "document_validation": {
#                     "directors": {},
#                     "companyDocuments": {}
#                 }
#             }

#             detailed_error = {
#                 "validation_rules": {
#                     "global_error": {
#                         "status": "failed",
#                         "error_message": str(e),
#                         "stacktrace": traceback.format_exc()
#                     }
#                 },
#                 "document_validation": {
#                     "directors": {},
#                     "companyDocuments": {}
#                 },
#                 "metadata": {
#                     "timestamp": datetime.now().isoformat(),
#                     "error": str(e)
#                 }
#             }

#             return error_response, detailed_error

#     def _validate_input_structure(self, input_data: Dict[str, Any]):
#         required_keys = ['directors']
#         for key in required_keys:
#             if key not in input_data:
#                 raise DocumentValidationError(f"Missing required input field: {key}")

#         directors = input_data['directors']
#         if not isinstance(directors, dict):
#             raise DocumentValidationError("Directors must be a dictionary")

#         for director_key, director_info in directors.items():
#             if not isinstance(director_info, dict):
#                 raise DocumentValidationError(f"Director {director_key} must be a dictionary")

#             required_director_keys = ['nationality', 'authorised', 'documents']
#             for req_key in required_director_keys:
#                 if req_key not in director_info:
#                     raise DocumentValidationError(f"Missing required field for director {director_key}: {req_key}")

#             documents = director_info.get('documents', {})
#             if not isinstance(documents, dict):
#                 raise DocumentValidationError(f"Documents for director {director_key} must be a dictionary")

#             for doc_key, doc_data in documents.items():
#                 if not doc_data or not isinstance(doc_data, str) or doc_data.strip() == "":
#                     continue
#                 if not isinstance(doc_data, str):
#                     raise DocumentValidationError(f"Document for {doc_key} in director {director_key} must be a base64 string")
#                 try:
                    
#                     base64.b64decode(doc_data)
#                 except Exception:
#                     raise DocumentValidationError(f"Invalid base64 encoding for {doc_key} in director {director_key}")

#         company_docs = input_data.get('companyDocuments', {})
#         if company_docs:
#             if not isinstance(company_docs, dict):
#                 raise DocumentValidationError("Company documents must be a dictionary")

#             required_company_doc_keys = ['addressProof']
#             for req_key in required_company_doc_keys:
#                 if req_key not in company_docs:
#                     raise DocumentValidationError(f"Missing required field in company documents: {req_key}")
#                 if not isinstance(company_docs[req_key], str):
#                     raise DocumentValidationError(f"Company document {req_key} must be a base64 string")
#                 doc_data = company_docs.get(req_key)
#                 if doc_data is None or not isinstance(doc_data, str) or doc_data.strip() == "":
#                     continue  # Skip empty company doc

#                 try:
#                     base64.b64decode(doc_data)
#                 except Exception:
#                     raise DocumentValidationError(f"Invalid base64 encoding in company document: {req_key}")

#     def _format_api_response(self, result: Dict[str, Any], detailed_result: Dict[str, Any]) -> Dict[str, Any]:
#         api_response = {
#             "validation_rules": result.get("validation_rules", {}),
#             "document_validation": {
#                 "directors": {},
#                 "companyDocuments": {}
#             }
#         }

#         # Process directors
#         directors = result.get("document_validation", {}).get("directors", {})
#         for dir_key, dir_val in directors.items():
#             if dir_key in ['global_errors', 'rule_validations']:
#                 continue
#             api_response["document_validation"]["directors"][dir_key] = {
#                 "nationality": dir_val.get("nationality", ""),
#                 "authorized": dir_val.get("is_authorised", False),
#                 "documents": {}
#             }
#             docs = dir_val.get("documents", {})
#             for doc_key, doc_val in docs.items():
#                 status = "Valid" if doc_val.get("is_valid", False) else "Not Valid"
#                 errors = []
#                 if doc_val.get("error"):
#                     errors.append(doc_val["error"])
#                 if doc_val.get("extracted_data", {}).get("error_message"):
#                     errors.append(doc_val["extracted_data"]["error_message"])
#                 if not doc_val.get("is_valid", False) and not errors:
#                     errors.append("Verification failed")
#                 api_response["document_validation"]["directors"][dir_key]["documents"][doc_key] = {
#                     "status": status,
#                     "error_messages": errors
#                 }

#         # Process company documents
#         company_docs = result.get("document_validation", {}).get("companyDocuments", {})
#         for doc_key in ["addressProof", "noc"]:
#             if doc_key in company_docs:
#                 doc_val = company_docs.get(doc_key, {})
#                 if not isinstance(doc_val, dict):
#                     doc_val = {}
#                 status = "Valid" if doc_val.get("is_valid", False) else "Not Valid"
#                 errors = []
#                 if "error" in doc_val:
#                     errors.append(doc_val["error"])
#                 for err in company_docs.get("validation_errors", []):
#                     if err not in errors:
#                         errors.append(err)
#                 api_response["document_validation"]["companyDocuments"][doc_key] = {
#                     "status": status,
#                     "error_messages": errors
#                 }

#         return api_response


# from datetime import datetime
# import json
# import traceback
# from typing import Dict, Any, Tuple

# from services.validation_service import DocumentValidationService
# from models.document_models import (
#     ValidationResult, 
#     DocumentValidationError
# )
# from utils.logging_utils import logger
# from config.settings import Config

# import logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('document_validation.log'),
#         logging.StreamHandler()
#     ]
# )

# class DocumentValidationAPI:
#     """
#     Document Validation API Endpoint
#     """
    
#     def __init__(
#         self, 
#         validation_service: DocumentValidationService = None
#     ):
#         """
#         Initialize API endpoint
        
#         Args:
#             validation_service (DocumentValidationService, optional): 
#                 Custom validation service
#         """
#         self.logger = logging.getLogger(__name__)
#         self.validation_service = validation_service or DocumentValidationService()
    
#     def validate_document(self, input_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
#         """
#         Main document validation endpoint
        
#         Args:
#             input_data (dict): Input document data
        
#         Returns:
#             tuple: (standard_result, detailed_result)
#         """
#         try:
#             # Validate input structure
#             self._validate_input_structure(input_data)
            
#             # Extract parameters
#             service_id = input_data.get('service_id', '1')
#             request_id = input_data.get('request_id', '')
            
#             # Perform validation
#             result, detailed_result = self.validation_service.validate_documents(
#                 service_id, 
#                 request_id, 
#                 input_data
#             )
            
#             # Format the result for API response
#             formatted_result = self._format_api_response(result, detailed_result)
            
#             # Return both the API formatted result and the detailed result
#             return formatted_result, detailed_result
        
#         except Exception as e:
#             self.logger.error(f"Validation API error: {str(e)}", exc_info=True)
            
#             # Create error response
#             error_response = {
#                 "validation_rules": {
#                     "global_error": {
#                         "status": "failed",
#                         "error_message": str(e)
#                     }
#                 },
#                 "document_validation": {
#                     "directors": {},
#                     "companyDocuments": {}
#                 }
#             }
            
#             # Create detailed error response
#             detailed_error = {
#                 "validation_rules": {
#                     "global_error": {
#                         "status": "failed",
#                         "error_message": str(e),
#                         "stacktrace": traceback.format_exc()
#                     }
#                 },
#                 "document_validation": {
#                     "directors": {},
#                     "companyDocuments": {}
#                 },
#                 "metadata": {
#                     "timestamp": datetime.now().isoformat(),
#                     "error": str(e)
#                 }
#             }
            
#             return error_response, detailed_error
    
#     def _validate_input_structure(self, input_data: Dict[str, Any]):
#         """
#         Validate the structure of input data
        
#         Args:
#             input_data (dict): Input document data
        
#         Raises:
#             DocumentValidationError: If input structure is invalid
#         """
#         # Debug print
#         print("DEBUG: Validating input structure")
#         print("DEBUG: Input data keys:", list(input_data.keys()))
        
#         # Check for required top-level keys
#         required_keys = ['directors']
        
#         for key in required_keys:
#             if key not in input_data:
#                 raise DocumentValidationError(
#                     f"Missing required input field: {key}"
#                 )
        
#         # Validate directors structure
#         directors = input_data['directors']
#         print("DEBUG: Number of directors:", len(directors))
        
#         if not isinstance(directors, dict):
#             raise DocumentValidationError(
#                 "Directors must be a dictionary"
#             )
        
#         # Allow optional companyDocuments
#         company_docs = input_data.get('companyDocuments', {})
#         print("DEBUG: Company documents:", company_docs)
        
#         # Validate each director
#         for director_key, director_info in directors.items():
#             print(f"DEBUG: Validating director {director_key}")
            
#             # Ensure director_info is a dictionary
#             if not isinstance(director_info, dict):
#                 raise DocumentValidationError(
#                     f"Director {director_key} must be a dictionary"
#                 )
            
#             # Print director info for debugging
#             print(f"DEBUG: Director {director_key} info:", director_info)
            
#             # Check for required director keys
#             required_director_keys = [
#                 'nationality', 
#                 'authorised', 
#                 'documents'
#             ]
            
#             for req_key in required_director_keys:
#                 if req_key not in director_info:
#                     raise DocumentValidationError(
#                         f"Missing required field for director {director_key}: {req_key}"
#                     )
            
#             # Validate documents
#             documents = director_info.get('documents', {})
#             if not isinstance(documents, dict):
#                 raise DocumentValidationError(
#                     f"Documents for director {director_key} must be a dictionary"
#                 )
            
#             # Optional: Add more specific document validation if needed
#             for doc_key, doc_url in documents.items():
#                 if not isinstance(doc_url, str):
#                     raise DocumentValidationError(
#                         f"Document URL for {doc_key} in director {director_key} must be a string"
#                     )
        
#         # Optional: Validate company documents structure if present
#         if company_docs:
#             if not isinstance(company_docs, dict):
#                 raise DocumentValidationError(
#                     "Company documents must be a dictionary"
#                 )
            
#             # Check for required company document keys if needed
#             required_company_doc_keys = ['addressProof']
            
#             for req_key in required_company_doc_keys:
#                 if req_key not in company_docs:
#                     raise DocumentValidationError(
#                         f"Missing required field in company documents: {req_key}"
#                     )
    
#     def _format_api_response(self, result: Dict[str, Any], detailed_result: Dict[str, Any]) -> Dict[str, Any]:
#         """
#         Format the validation results into the required API response schema
        
#         Args:
#             result (dict): Original validation result
#             detailed_result (dict): Detailed validation result
                
#         Returns:
#             dict: Formatted API response
#         """
#         # Debug logging
#         self.logger.debug(f"Formatting API response from validation results")
        
#         # Initialize the response structure
#         api_response = {
#             "validation_rules": {},
#             "document_validation": {
#                 "directors": {},
#                 "companyDocuments": {}
#             }
#         }
        
#         # Print detailed info for debugging
#         print("DEBUG: Standard result validation rules:", json.dumps(result.get('validation_rules', {}), indent=2))
#         print("DEBUG: Detailed result:", json.dumps(detailed_result.get('metadata', {}), indent=2))
        
#         # Use validation rules directly from the result if available
#         validation_rules = result.get('validation_rules', {})
        
#         # Add validation rules to API response
#         api_response["validation_rules"] = validation_rules
        
#         # Process directors with robust error handling
#         directors_data = result.get('document_validation', {}).get('directors', {})
#         if not isinstance(directors_data, dict):
#             self.logger.error(f"Expected directors_data to be a dictionary, got {type(directors_data)}")
#             directors_data = {}  # Convert to empty dict to avoid further errors
        
#         for director_id, director_data in directors_data.items():
#             # Skip special keys like 'global_errors' or 'rule_validations'
#             if director_id in ['global_errors', 'rule_validations']:
#                 continue
                
#             # Type check for director_data
#             if not isinstance(director_data, dict):
#                 self.logger.warning(f"Director data for {director_id} is not a dictionary, got {type(director_data)}. Skipping.")
#                 continue
            
#             # Initialize director entry
#             api_response["document_validation"]["directors"][director_id] = {
#                 "nationality": director_data.get('nationality', 'Unknown'),
#                 "documents": {}
#             }
            
#             # Add authorized status if available
#             if 'is_authorised' in director_data:
#                 api_response["document_validation"]["directors"][director_id]["authorized"] = director_data.get('is_authorised', False)
            
#             # Process director documents with type checking
#             documents = director_data.get('documents', {})
#             if not isinstance(documents, dict):
#                 self.logger.warning(f"Documents for director {director_id} is not a dictionary, got {type(documents)}. Skipping.")
#                 continue
                    
#             for doc_id, doc_data in documents.items():
#                 # Type check for document data
#                 if not isinstance(doc_data, dict):
#                     self.logger.warning(f"Document data for {doc_id} in director {director_id} is not a dictionary, got {type(doc_data)}. Skipping.")
#                     continue
                    
#                 # Determine document status
#                 is_valid = doc_data.get('is_valid', False)
#                 status = "Valid" if is_valid else "Not Valid"
                
#                 # Get error messages
#                 error_messages = []
#                 if 'error' in doc_data:
#                     error_messages.append(doc_data['error'])
                
#                 # Add extraction errors if available
#                 extracted_data = doc_data.get('extracted_data', {})
#                 if isinstance(extracted_data, dict) and 'error_message' in extracted_data:
#                     error_messages.append(extracted_data['error_message'])
                
#                 # For invalid documents without specific errors, add a generic message
#                 if not is_valid and not error_messages:
#                     error_messages.append("Verification failed")
                
#                 # Add document to response
#                 api_response["document_validation"]["directors"][director_id]["documents"][doc_id] = {
#                     "status": status,
#                     "error_messages": error_messages
#                 }
        
#         # Process company documents with type checking
#         company_docs = result.get('document_validation', {}).get('companyDocuments', {})
#         if not isinstance(company_docs, dict):
#             self.logger.warning(f"Company documents is not a dictionary, got {type(company_docs)}. Skipping.")
#             company_docs = {}
        
#         # Process address proof
#         if 'addressProof' in company_docs:
#             address_proof = company_docs.get('addressProof', {})
#             if not isinstance(address_proof, dict):
#                 self.logger.warning(f"Address proof is not a dictionary, got {type(address_proof)}. Using default values.")
#                 address_proof = {}
                    
#             status = "Valid" if address_proof.get('is_valid', False) else "Not Valid"
            
#             error_messages = []
#             if 'error' in address_proof:
#                 error_messages.append(address_proof['error'])
            
#             # Add validation errors if available
#             validation_errors = company_docs.get('validation_errors', [])
#             for error in validation_errors:
#                 if error not in error_messages and "owner" not in error.lower():
#                     error_messages.append(error)
            
#             api_response["document_validation"]["companyDocuments"]["addressProof"] = {
#                 "status": status,
#                 "error_messages": error_messages
#             }
        
#         # Process NOC if available
#         if 'noc' in company_docs:
#             noc = company_docs.get('noc', {})
#             if not isinstance(noc, dict):
#                 self.logger.warning(f"NOC is not a dictionary, got {type(noc)}. Using default values.")
#                 noc = {}
                    
#             status = "Valid" if noc.get('is_valid', False) else "Not Valid"
            
#             error_messages = []
#             if 'error' in noc:
#                 error_messages.append(noc['error'])
            
#             # Add owner-related validation errors
#             validation_errors = company_docs.get('validation_errors', [])
#             for error in validation_errors:
#                 if error not in error_messages and "owner" in error.lower():
#                     error_messages.append(error)
            
#             api_response["document_validation"]["companyDocuments"]["noc"] = {
#                 "status": status,
#                 "error_messages": error_messages
#             }
        
#         # Final logging
#         self.logger.debug(f"API response formatted with {len(api_response['validation_rules'])} validation rules")
#         print("DEBUG: Formatted API response:", json.dumps(api_response['validation_rules'], indent=2))
        
#         return api_response
    
#     def process_input_file(self, file_path: str) -> Dict[str, Any]:
#         """
#         Process input from a JSON file
        
#         Args:
#             file_path (str): Path to input JSON file
        
#         Returns:
#             dict: Validation results
#         """
#         try:
#             with open(file_path, 'r') as file:
#                 input_data = json.load(file)
            
#             api_response, _ = self.validate_document(input_data)
#             return api_response
        
#         except json.JSONDecodeError:
#             logger.error(f"Invalid JSON in file: {file_path}")
#             return self._create_error_response("Invalid JSON file")
        
#         except FileNotFoundError:
#             logger.error(f"Input file not found: {file_path}")
#             return self._create_error_response("Input file not found")
        
#         except Exception as e:
#             logger.error(f"Error processing input file: {e}")
#             return self._create_error_response(str(e))
    
#     def _create_error_response(self, error_message: str) -> Dict[str, Any]:
#         """
#         Create a standardized error response
        
#         Args:
#             error_message (str): Error description
        
#         Returns:
#             dict: Formatted error response
#         """
#         return {
#             "validation_rules": {
#                 "global_error": {
#                     "status": "failed",
#                     "error_message": error_message
#                 }
#             },
#             "document_validation": {
#                 "directors": {},
#                 "companyDocuments": {}
#             }
#         }