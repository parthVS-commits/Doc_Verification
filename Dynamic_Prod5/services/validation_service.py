import logging
import time
from datetime import datetime, timedelta
import traceback
from typing import Dict, Any, Optional, List, Tuple
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from dateutil import parser
import re
import json
import base64
import tempfile
import os

from services.extraction_service import ExtractionService
from utils.elasticsearch_utils import ElasticsearchClient
from utils.aadhar_pan_linkage import AadharPanLinkageService
from config.settings import Config
from models.document_models import (
    ValidationResult, 
    DocumentValidationError,
    ValidationRuleStatus
)
from rules.compliance_validation_rules import ComplianceValidationRules


class DocumentValidationService:
    """
    Comprehensive document validation service
    """
    
    def __init__(
        self, 
        es_client: Optional[ElasticsearchClient] = None,
        extraction_service: Optional[ExtractionService] = None
    ):
        """
        Initialize the validation service
        
        Args:
            es_client (ElasticsearchClient, optional): Elasticsearch client
            extraction_service (ExtractionService, optional): Document extraction service
        """
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        
        # Initialize services
        self.es_client = es_client or ElasticsearchClient()
        self.extraction_service = extraction_service or ExtractionService(
            Config.OPENAI_API_KEY
        )
        self.aadhar_pan_linkage_service = AadharPanLinkageService()

    def _get_compliance_rules(self, service_id: str) -> Dict:
        """
        Retrieve compliance rules for a service
        
        Args:
            service_id (str): Service identifier
        
        Returns:
            dict: Compliance rules
        """
        try:
            # Add explicit None check
            if self.es_client is None:
                self.logger.warning("Elasticsearch client is None, using default rules")
                return self._get_default_compliance_rules()
            
            # Retrieve rules
            rules = self.es_client.get_compliance_rules(service_id)
            
            # Log full details for debugging
            self.logger.info(f"DEBUG: Retrieved rules for service ID {service_id}: {json.dumps(rules, indent=2)}")
            
            # Explicitly filter and find the matching rule set
            matching_rules = [
                rule_set for rule_set in rules 
                if str(rule_set.get('service_id')) == str(service_id)
            ]
            
            # Add additional logging
            self.logger.info(f"DEBUG: Matching rules found: {len(matching_rules)}")
            
            # If matching rules found, return the first one
            if matching_rules:
                selected_rules = matching_rules[0]
                
                # CRITICAL: ALWAYS return rules for the specific service ID
                return {
                    "service_id": service_id,
                    "service_name": selected_rules.get('service_name', 'Unknown Service'),
                    "rules": selected_rules.get('rules', [])
                }
            
            # If no matching rules, log warning and use default
            self.logger.warning(f"No compliance rules found for service ID: {service_id}")
            default_rules = self._get_default_compliance_rules()
            
            # Override service ID in default rules
            default_rules['service_id'] = service_id
            default_rules['service_name'] = f"Default Rules for Service {service_id}"
            
            return default_rules
        
        except Exception as e:
            self.logger.error(f"Error retrieving compliance rules: {e}")
            self.logger.info("Using default compliance rules")
            default_rules = self._get_default_compliance_rules()
            default_rules['service_id'] = service_id
            default_rules['service_name'] = f"Default Rules for Service {service_id}"
            return default_rules
        
        
    def format_validation_results(self, standard_result: Dict) -> str:
        """Format validation results for display"""
        output = []
        output.append("==== Comprehensive Validation Results ====")
        
        # Overall Status
        overall_status = "✅ Passed" if standard_result.get('metadata', {}).get('is_compliant', False) else "❌ Failed"
        output.append(f"Overall Compliance Status: {overall_status}")
        
        # Rule Validations
        output.append("\n=== Rule Validations ===")
        for rule_name, rule_info in standard_result.get('validation_rules', {}).items():
            status = "✅" if rule_info.get('status') == 'passed' else "❌"
            error = f"\n   Error: {rule_info.get('error_message')}" if rule_info.get('error_message') else ""
            output.append(f"{rule_name}: {status}{error}")
        
        # Directors Validation
        output.append("\n=== Directors Validation ===")
        for director_key, director_info in standard_result.get('document_validation', {}).get('directors', {}).items():
            output.append(f"{director_key}:")
            output.append(f"  Nationality: {director_info.get('nationality', 'Unknown')}")
            output.append(f"  Authorized: {director_info.get('authorized', False)}")
            output.append("  Documents:")
            
            for doc_key, doc_info in director_info.get('documents', {}).items():
                status = "✅" if doc_info.get('status') == 'Valid' else "❌"
                reason = f" ({doc_info.get('reason')})" if doc_info.get('reason') else ""
                output.append(f"    {doc_key}: {status}{reason}")
        
        # Company Documents
        output.append("\n=== Company Documents ===")
        company_docs = standard_result.get('document_validation', {}).get('companyDocuments', {})
        
        # Address Proof
        address_status = "✅" if company_docs.get('addressProof', {}).get('status') == 'Valid' else "❌"
        address_reason = f" ({company_docs.get('addressProof', {}).get('reason')})" if company_docs.get('addressProof', {}).get('reason') else ""
        output.append(f"  Address Proof: {address_status}{address_reason}")
        
        # NOC
        noc_status = "✅" if company_docs.get('noc', {}).get('status') == 'Valid' else "❌"
        noc_reason = f" ({company_docs.get('noc', {}).get('reason')})" if company_docs.get('noc', {}).get('reason') else ""
        output.append(f"  NOC: {noc_status}{noc_reason}")
        
        return "\n".join(output)

    def _get_default_compliance_rules(self) -> Dict:
        """
        Get default compliance rules when Elasticsearch rules are unavailable
        
        Returns:
            dict: Default compliance rules
        """
        default_rules = {
            "rules": [
                {
                    "rule_id": "DIRECTOR_COUNT",
                    "rule_name": "Director Count",
                    "description": "Number of directors must be between 2 and 5",
                    "severity": "high",
                    "is_active": True,
                    "conditions": {
                        "min_directors": 2,
                        "max_directors": 5
                    }
                },
                {
                    "rule_id": "PASSPORT_PHOTO",
                    "rule_name": "Passport Photo",
                    "description": "Passport photo must be clear and properly formatted",
                    "severity": "medium",
                    "is_active": True,
                    "conditions": {
                        "min_clarity_score": 0.7,
                        "is_passport_style": True,
                        "face_visible": True
                    }
                },
                {
                    "rule_id": "SIGNATURE",
                    "rule_name": "Signature",
                    "description": "Signature must be clear and handwritten",
                    "severity": "medium",
                    "is_active": True,
                    "conditions": {
                        "min_clarity_score": 0.7,
                        "is_handwritten": True,
                        "is_complete": True
                    }
                },
                {
                    "rule_id": "ADDRESS_PROOF",
                    "rule_name": "Address Proof",
                    "description": "Address proof must be valid and recent",
                    "severity": "high",
                    "is_active": True,
                    "conditions": {
                        "max_age_days": 45,
                        "name_match_required": True,
                        "complete_address_required": True
                    }
                },
                {
                    "rule_id": "INDIAN_DIRECTOR_PAN",
                    "rule_name": "Indian Director PAN Card",
                    "description": "Indian directors must provide a valid PAN card",
                    "severity": "high",
                    "is_active": True,
                    "conditions": {
                        "min_age": 18
                    }
                },
                {
                    "rule_id": "INDIAN_DIRECTOR_AADHAR",
                    "rule_name": "Indian Director Aadhar Card",
                    "description": "Indian directors must provide valid Aadhar cards",
                    "severity": "high",
                    "is_active": True,
                    "conditions": {
                        "masked_not_allowed": True,
                        "different_images_required": True
                    }
                },
                {
                    "rule_id": "FOREIGN_DIRECTOR_DOCS",
                    "rule_name": "Foreign Director Documents",
                    "description": "Foreign directors must provide valid identification",
                    "severity": "high",
                    "is_active": True,
                    "conditions": {
                        "passport_required": True,
                        "passport_validity_check": True,
                        "driving_license_required": False
                    }
                },
                {
                    "rule_id": "COMPANY_ADDRESS_PROOF",
                    "rule_name": "Company Address Proof",
                    "description": "Company must have valid address proof",
                    "severity": "high",
                    "is_active": True,
                    "conditions": {
                        "max_age_days": 45,
                        "complete_address_required": True,
                        "name_match_required": False
                    }
                },
                {
                    "rule_id": "NOC_VALIDATION",
                    "rule_name": "No Objection Certificate",
                    "description": "NOC from property owner is required",
                    "severity": "medium",
                    "is_active": True,
                    "conditions": {
                        "noc_required": True,
                        "signature_required": True
                    }
                },
                {
                    "rule_id": "AADHAR_PAN_LINKAGE",
                    "rule_name": "Aadhar PAN Linkage",
                    "description": "Aadhar and PAN must be linked for Indian directors",
                    "severity": "high",
                    "is_active": True,
                    "conditions": {
                        "linkage_api_check_required": True
                    }
                }
            ]
        }
        
        self.logger.info(f"Using default compliance rules: {json.dumps(default_rules, indent=2)}")
        return default_rules
    
    # def validate_documents(
    #     self, 
    #     service_id: str, 
    #     request_id: str, 
    #     input_data: Dict[str, Any]
    # ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    #     """
    #     Main document validation method
    #     """
    #     start_time = time.time()
        
    #     try:
    #         # Retrieve compliance rules
    #         compliance_rules = self._get_compliance_rules(service_id)
            
    #         # Validate directors
    #         directors_validation = self._validate_directors(
    #             input_data.get('directors', {}), 
    #             compliance_rules
    #         )
            
    #         # Validate company documents
    #         company_docs_validation = self._validate_company_documents(
    #             input_data.get('companyDocuments', {}),
    #             input_data.get('directors', {}),
    #             compliance_rules
    #         )
            
    #         # Calculate processing time
    #         processing_time = time.time() - start_time
            
    #         # Ensure directors_validation is a dictionary
    #         if isinstance(directors_validation, list):
    #             directors_validation = {str(idx): info for idx, info in enumerate(directors_validation)}
            
    #         # Determine overall compliance
    #         is_compliant = all(
    #             director.get('is_valid', False) 
    #             for director in directors_validation.values() 
    #             if isinstance(director, dict)
    #         )
            
    #         # Prepare standard result with type checking
    #         standard_result = {
    #             "validation_rules": self._prepare_validation_rules(directors_validation, company_docs_validation),
    #             "document_validation": {
    #                 "directors": {
    #                     director_key: {
    #                         "nationality": director_info.get('nationality', 'Unknown'),
    #                         "authorized": director_info.get('is_authorised', False),
    #                         "documents": {
    #                             doc_key: {
    #                                 "status": self._get_document_status(doc_info),
    #                                 "reason": self._get_document_reason(doc_info)
    #                             } for doc_key, doc_info in director_info.get('documents', {}).items()
    #                         }
    #                     } for director_key, director_info in directors_validation.items() 
    #                     if isinstance(director_info, dict)
    #                 },
    #                 "companyDocuments": {
    #                     "addressProof": {
    #                         "status": "Valid" if company_docs_validation.get('is_valid', False) else "Not Valid",
    #                         "reason": company_docs_validation.get('validation_errors', [None])[0]
    #                     },
    #                     "noc": {
    #                         "status": "Valid" if company_docs_validation.get('noc', {}).get('is_valid', False) else "Not Valid",
    #                         "reason": None
    #                     }
    #                 }
    #             }
    #         }
            
    #         # Prepare detailed result
    #         detailed_result = {
    #             "validation_rules": self._prepare_detailed_validation_rules(directors_validation, company_docs_validation),
    #             "document_validation": {
    #                 "directors": directors_validation,
    #                 "companyDocuments": company_docs_validation
    #             },
    #             "metadata": {
    #                 "service_id": service_id,
    #                 "request_id": request_id,
    #                 "timestamp": datetime.now().isoformat(),
    #                 "processing_time": processing_time,
    #                 "is_compliant": is_compliant
    #             }
    #         }
            
    #         return standard_result, detailed_result
            
    #     except Exception as e:
    #         self.logger.error(f"Comprehensive validation error: {str(e)}", exc_info=True)
            
    #         # Prepare error results
    #         error_result = {
    #             "validation_rules": {
    #                 "global_error": {
    #                     "status": "failed",
    #                     "error_message": str(e)
    #                 }
    #             },
    #             "document_validation": {
    #                 "directors": {},
    #                 "companyDocuments": {}
    #             }
    #         }
            
    #         error_detailed_result = {
    #             "validation_rules": {
    #                 "global_error": {
    #                     "status": "failed",
    #                     "error_message": str(e),
    #                     "stacktrace": traceback.format_exc()
    #                 }
    #             },
    #             "document_validation": {
    #                 "directors": {},
    #                 "companyDocuments": {}
    #             },
    #             "metadata": {
    #                 "service_id": service_id,
    #                 "request_id": request_id,
    #                 "timestamp": datetime.now().isoformat(),
    #                 "error": str(e)
    #             }
    #         }
            
    #         return error_result, error_detailed_result
    def validate_documents(
        self, 
        service_id: str, 
        request_id: str, 
        input_data: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Main document validation method with FORCED service ID rule selection
        
        Args:
            service_id (str): Service identifier
            request_id (str): Unique request identifier
            input_data (Dict[str, Any]): Input validation data
        
        Returns:
            Tuple[Dict[str, Any], Dict[str, Any]]: Validation results
        """
        start_time = time.time()

        self._current_preconditions = input_data.get('preconditions', {})
        
        # CRITICAL: FORCE the service ID rules
        def force_service_id_rules(rules, target_service_id):
            """
            Forcibly select rules for a specific service ID
            
            Args:
                rules (list): Retrieved rules
                target_service_id (str): Target service ID
            
            Returns:
                dict: Selected rules for the target service
            """
            for rule_set in rules:
                if str(rule_set.get('service_id')) == str(target_service_id):
                    return {
                        "service_id": target_service_id,
                        "service_name": rule_set.get('service_name', f'Service {target_service_id}'),
                        "rules": rule_set.get('rules', [])
                    }
            
            # If no rules found, use default
            default_rules = self._get_default_compliance_rules()
            default_rules['service_id'] = target_service_id
            return default_rules

        try:
            # Retrieve ALL rules from Elasticsearch
            all_rules = self.es_client.get_compliance_rules(service_id)
            
            # FORCE selection of rules for specific service ID
            compliance_rules = force_service_id_rules(all_rules, service_id)
            
            # Log forced rule selection for debugging
            self.logger.info(f"FORCED Rule Selection for Service ID {service_id}: {json.dumps(compliance_rules, indent=2)}")
            
            # Extract preconditions if available
            preconditions = input_data.get('preconditions', {})

            # Validate directors
            directors_validation = self._validate_directors(
                input_data.get('directors', {}), 
                compliance_rules
            )
            
            # Validate company documents
            # company_docs_validation = self._validate_company_documents(
            #     input_data.get('companyDocuments', {}),
            #     input_data.get('directors', {}),
            #     compliance_rules,
            #     preconditions
            # )
            company_docs_validation = self._process_company_documents(
                input_data.get('companyDocuments', {})#,
                #input_data.get('directors', {}),
                #compliance_rules,
                #preconditions
            )
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Ensure directors_validation is a dictionary
            if isinstance(directors_validation, list):
                directors_validation = {str(idx): info for idx, info in enumerate(directors_validation)}
            
            # Determine overall compliance
            is_compliant = all(
                director.get('is_valid', False) 
                for director in directors_validation.values() 
                if isinstance(director, dict)
            )
            
            # Prepare standard result
            standard_result = {
                "validation_rules": self._prepare_validation_rules(directors_validation, company_docs_validation, compliance_rules),
                "document_validation": {
                    "directors": directors_validation,
                    "companyDocuments": company_docs_validation
                }
            }
            
            # Prepare detailed result
            detailed_result = {
                "validation_rules": self._prepare_detailed_validation_rules(directors_validation, company_docs_validation, compliance_rules),
                "document_validation": {
                    "directors": directors_validation,
                    "companyDocuments": company_docs_validation
                },
                "metadata": {
                    "service_id": service_id,
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "processing_time": processing_time,
                    "is_compliant": is_compliant
                }
            }
            
            # Save detailed results to JSON file
            with open('detailed_validation_results.json', 'w') as f:
                json.dump(detailed_result, f, indent=2)

            # Print simplified output to terminal
            print("\n=== Document Validation Summary ===")
            print(f"Service ID: {service_id}")
            print(f"Request ID: {request_id}")
            print(f"Processing Time: {processing_time:.2f} seconds")
            
            # Print only critical validation errors
            print("\nValidation Status:")
            errors_found = False
            
            # Print director-related errors
            if "global_errors" in directors_validation:
                for error in directors_validation["global_errors"]:
                    print(f"❌ {error}")
                    errors_found = True
            
            # Print company document errors
            if company_docs_validation.get("validation_errors"):
                for error in company_docs_validation["validation_errors"]:
                    print(f"❌ {error}")
                    errors_found = True
            
            if not errors_found:
                print("✅ All validations passed")
                    
            print("\nDetailed results saved to detailed_validation_results.json")
            
            return standard_result, detailed_result
            
        except Exception as e:
            self.logger.error(f"Comprehensive validation error: {str(e)}", exc_info=True)
            
            # Prepare error results
            error_result = {
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
            
            error_detailed_result = {
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
                    "service_id": service_id,
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e)
                }
            }
            
            # Save error results to JSON
            with open('detailed_validation_results.json', 'w') as f:
                json.dump(error_detailed_result, f, indent=2)
                    
            print("\n❌ Error during validation:")
            print(f"Error: {str(e)}")
            print("Check detailed_validation_results.json for more information")
            
            return error_result, error_detailed_result
        
    def _get_document_status(self, doc_info: Dict) -> str:
        """Determine document validation status"""
        if not isinstance(doc_info, dict):
            return "Not Valid"
            
        # Check basic validity
        if not doc_info.get('is_valid', False):
            return "Not Valid"
            
        # Get extracted data
        extracted_data = doc_info.get('extracted_data', {})
        
        # If extraction failed
        if extracted_data.get('extraction_status') == 'failed':
            return "Not Valid"
            
        # Check clarity score
        clarity_score = extracted_data.get('clarity_score', 0)
        if clarity_score > 0.7:
            return "Valid"
            
        return "Not Valid"

    def _get_document_reason(self, doc_info: Dict) -> Optional[str]:
        """Get reason for document validation status"""
        if not isinstance(doc_info, dict):
            return "Invalid document format"
            
        if not doc_info.get('is_valid', False):
            return "Document validation failed"
            
        extracted_data = doc_info.get('extracted_data', {})
        
        if extracted_data.get('extraction_status') == 'failed':
            return extracted_data.get('error_message', 'Extraction failed')
            
        clarity_score = extracted_data.get('clarity_score', 0)
        if clarity_score < 0.7:
            return f"Low clarity score: {clarity_score}"
            
        return None

        
    def _get_validation_reason(self, doc_info):
        """Helper to get validation failure reason"""
        if not isinstance(doc_info, dict):
            return "Invalid document data"
            
        if not doc_info.get('is_valid', False):
            return "Document validation failed"
            
        extracted_data = doc_info.get('extracted_data', {})
        
        if 'extraction_status' in extracted_data:
            return extracted_data.get('error_message', 'Extraction failed')
            
        clarity_score = extracted_data.get('clarity_score', 0)
        if clarity_score < 0.7:
            return f"Low clarity score: {clarity_score}"
            
        return None

    def _prepare_validation_rules(self, directors_validation, company_docs_validation, compliance_rules):
        """
        Prepare validation rules summary dynamically based on compliance rules
        
        Args:
            directors_validation (dict or list): Directors validation data
            company_docs_validation (dict): Company documents validation
            compliance_rules (dict): Compliance rules for the service
                
        Returns:
            dict: Processed validation rules
        """
        validation_rules = {}
        
        # Extract rules from compliance rules
        rules = compliance_rules.get('rules', [])
        
        # Standard rule ID mapping for API response keys
        rule_id_mapping = {
            'director_count': 'director_count',
            'passport_photo': 'passport_photo_validation',
            'signature': 'signature_validation',
            'address_proof': 'address_proof_validation',
            'indian_director_pan': 'pan_validation',
            'indian_director_aadhar': 'aadhar_validation',
            'foreign_director_docs': 'foreign_director_docs_validation',
            'company_address_proof': 'company_address_proof',
            'noc_validation': 'noc_validation',
            'aadhar_pan_linkage': 'aadhar_pan_linkage',
            'noc_owner_validation': 'noc_owner_validation'  # Added this mapping
        }
        
        # Initialize validation results with default values
        validation_defaults = {}
        
        # Dynamically build default validation rules based on the compliance rules
        for rule in rules:
            rule_id = rule.get('rule_id', '').lower()
            api_rule_id = rule_id_mapping.get(rule_id.lower(), rule_id.lower())
            
            validation_defaults[api_rule_id] = {
                "status": "passed",
                "error_message": None
            }
        
        # Get rule validations from directors
        if isinstance(directors_validation, dict):
            # Check for global rule validations from directors
            if 'rule_validations' in directors_validation:
                for rule_id, rule_result in directors_validation['rule_validations'].items():
                    api_rule_id = rule_id_mapping.get(rule_id.lower(), rule_id.lower())
                    validation_defaults[api_rule_id] = {
                        "status": rule_result.get('status', 'failed').lower(),
                        "error_message": rule_result.get('error_message')
                    }
            
            # Check individual directors for rule validations
            for director_key, director_info in directors_validation.items():
                if isinstance(director_info, dict) and director_key not in ['global_errors', 'rule_validations']:
                    rule_validations = director_info.get('rule_validations', {})
                    for rule_id, rule_result in rule_validations.items():
                        api_rule_id = rule_id_mapping.get(rule_id.lower(), rule_id.lower())
                        validation_defaults[api_rule_id] = {
                            "status": rule_result.get('status', 'failed').lower(),
                            "error_message": rule_result.get('error_message')
                        }
        
        # Get validation errors from company documents
        if isinstance(company_docs_validation, dict):
            # Check for validation errors in company documents
            validation_errors = company_docs_validation.get('validation_errors', [])
            
            # Company address proof validation
            if 'company_address_proof' in validation_defaults and validation_errors:
                validation_defaults['company_address_proof'] = {
                    "status": "failed",
                    "error_message": validation_errors[0] if validation_errors else None
                }
            
            # NOC validation
            if 'noc_validation' in validation_defaults:
                noc_validation = company_docs_validation.get('noc_validation', {})
                if noc_validation:
                    validation_defaults['noc_validation'] = {
                        "status": noc_validation.get('status', 'failed').lower(),
                        "error_message": noc_validation.get('error_message')
                    }
                elif validation_errors:
                    validation_defaults['noc_validation'] = {
                        "status": "failed",
                        "error_message": validation_errors[0] if validation_errors else None
                    }
            
            # NOC Owner validation
            if 'noc_owner_validation' in validation_defaults:
                noc_owner_validation = company_docs_validation.get('noc_owner_validation', {})
                if noc_owner_validation:
                    validation_defaults['noc_owner_validation'] = {
                        "status": noc_owner_validation.get('status', 'failed').lower(),
                        "error_message": noc_owner_validation.get('error_message')
                    }
                elif validation_errors and any("owner" in error.lower() for error in validation_errors):
                    # Find owner-related error
                    owner_error = next((error for error in validation_errors if "owner" in error.lower()), None)
                    if owner_error:
                        validation_defaults['noc_owner_validation'] = {
                            "status": "failed",
                            "error_message": owner_error
                        }
        
        return validation_defaults

    def _prepare_detailed_validation_rules(self, directors_validation, company_docs_validation, compliance_rules):
        """
        Prepare detailed validation rules dynamically
        
        Args:
            directors_validation (dict or list): Directors validation results
            company_docs_validation (dict): Company documents validation results
            compliance_rules (dict): Compliance rules for the service
        
        Returns:
            dict: Detailed validation rules with compliance information
        """
        # Ensure directors_validation is a dictionary
        if isinstance(directors_validation, list):
            directors_validation = {str(idx): info for idx, info in enumerate(directors_validation)}
        
        # Extract rules from compliance rules
        rules = compliance_rules.get('rules', [])
        
        validation_rules = {}
        
        # Process rules with their original details
        for rule in rules:
            rule_id = rule.get('rule_id', '').lower()
            
            # Determine rule result based on rule type
            if any(company_rule in rule_id for company_rule in ['company_address_proof', 'noc_validation', 'noc_owner_validation']):
                # Use company documents validation
                rule_result = company_docs_validation.get(rule_id, {})
            else:
                # Look for rule result in directors validation
                try:
                    rule_result = next(
                        (director.get('rule_validations', {}).get(rule_id, {}) 
                        for director in directors_validation.values() 
                        if isinstance(director, dict) and rule_id in director.get('rule_validations', {})), 
                        {}
                    )
                except AttributeError:
                    self.logger.warning(f"Invalid director data structure for rule {rule_id}")
                    rule_result = {}
            
            # Prepare detailed rule information
            validation_rules[rule_id] = {
                "rule_id": rule.get('rule_id'),
                "rule_name": rule.get('rule_name'),
                "description": rule.get('description'),
                "severity": rule.get('severity', 'medium'),
                "is_active": rule.get('is_active', True),
                "conditions": rule.get('conditions', {}),
                "status": rule_result.get('status', 'failed'),
                "error_message": rule_result.get('error_message'),
                "details": rule_result
            }
        
        return validation_rules
    
    def _validate_noc_owner_name_rule(self, company_docs_validation, conditions, preconditions=None):
        """
        Validate NOC owner name against provided precondition
        
        Args:
            company_docs_validation (dict): Company document validation data
            conditions (dict): Rule conditions
            preconditions (dict): Input preconditions
        
        Returns:
            dict: Validation result
        """
        # Default to passed if no validation needed
        if not preconditions:
            return {
                "status": "passed",
                "error_message": None
            }
            
        # Check if API check is required
        api_check_required = conditions.get('api_check_required', True)
        if not api_check_required:
            return {
                "status": "passed",
                "error_message": None
            }
        
        # Check if preconditions contain owner name
        expected_owner_name = preconditions.get('owner_name')
        if not expected_owner_name:
            return {
                "status": "passed",
                "error_message": None
            }
        
        # Get NOC document
        noc = company_docs_validation.get('noc', {})
        
        # If no NOC document found
        if not noc:
            return {
                "status": "failed",
                "error_message": "No Objection Certificate (NOC) is required"
            }
        
        # Get extracted NOC data
        extracted_data = noc.get('extracted_data', {})
        
        # Get actual owner name from NOC
        actual_owner_name = extracted_data.get('owner_name')
        
        # Validate name matching
        if not actual_owner_name:
            return {
                "status": "failed",
                "error_message": "Could not extract owner name from NOC"
            }
        
        # Normalize names for comparison
        def normalize_name(name):
            # Convert to lowercase, remove punctuation
            import re
            return re.sub(r'[^\w\s]', '', name.lower()).strip()
        
        # Compare normalized names
        if normalize_name(expected_owner_name) != normalize_name(actual_owner_name):
            return {
                "status": "failed",
                "error_message": f"NOC owner name '{actual_owner_name}' does not match expected name '{expected_owner_name}'"
            }
        
        # Names match
        return {
            "status": "passed",
            "error_message": None
        }

    def _validate_directors(
        self, 
        directors: Dict,
        compliance_rules: Dict
    ) -> Dict:
        """
        Comprehensive validation of all directors
        
        Args:
            directors (dict): Directors to validate
            compliance_rules (dict): Compliance rules to apply
        
        Returns:
            dict: Detailed validation results for all directors
        """
        # Validate input types
        if not isinstance(directors, dict):
            error_msg = f"Invalid directors input. Expected dict, got {type(directors)}"
            self.logger.error(error_msg)
            return {
                "validation_error": error_msg,
                "global_errors": [error_msg],
                "director_errors": {},
                "raw_input": str(directors)
            }
        
        # Extract rules
        rules = self._extract_rules_from_compliance_data(compliance_rules)
        
        # Prepare validation results
        validation_results = {}
        global_errors = []
        rule_validations = {}
        
        # Director count validation
        director_count_rule = next(
            (rule for rule in rules if rule.get('rule_id') == 'DIRECTOR_COUNT'), 
            None
        )
        
        if director_count_rule:
            conditions = director_count_rule.get('conditions', {})
            min_directors = conditions.get('min_directors', 2)
            max_directors = conditions.get('max_directors', 5)
            
            director_count = len(directors)
            if director_count < min_directors:
                error_msg = f"Insufficient directors. Found {director_count}, minimum required is {min_directors}."
                global_errors.append(error_msg)
                rule_validations['director_count'] = {
                    "status": "failed",
                    "error_message": error_msg
                }
            elif director_count > max_directors:
                error_msg = f"Too many directors. Found {director_count}, maximum allowed is {max_directors}."
                global_errors.append(error_msg)
                rule_validations['director_count'] = {
                    "status": "failed",
                    "error_message": error_msg
                }
            else:
                rule_validations['director_count'] = {
                    "status": "passed",
                    "error_message": None
                }
        
        # Process directors in parallel
        with ThreadPoolExecutor(max_workers=min(len(directors), 5)) as executor:
            # Create futures for each director validation
            future_to_director = {
                executor.submit(self._validate_single_director, director_key, director_info, rules): director_key
                for director_key, director_info in directors.items()
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_director):
                director_key = future_to_director[future]
                try:
                    director_validation = future.result()
                    
                    # Store any rule validations from the director
                    if 'rule_validations' in director_validation:
                        for rule_id, rule_result in director_validation['rule_validations'].items():
                            rule_validations[rule_id] = rule_result
                    
                    validation_results[director_key] = director_validation
                
                except Exception as e:
                    self.logger.error(f"Error processing director {director_key}: {str(e)}", exc_info=True)
                    validation_results[director_key] = {
                        "error": str(e),
                        "is_valid": False,
                        "validation_errors": [str(e)]
                    }
        
        # Add global errors if any
        if global_errors:
            validation_results['global_errors'] = global_errors
        
        # Add rule validations to the overall results
        validation_results['rule_validations'] = rule_validations
        
        return validation_results


    def _validate_single_director(
        self, 
        director_key: str, 
        director_info: Dict[str, Any], 
        rules: List
    ) -> Dict:
        """
        Comprehensive validation for a single director
        
        Args:
            director_key (str): Director identifier
            director_info (dict): Director information
            rules (list): Validation rules
        
        Returns:
            dict: Detailed validation results
        """
        # Validate basic structure
        validation_errors = []
        required_keys = ['nationality', 'authorised', 'documents']
        for key in required_keys:
            if key not in director_info:
                validation_errors.append(f"Missing required key: {key}")
        
        # Get nationality and documents
        nationality = director_info.get('nationality', '').lower()
        documents = director_info.get('documents', {})
        
        # Prepare full document validation with extraction results in parallel
        full_documents = self._process_director_documents_parallel(documents)
        
        # Specific nationality-based rules mapping
        nationality_rules = {
            'indian': [
                'INDIAN_DIRECTOR_PAN', 
                'INDIAN_DIRECTOR_AADHAR', 
                'AADHAR_PAN_LINKAGE'
            ],
            'foreign': ['FOREIGN_DIRECTOR_DOCS']
        }
        
        # Common rules for all directors
        common_rules = ['PASSPORT_PHOTO', 'SIGNATURE', 'ADDRESS_PROOF']
        
        # Get applicable rules based on nationality
        applicable_rules = nationality_rules.get(nationality, []) + common_rules
        
        # Rule processing map
        rule_processing_map = {
            "INDIAN_DIRECTOR_PAN": self._validate_indian_pan_rule,
            "INDIAN_DIRECTOR_AADHAR": self._validate_indian_aadhar_rule,
            "FOREIGN_DIRECTOR_DOCS": self._validate_foreign_director_rule,
            "AADHAR_PAN_LINKAGE": self._validate_aadhar_pan_linkage_rule,
            "PASSPORT_PHOTO": self._validate_passport_photo_rule,
            "SIGNATURE": self._validate_signature_rule,
            "ADDRESS_PROOF": self._validate_address_proof_rule
        }
        
        # Storage for rule validations
        rule_validations = {}
        
        # Apply each relevant rule
        for rule_id in applicable_rules:
            try:
                # Get rule conditions
                rule_conditions = next(
                    (rule.get('conditions', {}) for rule in rules if rule.get('rule_id') == rule_id), 
                    {}
                )
                
                # Prepare director data with full documents
                director_validation_data = {
                    director_key: {
                        **director_info,
                        'documents': full_documents
                    }
                }
                
                # Apply validation method
                validation_method = rule_processing_map.get(rule_id)
                if validation_method:
                    result = validation_method(
                        director_validation_data, 
                        rule_conditions
                    )
                    
                    # Store the rule validation result
                    rule_validations[rule_id.lower()] = result
                    
                    # Collect errors if validation fails
                    if result.get('status') != 'passed':
                        validation_errors.append(
                            result.get('error_message', f'Validation failed for {rule_id}')
                        )
            
            except Exception as e:
                self.logger.error(f"Rule validation error for {rule_id}: {str(e)}", exc_info=True)
                validation_errors.append(f"Error in {rule_id} validation: {str(e)}")
                rule_validations[rule_id.lower()] = {
                    "status": "failed",
                    "error_message": str(e)
                }
        
        # Determine overall validation status
        is_valid = len(validation_errors) == 0
        
        # Create comprehensive director validation result
        return {
            'nationality': director_info.get('nationality', 'Unknown'),
            'is_authorised': director_info.get('authorised', 'No') == 'Yes',
            'is_valid': is_valid,
            'validation_errors': validation_errors,
            'documents': full_documents,
            'rule_validations': rule_validations
        }
    
    def _process_director_documents_parallel(
        self, 
        documents: Dict[str, str]
    ) -> Dict[str, Dict[str, Any]]:
        processed_docs = {}

        if not documents:
            return processed_docs

        futures = {}
        with ThreadPoolExecutor(max_workers=min(len(documents), 10)) as executor:
            for doc_key, doc_content in documents.items():
                if isinstance(doc_content, str) and doc_content:
                    future = executor.submit(
                        self._extract_document_data_safe,
                        doc_key,
                        doc_content
                    )
                    futures[future] = doc_key

        for future in as_completed(futures):
            doc_key = futures[future]
            try:
                result = future.result()
                processed_docs[doc_key] = result
            except Exception as e:
                self.logger.error(f"Error processing document {doc_key}: {str(e)}", exc_info=True)
                processed_docs[doc_key] = {
                    "is_valid": False,
                    "error": str(e)
                }

        return processed_docs

    def _process_company_documents(self, company_docs: Dict[str, str]) -> Dict[str, Any]:
        processed_docs = {}
        
        for doc_key, doc_content in company_docs.items():
            try:
                # Save base64 string to temp file (if not URL)
                if isinstance(doc_content, str):
                    if doc_content.startswith("http://") or doc_content.startswith("https://"):
                        source = doc_content
                    else:
                        # Determine file extension
                        file_ext = "pdf" if "JVBER" in doc_content[:20] else "jpg"
                        decoded = base64.b64decode(doc_content)
                        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_ext}") as tmp_file:
                            tmp_file.write(decoded)
                            source = tmp_file.name

                    # Extract data
                    result = self.extraction_service.extract_document_data(source, doc_key)
                    processed_docs[doc_key] = result

            except Exception as e:
                self.logger.error(f"Error processing company document {doc_key}: {e}")
                processed_docs[doc_key] = {
                    "is_valid": False,
                    "error": str(e)
                }
        
        return processed_docs



    def _extract_document_data_safe(
        self, 
        doc_key: str, 
        doc_content: str  # either base64 string or URL
    ) -> Dict[str, Any]:
        """
        Thread-safe method to extract document data from base64 or URL
        
        Args:
            doc_key (str): Document key
            doc_content (str): base64-encoded file or URL
        
        Returns:
            dict: Document validation result
        """
        try:
            doc_type = self._get_document_type(doc_key)

            # Detect base64 string (naive but works well)
            if doc_content.startswith("http://") or doc_content.startswith("https://"):
                input_source = doc_content
            else:
                # Save base64 to temp file
                file_ext = "pdf" if "JVBER" in doc_content[:20] else "jpg"
                decoded = base64.b64decode(doc_content)
                with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_ext}") as tmp_file:
                    tmp_file.write(decoded)
                    input_source = tmp_file.name

            extracted_data = self.extraction_service.extract_document_data(
                input_source, doc_type
            )

            return {
                "source": input_source,
                "document_type": doc_type,
                "is_valid": extracted_data is not None and not (
                    isinstance(extracted_data, dict) and extracted_data.get('extraction_status') == 'failed'
                ),
                "extracted_data": extracted_data or {}
            }

        except Exception as e:
            self.logger.error(f"Document extraction error for {doc_key}: {str(e)}", exc_info=True)
            return {
                "document_type": self._get_document_type(doc_key),
                "is_valid": False,
                "error": str(e)
            }


    def _get_document_type(self, doc_key: str) -> str:
        """
        Map document key to standard document type
        
        Args:
            doc_key (str): Document key from input
        
        Returns:
            str: Standardized document type
        """
        doc_type_mapping = {
            'aadharCardFront': 'aadhar_front',
            'aadharCardBack': 'aadhar_back',
            'panCard': 'pan',
            'passportPhoto': 'passport_photo',
            'passport': 'passport',
            'address_proof': 'address_proof',
            'signature': 'signature',
            'drivingLicense': 'driving_license'
        }
        
        return doc_type_mapping.get(doc_key, 'unknown')

    def _get_rule_conditions(self, rules: List, rule_id: str) -> Dict:
        """
        Extract conditions for a specific rule
        
        Args:
            rules (list): List of rules
            rule_id (str): Rule identifier
        
        Returns:
            dict: Rule conditions
        """
        for rule in rules:
            if rule.get('rule_id', '').upper() == rule_id.upper():
                return rule.get('conditions', {})
        return {}
    
    def _extract_rules_from_compliance_data(self, compliance_rules: Dict) -> List:
        """
        Extract rules from compliance data, handling various structures
        
        Args:
            compliance_rules (dict): Compliance rules data
        
        Returns:
            list: Extracted rules list
        """
        try:
            # Get the rules list
            rules = compliance_rules.get('rules', [])
            
            # If rules is a list of dicts and the first item has a 'rules' key
            if (isinstance(rules, list) and len(rules) > 0 and 
                isinstance(rules[0], dict) and 'rules' in rules[0]):
                return rules[0].get('rules', [])
            
            return rules
        
        except Exception as e:
            self.logger.error(f"Error extracting rules: {str(e)}", exc_info=True)
            return []
    
    def _process_director(self, director_key: str, director_info: Dict) -> Dict:
        """
        Process and validate a single director
        
        Args:
            director_key (str): Director identifier
            director_info (dict): Director information
        
        Returns:
            dict: Processed director information
        """
        # Validate director info structure
        if not isinstance(director_info, dict):
            raise DocumentValidationError(f"Invalid director information structure for {director_key}")
        
        # Extract basic director information
        nationality = director_info.get('nationality', 'Unknown')
        is_authorised = director_info.get('authorised', 'No') == 'Yes'
        
        # Process documents
        documents = director_info.get('documents', {})
        processed_documents = {}
        
        # Validate and extract data from each document
        for doc_key, doc_url in documents.items():
            if isinstance(doc_url, str) and doc_url:
                # Get document type
                doc_type = self._get_document_type(doc_key)
                
                try:
                    # Extract data from document
                    extracted_data = self.extraction_service.extract_document_data(
                        doc_url, 
                        doc_type
                    )
                    
                    # Prepare document validation result
                    doc_validation = {
                        "url": doc_url,
                        "document_type": doc_type,
                        "is_valid": extracted_data is not None and not ('extraction_status' in extracted_data and extracted_data['extraction_status'] == 'failed'),
                        "extracted_data": extracted_data or {}
                    }
                    
                    # Add optional fields from extraction if available
                    if extracted_data:
                        if 'clarity_score' in extracted_data:
                            doc_validation['clarity_score'] = extracted_data['clarity_score']
                        
                        if 'is_masked' in extracted_data:
                            doc_validation['is_masked'] = extracted_data['is_masked']
                        
                        if 'is_recent' in extracted_data:
                            doc_validation['is_recent'] = extracted_data['is_recent']
                    
                    processed_documents[doc_key] = doc_validation
                
                except Exception as e:
                    self.logger.error(f"Error processing document {doc_key} for {director_key}: {str(e)}", exc_info=True)
                    processed_documents[doc_key] = {
                        "url": doc_url,
                        "document_type": doc_type,
                        "is_valid": False,
                        "error": str(e)
                    }
            else:
                self.logger.warning(f"Invalid document URL for {doc_key} in {director_key}")
                processed_documents[doc_key] = {
                    "error": "Invalid or missing document URL",
                    "is_valid": False
                }
        
        # Return processed director information
        return {
            "nationality": nationality,
            "is_authorised": is_authorised,
            "documents": processed_documents
        }
    
    def _get_document_type(self, doc_key: str) -> str:
        """
        Determine document type from document key
        
        Args:
            doc_key (str): Document key
        
        Returns:
            str: Document type
        """
        doc_type_mapping = {
            'aadharCardFront': 'aadhar_front',
            'aadharCardBack': 'aadhar_back',
            'panCard': 'pan',
            'passport': 'passport',
            'passportPhoto': 'passport_photo',
            'address_proof': 'address_proof',
            'signature': 'signature',
            'drivingLicense': 'driving_license'
        }
        
        return doc_type_mapping.get(doc_key, 'unknown')

    def _validate_company_documents(
        self, 
        company_docs: Dict[str, Any],
        directors: Dict,
        compliance_rules: Dict,
        preconditions: Dict = None
    ) -> Dict[str, Any]:
        """
        Validate company-level documents
        
        Args:
            company_docs (dict): Company document information
            directors (dict): Director information
            compliance_rules (dict): Compliance rules
            preconditions (dict, optional): Additional validation preconditions
        
        Returns:
            dict: Validation results for company documents
        """
        try:
            # Extract rules
            rules = self._extract_rules_from_compliance_data(compliance_rules)
            
            validation_result = {}
            validation_errors = []
            
            # Use ThreadPoolExecutor for parallel processing of company documents
            with ThreadPoolExecutor(max_workers=2) as executor:
                # Submit address proof task
                address_proof_future = None
                if 'addressProof' in company_docs:
                    address_proof_url = company_docs.get('addressProof')
                    if address_proof_url:
                        address_proof_future = executor.submit(
                            self.extraction_service.extract_document_data,
                            address_proof_url,
                            'address_proof'
                        )
                
                # Submit NOC task
                noc_future = None
                if 'noc' in company_docs:
                    noc_url = company_docs.get('noc')
                    if noc_url:
                        noc_future = executor.submit(
                            self.extraction_service.extract_document_data,
                            noc_url,
                            'noc'
                        )
                
                # Process address proof result
                if address_proof_future:
                    try:
                        address_proof_data = address_proof_future.result()
                        
                        # Get clarity score
                        clarity_score = 0.0
                        if address_proof_data and "clarity_score" in address_proof_data:
                            clarity_score = float(address_proof_data.get("clarity_score", 0.0))
                        
                        # Check for complete address
                        complete_address = False
                        if address_proof_data:
                            complete_address = address_proof_data.get("complete_address_visible", False)
                        
                        validation_result["addressProof"] = {
                            "url": company_docs.get('addressProof'),
                            "is_valid": address_proof_data is not None,
                            "clarity_score": clarity_score,
                            "complete_address_visible": complete_address,
                            "extracted_data": address_proof_data
                        }
                        
                        # Validate age if extracted data available
                        if address_proof_data:
                            # Get company address proof rule
                            company_address_rule = next(
                                (rule for rule in rules if rule.get('rule_id') == 'COMPANY_ADDRESS_PROOF'), 
                                None
                            )
                            
                            if company_address_rule:
                                # Get conditions
                                conditions = company_address_rule.get('conditions', {})
                                max_age_days = conditions.get('max_age_days', 45)
                                
                                # Check address proof age
                                date_str = address_proof_data.get("date") or address_proof_data.get("bill_date")
                                if date_str:
                                    try:
                                        doc_date = self._parse_date(date_str)
                                        if doc_date:
                                            today = datetime.now()
                                            doc_age = (today - doc_date).days
                                            # Use max_age_days from rule conditions
                                            if doc_age > max_age_days:
                                                validation_errors.append(f"Address proof is {doc_age} days old (exceeds {max_age_days} days limit)")
                                    except Exception as e:
                                        self.logger.error(f"Error calculating document age: {e}")
                    
                    except Exception as e:
                        self.logger.error(f"Error processing address proof: {str(e)}", exc_info=True)
                        validation_result["addressProof"] = {
                            "url": company_docs.get('addressProof'),
                            "is_valid": False,
                            "error": str(e)
                        }
                        validation_errors.append(f"Address proof error: {str(e)}")
                
                # Process NOC result
                if noc_future:
                    try:
                        noc_data = noc_future.result()
                        
                        validation_result["noc"] = {
                            "url": company_docs.get('noc'),
                            "is_valid": noc_data is not None,
                            "has_signature": noc_data.get('has_signature', True) if noc_data else False,
                            "extracted_data": noc_data
                        }
                        
                        # Validate NOC Owner Name if preconditions are provided
                        if noc_data and preconditions and 'owner_name' in preconditions:
                            noc_owner_rule = next(
                                (rule for rule in rules if rule.get('rule_id') == 'NOC_OWNER_VALIDATION'), 
                                None
                            )
                            
                            if noc_owner_rule:
                                expected_owner_name = preconditions.get('owner_name')
                                actual_owner_name = noc_data.get('owner_name')
                                
                                # Store the validation result for NOC owner
                                noc_owner_validation = self._validate_noc_owner_name(
                                    actual_owner_name, 
                                    expected_owner_name
                                )
                                
                                # Store the validation in result
                                validation_result["noc_owner_validation"] = noc_owner_validation
                                
                                # Add to validation errors if failed
                                if noc_owner_validation["status"] != "passed":
                                    validation_errors.append(noc_owner_validation["error_message"])
                    
                    except Exception as e:
                        self.logger.error(f"Error processing NOC: {str(e)}", exc_info=True)
                        validation_result["noc"] = {
                            "url": company_docs.get('noc'),
                            "is_valid": False,
                            "error": str(e)
                        }
                        validation_errors.append(f"NOC error: {str(e)}")
            
            # Add validation errors
            if validation_errors:
                validation_result["validation_errors"] = validation_errors
                validation_result["is_valid"] = False
            else:
                validation_result["is_valid"] = True
            
            return validation_result
                
        except Exception as e:
            self.logger.error(f"Company document validation error: {str(e)}", exc_info=True)
            return {
                "error": str(e),
                "is_valid": False,
                "validation_errors": [str(e)]
            }
        
    def _validate_noc_owner_name(self, actual_owner_name: str, expected_owner_name: str) -> Dict[str, Any]:
        """
        Validate NOC owner name against expected name
        
        Args:
            actual_owner_name (str): Owner name from NOC
            expected_owner_name (str): Expected owner name
        
        Returns:
            dict: Validation result
        """
        # Handle None values
        if not actual_owner_name:
            return {
                "status": "failed",
                "error_message": "Could not extract owner name from NOC"
            }
        
        if not expected_owner_name:
            return {
                "status": "passed",
                "error_message": None
            }
        
        # Normalize names for comparison
        def normalize_name(name):
            # Convert to lowercase, remove punctuation
            import re
            return re.sub(r'[^\w\s]', '', name.lower()).strip()
        
        # Compare normalized names
        if normalize_name(expected_owner_name) != normalize_name(actual_owner_name):
            return {
                "status": "failed",
                "error_message": f"NOC owner name '{actual_owner_name}' does not match expected name '{expected_owner_name}'"
            }
        
        # Names match
        return {
            "status": "passed",
            "error_message": None
        }
    
    def _apply_compliance_rules(
        self, 
        directors_validation: Dict, 
        company_docs_validation: Dict,
        compliance_rules: Dict
    ) -> Dict:
        """
        Apply compliance rules dynamically based on Elasticsearch configuration
        
        Args:
            directors_validation (dict): Director document validation results
            company_docs_validation (dict): Company document validation results
            compliance_rules (dict): Compliance rules from Elasticsearch
        
        Returns:
            dict: Detailed compliance rule validation results
        """
        validation_rules = {}
        
        # Check for validation error in directors validation
        if isinstance(directors_validation, dict) and "validation_error" in directors_validation:
            return {
                "global_error": {
                    "status": "failed",
                    "error_message": directors_validation.get("validation_error", "Unknown validation error"),
                    "global_errors": directors_validation.get("global_errors", []),
                    "director_errors": directors_validation.get("director_errors", {})
                }
            }
        
        try:
            # Extract rules, handling potential nested structure
            rules = self._extract_rules_from_compliance_data(compliance_rules)
            
            # Log processing rules for debugging
            self.logger.info(f"Processing {len(rules)} compliance rules")
            
            # Rule processing map
            rule_processing_map = {
                "DIRECTOR_COUNT": self._validate_director_count_rule,
                "PASSPORT_PHOTO": self._validate_passport_photo_rule,
                "SIGNATURE": self._validate_signature_rule,
                "ADDRESS_PROOF": self._validate_address_proof_rule,
                "INDIAN_DIRECTOR_PAN": self._validate_indian_pan_rule,
                "INDIAN_DIRECTOR_AADHAR": self._validate_indian_aadhar_rule,
                "FOREIGN_DIRECTOR_DOCS": self._validate_foreign_director_rule,
                "COMPANY_ADDRESS_PROOF": self._validate_company_address_proof_rule,
                "NOC_VALIDATION": self._validate_noc_rule,
                "AADHAR_PAN_LINKAGE": self._validate_aadhar_pan_linkage_rule,
                "NOC_OWNER_VALIDATION": self._validate_noc_owner_name_rule
            }
            
            # Process each rule
            for rule in rules:
                rule_id = rule.get('rule_id', '')
                
                # Skip inactive rules
                if not rule.get('is_active', True):
                    self.logger.info(f"Skipping inactive rule: {rule_id}")
                    continue
                
                # Find appropriate validation method
                validation_method = rule_processing_map.get(rule_id)
                
                if not validation_method:
                    self.logger.warning(f"No validation method found for rule: {rule_id}")
                    continue
                
                try:
                    # Prepare conditions for the rule
                    conditions = rule.get('conditions', {})
                    
                    # For NOC Owner validation, we need preconditions
                    if rule_id == "NOC_OWNER_VALIDATION":
                        # Get preconditions from the last called validate_documents method
                        preconditions = getattr(self, '_current_preconditions', {})
                        validation_result = validation_method(company_docs_validation, conditions, preconditions)
                    # Determine which data to pass based on rule type
                    elif rule_id in ["DIRECTOR_COUNT", "PASSPORT_PHOTO", "SIGNATURE", 
                                "ADDRESS_PROOF", "INDIAN_DIRECTOR_PAN", 
                                "INDIAN_DIRECTOR_AADHAR", "FOREIGN_DIRECTOR_DOCS", 
                                "AADHAR_PAN_LINKAGE"]:
                        validation_result = validation_method(directors_validation, conditions)
                    elif rule_id in ["COMPANY_ADDRESS_PROOF", "NOC_VALIDATION"]:
                        validation_result = validation_method(company_docs_validation, conditions)
                    else:
                        self.logger.warning(f"Unhandled rule type: {rule_id}")
                        continue
                    
                    # Store validation result under lowercase rule_id
                    validation_rules[rule_id.lower()] = validation_result
                    
                    # Log rule validation result for debugging
                    self.logger.info(f"Rule {rule_id} validation result: {validation_result}")
                
                except Exception as rule_error:
                    self.logger.error(f"Error processing rule {rule_id}: {rule_error}", exc_info=True)
                    validation_rules[rule_id.lower()] = {
                        "status": "error",
                        "error_message": str(rule_error)
                    }
            
            return validation_rules
        
        except Exception as e:
            self.logger.error(f"Comprehensive compliance rules application error: {e}", exc_info=True)
            return {
                "global_error": {
                    "status": "error",
                    "error_message": str(e)
                }
            }
    
    def _safe_validate_directors(self, directors_validation):
        """
        Safely convert directors validation to a dictionary
        
        Args:
            directors_validation (dict or str): Input validation data
        
        Returns:
            dict: Processed directors validation
        """
        # If it's already a dictionary, return as-is
        if isinstance(directors_validation, dict):
            return directors_validation
        
        # If it's a string error, return an empty dictionary
        if isinstance(directors_validation, str):
            self.logger.error(f"Received string instead of directors validation: {directors_validation}")
            return {}
        
        # For any other unexpected type
        self.logger.error(f"Unexpected directors validation type: {type(directors_validation)}")
        return {}

    def _validate_director_count_rule(self, directors_validation, conditions):
        """
        Validate director count rule
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Get director count
        director_count = len(safe_directors)
        
        # Get conditions
        min_directors = conditions.get('min_directors', 2)
        max_directors = conditions.get('max_directors', 5)
        
        # Validate count
        if director_count < min_directors:
            return {
                "status": "failed",
                "error_message": f"Insufficient directors. Found {director_count}, minimum required is {min_directors}."
            }
        
        if director_count > max_directors:
            return {
                "status": "failed",
                "error_message": f"Too many directors. Found {director_count}, maximum allowed is {max_directors}."
            }
        
        return {
            "status": "passed",
            "error_message": None
        }

    def _validate_passport_photo_rule(self, directors_validation, conditions):
        """
        Validate passport photo rule with more leniency
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Get conditions with more leniency
        min_clarity_score = conditions.get('min_clarity_score', 0.1)  # Lower threshold
        require_passport_style = conditions.get('is_passport_style', False)  # Make optional
        require_face_visible = conditions.get('face_visible', True)  # Keep this requirement
        
        # Check each director
        for director_key, director_info in safe_directors.items():
            documents = director_info.get('documents', {})
            passport_photo = documents.get('passportPhoto', {})
            
            # Skip if no passport photo
            if not passport_photo:
                self.logger.warning(f"No passport photo found for {director_key}")
                continue
            
            # If extraction failed, be lenient
            if not passport_photo.get('is_valid', False):
                self.logger.warning(f"Passport photo extraction issues for {director_key}, but proceeding with validation")
                continue
                
            # Get extraction data
            extracted_data = passport_photo.get('extracted_data', {})
            
            # Only check face visibility as a strict requirement
            if require_face_visible and 'face_visible' in extracted_data:
                if not extracted_data.get('face_visible', False):
                    return {
                        "status": "failed",
                        "error_message": f"Face not clearly visible in photo for {director_key}"
                    }
        
        # All directors pass the check
        return {
            "status": "passed",
            "error_message": None
        }

    def _validate_signature_rule(self, directors_validation, conditions):
        """
        Validate signature rule for all directors with more leniency
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Get conditions with lower default thresholds for leniency
        min_clarity_score = conditions.get('min_clarity_score', 0.1)  # Lower threshold
        require_handwritten = conditions.get('is_handwritten', False)  # Make optional
        require_complete = conditions.get('is_complete', False)  # Make optional
        
        # Check each director
        for director_key, director_info in safe_directors.items():
            documents = director_info.get('documents', {})
            signature = documents.get('signature', {})
            
            # Skip if no signature
            if not signature:
                # Just log a warning but don't fail
                self.logger.warning(f"No signature document found for {director_key}")
                continue
            
            # If extraction failed, be lenient
            if not signature.get('is_valid', False):
                self.logger.warning(f"Signature extraction issues for {director_key}, but proceeding with validation")
                continue
                
            # Get extraction data
            extracted_data = signature.get('extracted_data', {})
            
            # Check clarity score if available
            if 'clarity_score' in extracted_data:
                clarity_score = float(extracted_data.get('clarity_score', 0))
                if clarity_score < min_clarity_score:
                    return {
                        "status": "failed",
                        "error_message": f"Signature for {director_key} has insufficient clarity. Score: {clarity_score:.2f}, required: {min_clarity_score:.2f}"
                    }
        
        # All directors pass the check
        return {
            "status": "passed",
            "error_message": None
        }

    def _validate_address_proof_rule(self, directors_validation, conditions):
        """
        Validate address proof rule with improved date detection
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Get conditions
        max_age_days = conditions.get('max_age_days', 45)
        name_match_required = conditions.get('name_match_required', True)
        complete_address_required = conditions.get('complete_address_required', True)
        
        # Check each director
        for director_key, director_info in safe_directors.items():
            documents = director_info.get('documents', {})
            address_proof = documents.get('address_proof', {})
            
            # Skip if no address proof
            if not address_proof:
                continue
            
            # Get extraction data
            extracted_data = address_proof.get('extracted_data', {})
            
            # Check document age
            date_str = extracted_data.get('date') or extracted_data.get('bill_date')
            if date_str:
                doc_date = self._parse_date(date_str)
                if doc_date:
                    today = datetime.now()
                    doc_age = (today - doc_date).days
                    if doc_age > max_age_days:
                        return {
                            "status": "failed",
                            "error_message": f"Address proof for {director_key} is {doc_age} days old (exceeds {max_age_days} days limit)"
                        }
            
            # Check for complete address
            if complete_address_required:
                address = extracted_data.get('address', '')
                if not address or len(address.strip()) < 10:
                    return {
                        "status": "failed",
                        "error_message": f"Address proof for {director_key} does not contain a complete address"
                    }
            
            # Check name matching
            if name_match_required:
                # Get director name from other documents
                director_name = self._extract_director_name(director_info)
                address_name = extracted_data.get('name') or extracted_data.get('consumer_name')
                
                if director_name and address_name and not self._names_match(director_name, address_name):
                    return {
                        "status": "failed",
                        "error_message": f"Address proof name for {director_key} does not match director name"
                    }
        
        # All directors pass the check
        return {
            "status": "passed",
            "error_message": None
        }
    
    def _validate_indian_pan_rule(self, directors_validation, conditions):
        """
        Validate PAN card for Indian directors
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Get conditions
        min_age = conditions.get('min_age', 18)
        
        # Check each director
        for director_key, director_info in safe_directors.items():
            # Only validate Indian directors
            if director_info.get('nationality', '').lower() != 'indian':
                continue
                
            documents = director_info.get('documents', {})
            pan_card = documents.get('panCard', {})
            
            # Check if PAN card is present
            if not pan_card or not pan_card.get('is_valid', False):
                return {
                    "status": "failed",
                    "error_message": f"Valid PAN card required for Indian director {director_key}"
                }
            
            # Get extraction data
            extracted_data = pan_card.get('extracted_data', {})
            
            # Validate PAN number format
            pan_number = extracted_data.get('pan_number', '')
            if not re.match(r'^[A-Z]{5}\d{4}[A-Z]{1}$', pan_number):
                return {
                    "status": "failed",
                    "error_message": f"Invalid PAN number format for {director_key}"
                }
            
            # Check age if DOB is available
            dob_str = extracted_data.get('dob')
            if dob_str:
                dob_date = self._parse_date(dob_str)
                if dob_date:
                    today = datetime.now()
                    age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
                    if age < min_age:
                        return {
                            "status": "failed",
                            "error_message": f"Director {director_key} is {age} years old, below minimum age of {min_age}"
                        }
        
        # All Indian directors pass the check
        return {
            "status": "passed",
            "error_message": None
        }
        
    def _validate_indian_aadhar_rule(self, directors_validation, conditions):
        """
        Validate Aadhar card for Indian directors with improved image comparison
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Get conditions
        masked_not_allowed = conditions.get('masked_not_allowed', True)
        different_images_required = conditions.get('different_images_required', True)
        
        # Check each director
        for director_key, director_info in safe_directors.items():
            # Only validate Indian directors
            if director_info.get('nationality', '').lower() != 'indian':
                continue
                    
            documents = director_info.get('documents', {})
            aadhar_front = documents.get('aadharCardFront', {})
            aadhar_back = documents.get('aadharCardBack', {})
            
            # Check if both front and back are present
            if not aadhar_front or not aadhar_back:
                return {
                    "status": "failed",
                    "error_message": f"Both Aadhar front and back required for Indian director {director_key}"
                }
            
            # Check if both are valid
            if not aadhar_front.get('is_valid', False) or not aadhar_back.get('is_valid', False):
                return {
                    "status": "failed",
                    "error_message": f"Valid Aadhar front and back required for {director_key}"
                }
            
            # Advanced image comparison logic
            front_data = aadhar_front.get('extracted_data', {})
            back_data = aadhar_back.get('extracted_data', {})
            
            # Check for masked Aadhar
            if masked_not_allowed:
                # Only check if both are masked - be more lenient
                if front_data.get('is_masked', False) and back_data.get('is_masked', False):
                    return {
                        "status": "failed",
                        "error_message": f"Both Aadhar front and back are masked for {director_key}, need at least one unmasked"
                    }
            
            # Intelligent image comparison
            # Compare key data points instead of just image URLs
            key_fields = ['name', 'dob', 'aadhar_number', 'gender']
            
            # Check if key information is consistent
            inconsistent_fields = [
                field for field in key_fields 
                if front_data.get(field) != back_data.get(field)
            ]
            
            # If different_images_required is True, do stricter checking
            if different_images_required:
                # Check URL or file uniqueness
                # Try comparing base64 content if URL is missing
                front_raw = aadhar_front.get('base64') or aadhar_front.get('content') or ''
                back_raw = aadhar_back.get('base64') or aadhar_back.get('content') or ''

                # fallback: compare by hash (short hash, to avoid long strings)
                import hashlib
                front_hash = hashlib.md5(front_raw.encode()).hexdigest() if front_raw else ''
                back_hash = hashlib.md5(back_raw.encode()).hexdigest() if back_raw else ''

                # If hashes are equal, assume same image
                if front_hash and front_hash == back_hash:
                    if len(inconsistent_fields) > 1:
                        return {
                            "status": "failed",
                            "error_message": f"Same image used for Aadhar front and back for {director_key}"
                        }

                # front_url = aadhar_front.get('url', '')
                # back_url = aadhar_back.get('url', '')
                
                # # Extract file ID from Google Drive URL
                # def extract_google_drive_id(url):
                #     if 'drive.google.com' in url:
                #         match = re.search(r'/d/([a-zA-Z0-9_-]+)', url)
                #         if match:
                #             return match.group(1)
                #     return url
                
                # front_id = extract_google_drive_id(front_url)
                # back_id = extract_google_drive_id(back_url)
                
                # # If URLs are identical and we require different images
                # if front_id == back_id:
                #     # But allow if key information is consistent and not masked
                #     if len(inconsistent_fields) > 1:
                #         return {
                #             "status": "failed",
                #             "error_message": f"Same image used for Aadhar front and back for {director_key}"
                #         }
                    
                    # Log a warning about potential duplicate
                    self.logger.warning(f"Potential duplicate Aadhar images for {director_key}")
            
            # Optional: Add logging for inconsistent fields
            if inconsistent_fields:
                self.logger.warning(f"Inconsistent Aadhar fields for {director_key}: {inconsistent_fields}")
        
        # All directors pass the check
        return {
            "status": "passed",
            "error_message": None
        }
    
    def _validate_foreign_director_rule(self, directors_validation, conditions):
        """
        Validate documents for foreign directors
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Get conditions
        passport_required = conditions.get('passport_required', True)
        passport_validity_check = conditions.get('passport_validity_check', True)
        driving_license_required = conditions.get('driving_license_required', False)
        
        # For each foreign director
        foreign_directors_found = False
        
        for director_key, director_info in safe_directors.items():
            # Only validate foreign directors
            if director_info.get('nationality', '').lower() != 'foreign':
                continue
            
            foreign_directors_found = True
            documents = director_info.get('documents', {})
            
            # First, check if foreign director has any valid ID document
            # This could be a passport, driving license, or even a PAN card
            if passport_required:
                # First, look for explicit passport document
                passport = documents.get('passport', {})
                
                # If no explicit passport, check if panCard can be treated as ID
                if not passport or not passport.get('is_valid', False):
                    # Check if panCard exists and is valid as alternative ID
                    pan_card = documents.get('panCard', {})
                    if not pan_card or not pan_card.get('is_valid', False):
                        return {
                            "status": "failed",
                            "error_message": f"Valid ID document (passport or equivalent) required for foreign director {director_key}"
                        }
                    else:
                        # PanCard is being used as ID document
                        self.logger.info(f"Using PAN card as ID document for foreign director {director_key}")
        
        # If we found no foreign directors, pass this rule
        if not foreign_directors_found:
            return {
                "status": "passed",
                "error_message": None,
                "details": "No foreign directors found requiring validation"
            }
        
        # All foreign directors pass the check
        return {
            "status": "passed",
            "error_message": None
        }
    
    def _validate_company_address_proof_rule(self, company_docs_validation, conditions):
        """
        Validate company address proof with better date parsing
        
        Args:
            company_docs_validation (dict): Company document validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Get conditions
        max_age_days = conditions.get('max_age_days', 45)
        complete_address_required = conditions.get('complete_address_required', True)
        name_match_required = conditions.get('name_match_required', False)
        
        # Check if address proof exists
        address_proof = company_docs_validation.get('addressProof', {})
        if not address_proof or not address_proof.get('is_valid', False):
            return {
                "status": "failed",
                "error_message": "Valid company address proof required"
            }
        
        # Get extraction data
        extracted_data = address_proof.get('extracted_data', {})
        
        # Check document age with improved date parsing
        date_str = extracted_data.get('date') or extracted_data.get('bill_date')
        if date_str:
            doc_date = self._parse_date(date_str)
            if doc_date:
                today = datetime.now()
                doc_age = (today - doc_date).days
                if doc_age > max_age_days:
                    return {
                        "status": "failed",
                        "error_message": f"Company address proof is {doc_age} days old (exceeds {max_age_days} days limit)"
                    }
        
        # Check for complete address
        if complete_address_required:
            address = extracted_data.get('address', '')
            if not address or len(address.strip()) < 10:
                return {
                    "status": "failed",
                    "error_message": "Company address proof does not contain a complete address"
                }
        
        # All checks passed
        return {
            "status": "passed",
            "error_message": None
        }
    
    def _validate_noc_rule(self, company_docs_validation, conditions):
        """
        Validate No Objection Certificate (NOC) with more flexible validation
        
        Args:
            company_docs_validation (dict): Company document validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Get conditions
        noc_required = conditions.get('noc_required', True)
        signature_required = conditions.get('signature_required', True)
        
        # If NOC is not required, pass automatically
        if not noc_required:
            return {
                "status": "passed",
                "error_message": None
            }
        
        # Check if NOC exists in company documents
        noc = company_docs_validation.get('noc', {})
        
        # If no NOC document found and it's required
        if not noc:
            return {
                "status": "failed",
                "error_message": "No Objection Certificate (NOC) is required but not provided"
            }
        
        # Get extracted NOC data
        extracted_data = noc.get('extracted_data', {})
        
        # Comprehensive NOC validation checks
        validation_checks = []
        
        # Check for mandatory fields
        mandatory_fields = ['owner_name', 'property_address', 'applicant_name', 'date']
        missing_fields = [field for field in mandatory_fields if not extracted_data.get(field)]
        
        if missing_fields:
            validation_checks.append(f"Missing mandatory NOC fields: {', '.join(missing_fields)}")
        
        # Date validation - should be recent (within last 90 days)
        if 'date' in extracted_data:
            try:
                noc_date = self._parse_date(extracted_data['date'])
                if noc_date:
                    today = datetime.now()
                    noc_age = (today - noc_date).days
                    
                    # Allow NOC up to 90 days old
                    if noc_age > 90:
                        validation_checks.append(f"NOC is {noc_age} days old (exceeds 90 days limit)")
            except Exception as e:
                validation_checks.append(f"Invalid NOC date: {str(e)}")
        
        # Signature validation
        if signature_required:
            # Check for signature presence
            has_signature = extracted_data.get('has_signature', False)
            
            # Additional checks for signature validity
            if not has_signature:
                validation_checks.append("NOC lacks required property owner's signature")
        
        # Property address check
        if 'property_address' in extracted_data:
            address = extracted_data['property_address']
            if not address or len(address.strip()) < 10:
                validation_checks.append("Incomplete or invalid property address")
        
        # Purpose validation
        purpose = extracted_data.get('purpose', '')
        if not purpose or len(purpose.strip()) < 5:
            validation_checks.append("Invalid or missing purpose in NOC")
        
        # Comprehensive owner name and applicant name validation
        owner_name = extracted_data.get('owner_name', '').strip()
        applicant_name = extracted_data.get('applicant_name', '').strip()
        
        if not owner_name or not applicant_name:
            validation_checks.append("Missing owner or applicant name")
        
        # If any validation checks failed, return failure
        if validation_checks:
            return {
                "status": "failed",
                "error_message": "; ".join(validation_checks)
            }
        
        # Clarity score check
        clarity_score = extracted_data.get('clarity_score', 0)
        if clarity_score < 0.7:  # Minimum clarity threshold
            return {
                "status": "failed",
                "error_message": f"Low document clarity: {clarity_score}"
            }
        
        # Validate NOC is marked as valid
        is_valid_noc = extracted_data.get('is_valid_noc', False)
        if not is_valid_noc:
            return {
                "status": "failed",
                "error_message": "Document does not appear to be a valid NOC"
            }
        
        # All checks passed
        return {
            "status": "passed",
            "error_message": None
        }
    
    def _validate_aadhar_pan_linkage_rule(self, directors_validation, conditions):
        """
        Validate Aadhar PAN linkage with strict error handling
        
        Args:
            directors_validation (dict): Directors validation data
            conditions (dict): Rule conditions
        
        Returns:
            dict: Validation result
        """
        # Safely process directors validation
        safe_directors = self._safe_validate_directors(directors_validation)
        
        # Check if linkage check is required
        linkage_api_check_required = conditions.get('linkage_api_check_required', True)
        if not linkage_api_check_required:
            return {
                "status": "passed",
                "error_message": None
            }
        
        # Check each director
        for director_key, director_info in safe_directors.items():
            # Only validate Indian directors
            if director_info.get('nationality', '').lower() != 'indian':
                continue
                
            documents = director_info.get('documents', {})
            
            # Get Aadhar and PAN documents
            aadhar_front = documents.get('aadharCardFront', {})
            aadhar_back = documents.get('aadharCardBack', {})
            pan_card = documents.get('panCard', {})
            
            # Check if both documents exist
            if not aadhar_front and not aadhar_back:
                self.logger.warning(f"No Aadhar card found for {director_key}")
                continue
                
            if not pan_card:
                self.logger.warning(f"No PAN card found for {director_key}")
                continue
            
            # Get extraction data
            aadhar_data = aadhar_front.get('extracted_data', {})
            aadhar_back_data = aadhar_back.get('extracted_data', {}) if aadhar_back else {}
            pan_data = pan_card.get('extracted_data', {})
            
            # Get Aadhar number (try from both front and back)
            aadhar_number = aadhar_data.get('aadhar_number', '')
            
            # If front is masked, try to get from back
            if aadhar_data.get('is_masked', False) and aadhar_back_data:
                aadhar_number = aadhar_back_data.get('aadhar_number', aadhar_number)
            
            pan_number = pan_data.get('pan_number', '')
            
            # Check if both numbers are available and valid
            if not aadhar_number or 'XXXX' in aadhar_number:
                self.logger.warning(f"Masked or missing Aadhar number for {director_key}")
                continue
                
            if not pan_number:
                self.logger.warning(f"Missing PAN number for {director_key}")
                continue
            
            # Remove spaces and any other non-numeric characters from Aadhar number
            formatted_aadhar = re.sub(r'\D', '', aadhar_number)
            
            # Verify linkage
            try:
                self.logger.info(f"Verifying Aadhar-PAN linkage for {director_key}: Aadhar={formatted_aadhar}, PAN={pan_number}")
                
                linkage_result = self.aadhar_pan_linkage_service.verify_linkage(
                    formatted_aadhar,
                    pan_number
                )
                
                # Log the result for debugging
                self.logger.info(f"Linkage result: {linkage_result}")
                
                # Strictly check for linkage - fail on any error or non-linked status
                if not linkage_result.get('is_linked', False):
                    error_message = linkage_result.get('message', 'Unknown error')
                    return {
                        "status": "failed",
                        "error_message": f"Aadhar and PAN not linked for {director_key}: {error_message}"
                    }
                
                # Successful linkage for at least one Indian director
                return {
                    "status": "passed",
                    "error_message": None
                }
            except Exception as e:
                self.logger.error(f"Error verifying Aadhar-PAN linkage for {director_key}: {str(e)}", exc_info=True)
                return {
                    "status": "failed",
                    "error_message": f"Error during Aadhar-PAN linkage verification: {str(e)}"
                }
        
        # No Indian directors found for linkage check
        return {
            "status": "passed",
            "error_message": None
        }
    
    def _extract_director_name(self, director_info):
        """
        Extract director name from documents
        
        Args:
            director_info (dict): Director information
        
        Returns:
            str: Director name
        """
        # Priority order for documents to get name from
        priority_docs = ['panCard', 'aadharCardFront', 'passport', 'drivingLicense']
        
        documents = director_info.get('documents', {})
        
        # Try to get name from documents in priority order
        for doc_key in priority_docs:
            if doc_key in documents:
                doc = documents[doc_key]
                extracted_data = doc.get('extracted_data', {})
                name = extracted_data.get('name')
                if name:
                    return name
        
        # If no name found, try any other document
        for doc_key, doc in documents.items():
            extracted_data = doc.get('extracted_data', {})
            name = extracted_data.get('name')
            if name:
                return name
        
        # No name found
        return None
    
    def _get_director_names(self, directors):
        """
        Get all director names
        
        Args:
            directors (dict): Directors data
        
        Returns:
            list: Director names
        """
        director_names = []
        
        # Check if directors is a dict
        if not isinstance(directors, dict):
            self.logger.warning(f"Invalid directors input in _get_director_names. Expected dict, got {type(directors)}")
            return director_names
        
        for director_key, director_info in directors.items():
            if not isinstance(director_info, dict):
                continue
                
            name = self._extract_director_name(director_info)
            if name:
                director_names.append(name)
        
        return director_names

    def _extract_director_name(self, director_info):
        """
        Extract director name from documents
        
        Args:
            director_info (dict): Director information
        
        Returns:
            str: Director name
        """
        # Check if director_info is a dict
        if not isinstance(director_info, dict):
            self.logger.warning(f"Invalid director_info in _extract_director_name. Expected dict, got {type(director_info)}")
            return None
            
        # Priority order for documents to get name from
        priority_docs = ['panCard', 'aadharCardFront', 'passport', 'drivingLicense']
        
        documents = director_info.get('documents', {})
        
        # Try to get name from documents in priority order
        for doc_key in priority_docs:
            if doc_key in documents:
                doc = documents[doc_key]
                if not isinstance(doc, dict):
                    continue
                    
                extracted_data = doc.get('extracted_data', {})
                name = extracted_data.get('name')
                if name:
                    return name
        
        # If no name found, try any other document
        for doc_key, doc in documents.items():
            if not isinstance(doc, dict):
                continue
                
            extracted_data = doc.get('extracted_data', {})
            name = extracted_data.get('name')
            if name:
                return name
        
        # No name found
        return None
    
    def _parse_date(self, date_str):
        """
        Parse date string in multiple formats with better detection
        
        Args:
            date_str (str): Date string
        
        Returns:
            datetime: Parsed date or None
        """
        if not date_str:
            return None
        
        # Pre-process the date string
        date_str = date_str.strip()
        
        # Try multiple date formats in order of preference
        formats = [
            '%d/%m/%Y',  # DD/MM/YYYY
            '%Y-%m-%d',  # YYYY-MM-DD
            '%d-%m-%Y',  # DD-MM-YYYY
            '%m/%d/%Y',  # MM/DD/YYYY
            '%d %B %Y',  # DD Month YYYY
            '%d %b %Y',  # DD Mon YYYY
            '%B %d, %Y', # Month DD, YYYY
            '%b %d, %Y'  # Mon DD, YYYY
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        # Try with dateutil parser as fallback
        try:
            # Force day first parsing since most dates in India are DD/MM/YYYY
            parsed_date = parser.parse(date_str, dayfirst=True)
            
            # Extra validation - reject future dates
            if parsed_date > datetime.now() + timedelta(days=3):  # Allow 3 days for timezone differences
                self.logger.warning(f"Rejecting future date: {parsed_date}")
                return None
                
            return parsed_date
        except Exception:
            return None
    
    def _names_match(self, name1, name2):
        """
        Check if names match with fuzzy logic
        
        Args:
            name1 (str): First name
            name2 (str): Second name
        
        Returns:
            bool: Whether names match
        """
        # Handle None values
        if not name1 or not name2:
            return False
        
        # Normalize names
        def normalize_name(name):
            # Convert to lowercase and remove punctuation
            name = re.sub(r'[^\w\s]', '', name.lower())
            # Remove multiple spaces
            name = re.sub(r'\s+', ' ', name).strip()
            return name
        
        norm1 = normalize_name(name1)
        norm2 = normalize_name(name2)
        
        # Check for exact match
        if norm1 == norm2:
            return True
        
        # Check if one is substring of another
        if norm1 in norm2 or norm2 in norm1:
            return True
        
        # Split names into parts
        parts1 = set(norm1.split())
        parts2 = set(norm2.split())
        
        # Check for common words
        common_words = parts1.intersection(parts2)
        
        # If at least 50% words match
        return len(common_words) >= min(len(parts1), len(parts2)) / 2
