import json
import os
from pathlib import Path
from typing import Dict, Any, Union


def load_schema(schema_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load a JSON schema from a file and return it as a dictionary.
    
    Args:
        schema_path: Path to the JSON schema file
        
    Returns:
        Dict containing the parsed JSON schema
        
    Raises:
        FileNotFoundError: If the schema file doesn't exist
        json.JSONDecodeError: If the file contains invalid JSON
        ValueError: If the loaded content is not a valid schema object
    """
    schema_path = Path(schema_path)
    
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    
    if not schema_path.is_file():
        raise ValueError(f"Path is not a file: {schema_path}")
    
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in schema file {schema_path}: {e.msg}", e.doc, e.pos)
    
    # Basic validation that it's a schema-like object
    if not isinstance(schema, dict):
        raise ValueError(f"Schema must be a JSON object, got {type(schema).__name__}")
    
    # Optional: Validate that it looks like a JSON Schema
    if "$schema" in schema:
        print(f"Loaded schema with $schema: {schema['$schema']}")
    
    if "title" in schema:
        print(f"Loaded schema: {schema['title']}")
    
    return schema


def load_schema_with_defaults(schema_path: Union[str, Path], 
                            default_title: str = "JSON Schema Form",
                            validate_schema: bool = True) -> Dict[str, Any]:
    """
    Load a JSON schema with additional validation and default values.
    
    Args:
        schema_path: Path to the JSON schema file
        default_title: Default title if none specified in schema
        validate_schema: Whether to perform basic schema validation
        
    Returns:
        Dict containing the parsed and validated JSON schema
    """
    schema = load_schema(schema_path)
    
    # Add default title if not present
    if "title" not in schema:
        schema["title"] = default_title
    
    # Add default type if not present (assume object)
    if "type" not in schema and "$ref" not in schema and "oneOf" not in schema and "anyOf" not in schema:
        schema["type"] = "object"
    
    if validate_schema:
        # Basic schema validation
        if "type" in schema:
            valid_types = ["null", "boolean", "object", "array", "number", "string", "integer"]
            schema_type = schema["type"]
            if isinstance(schema_type, str):
                if schema_type not in valid_types:
                    raise ValueError(f"Invalid schema type: {schema_type}")
            elif isinstance(schema_type, list):
                for t in schema_type:
                    if t not in valid_types:
                        raise ValueError(f"Invalid schema type in array: {t}")
        
        # Validate properties exist for object types
        if schema.get("type") == "object" and "properties" not in schema and "$ref" not in schema:
            print("Warning: Object schema without properties defined")
    
    return schema


# Example usage and test function
def test_schema_loading():
    """Test function to demonstrate schema loading"""
    try:
        # Test loading the comprehensive schema
        schema = load_schema("example_schema.json")
        print(f"Successfully loaded schema with {len(schema.get('properties', {}))} root properties")
        
        # Print some basic info about the schema
        if "properties" in schema:
            print("Root properties:")
            for prop_name in schema["properties"].keys():
                print(f"  - {prop_name}")
        
        if "$defs" in schema:
            print(f"Schema definitions: {list(schema['$defs'].keys())}")
            
        return schema
        
    except Exception as e:
        print(f"Error loading schema: {e}")
        return None


if __name__ == "__main__":
    # Test the function
    test_schema_loading()