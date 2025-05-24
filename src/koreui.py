from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox, 
    QDoubleSpinBox, QComboBox, QCheckBox, QGroupBox, QPushButton, 
    QApplication, QScrollArea, QTextEdit, QDateEdit, QTimeEdit, 
    QDateTimeEdit, QTabWidget, QFrame, QSplitter, QTreeWidget, 
    QTreeWidgetItem, QHeaderView, QMessageBox, QFormLayout, 
    QStackedWidget, QSlider, QProgressBar, QDial, QLCDNumber,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem
)
from PySide6.QtCore import Qt, QDate, QTime, QDateTime, QTimer, Signal, QObject, QUrl
from PySide6.QtGui import QValidator, QRegularExpressionValidator, QFont, QPalette, QColor
import json
import re
import uuid
import base64
from datetime import datetime, date, time
from typing import Any, Dict, List, Optional, Union, Callable, Set
from urllib.parse import urlparse
import ipaddress
import email.utils

MODERN_STYLESHEET = """
/* Stylesheet Coming Soon */
"""

class ValidationError(Exception):
    """Custom validation error for schema validation"""
    def __init__(self, message: str, path: str = "", schema_path: str = ""):
        self.message = message
        self.path = path
        self.schema_path = schema_path
        super().__init__(f"{path}: {message}")


class SchemaResolver:
    """
    Handles JSON Schema resolution including $ref, $defs, and recursive schemas.
    Supports Draft 2020-12 features.
    """
    
    def __init__(self, root_schema: Dict[str, Any]):
        self.root_schema = root_schema
        self.refs_cache = {}
        self.resolution_stack = []
        self.composition_depth = 0
        self.max_depth = 50  # Prevent infinite recursion
        
    def resolve_schema(self, schema: Union[Dict[str, Any], bool], current_path: str = "#") -> Dict[str, Any]:
        """Enhanced resolution with depth tracking"""
        if self.composition_depth > self.max_depth:
            raise ValidationError(f"Maximum schema resolution depth exceeded at {current_path}")
            
        if isinstance(schema, bool):
            return {"type": "object"} if schema else {"not": {}}
            
        if not isinstance(schema, dict):
            return {}
        
        self.composition_depth += 1
        try:
            # Handle $ref first
            if "$ref" in schema:
                return self._resolve_ref(schema["$ref"], current_path)
                
            # Handle conditional schemas (preserve structure for runtime evaluation)
            if "if" in schema:
                resolved = dict(schema)
                resolved["if"] = self.resolve_schema(schema["if"], f"{current_path}/if")
                if "then" in schema:
                    resolved["then"] = self.resolve_schema(schema["then"], f"{current_path}/then")
                if "else" in schema:
                    resolved["else"] = self.resolve_schema(schema["else"], f"{current_path}/else")
                return resolved
            
            # Handle composition keywords with better nesting support
            resolved = dict(schema)
            
            # Handle allOf (merge schemas)
            if "allOf" in schema:
                resolved = self._merge_all_of(schema["allOf"], resolved, current_path)
                
            # Handle oneOf/anyOf (preserve for widget creation)
            if "oneOf" in schema:
                resolved["oneOf"] = [
                    self.resolve_schema(sub_schema, f"{current_path}/oneOf/{i}")
                    for i, sub_schema in enumerate(schema["oneOf"])
                ]
                
            if "anyOf" in schema:
                resolved["anyOf"] = [
                    self.resolve_schema(sub_schema, f"{current_path}/anyOf/{i}")
                    for i, sub_schema in enumerate(schema["anyOf"])
                ]
                
            # Handle items schema for arrays
            if "items" in schema:
                resolved["items"] = self.resolve_schema(schema["items"], f"{current_path}/items")
                
            # Handle properties for objects
            if "properties" in schema:
                resolved_props = {}
                for prop_name, prop_schema in schema["properties"].items():
                    resolved_props[prop_name] = self.resolve_schema(
                        prop_schema, f"{current_path}/properties/{prop_name}"
                    )
                resolved["properties"] = resolved_props
                
            return resolved
            
        finally:
            self.composition_depth -= 1
        
    def _merge_all_of(self, all_of_schemas: List[Dict], base_schema: Dict, current_path: str) -> Dict[str, Any]:
        """Enhanced allOf merging with support for nested compositions"""
        result = dict(base_schema)
        
        # Remove allOf from result to avoid infinite loops
        if "allOf" in result:
            del result["allOf"]
        
        for i, sub_schema in enumerate(all_of_schemas):
            resolved_sub = self.resolve_schema(sub_schema, f"{current_path}/allOf/{i}")
            result = self._deep_merge_schemas(result, resolved_sub)
            
        return result
        
    def _deep_merge_schemas(self, schema1: Dict, schema2: Dict) -> Dict[str, Any]:
        """Enhanced schema merging with better composition handling"""
        result = dict(schema1)
        
        for key, value in schema2.items():
            if key in result:
                if key == "properties":
                    # Merge properties recursively
                    merged_props = dict(result[key])
                    for prop_name, prop_schema in value.items():
                        if prop_name in merged_props:
                            # If both have the same property, merge them with allOf
                            merged_props[prop_name] = {
                                "allOf": [merged_props[prop_name], prop_schema]
                            }
                        else:
                            merged_props[prop_name] = prop_schema
                    result[key] = merged_props
                elif key == "required":
                    # Union of required arrays
                    result[key] = list(set(result[key] + value))
                elif key in ["allOf", "anyOf", "oneOf"]:
                    # Combine composition arrays
                    result[key] = result[key] + value
                elif key == "items":
                    # For array items, use allOf to merge
                    result[key] = {"allOf": [result[key], value]}
                else:
                    # Override other properties
                    result[key] = value
            else:
                result[key] = value
                
        return result


class SchemaValidator:
    """
    Comprehensive JSON Schema Draft 2020-12 validator
    """
    
    # Format validators
    FORMAT_VALIDATORS = {
        'email': lambda v: email.utils.parseaddr(v)[1] != '',
        'uri': lambda v: urlparse(v).scheme != '',
        'uuid': lambda v: bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v, re.I)),
        'date': lambda v: bool(re.match(r'^\d{4}-\d{2}-\d{2}$', v)),
        'time': lambda v: bool(re.match(r'^\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?$', v)),
        'date-time': lambda v: bool(re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?$', v)),
        'ipv4': lambda v: bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v)) and all(0 <= int(x) <= 255 for x in v.split('.')),
        'ipv6': lambda v: SchemaValidator._validate_ipv6(v),
        'hostname': lambda v: bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', v)),
    }
    
    def __init__(self, resolver: SchemaResolver):
        self.resolver = resolver
        
    @staticmethod
    def _validate_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False
            
    def validate(self, data: Any, schema: Dict[str, Any], path: str = "") -> List[ValidationError]:
        """Validate data against schema, returning list of errors"""
        errors = []
        
        try:
            resolved_schema = self.resolver.resolve_schema(schema)
            self._validate_value(data, resolved_schema, path, errors)
        except ValidationError as e:
            errors.append(e)
            
        return errors
        
    def _validate_value(self, data: Any, schema: Dict[str, Any], path: str, errors: List[ValidationError]):
        """Core validation logic"""
        
        # Handle type validation
        if "type" in schema:
            self._validate_type(data, schema["type"], path, errors)
            
        # Handle const
        if "const" in schema:
            if data != schema["const"]:
                errors.append(ValidationError(f"Value must be {schema['const']}", path))
                
        # Handle enum
        if "enum" in schema:
            if data not in schema["enum"]:
                errors.append(ValidationError(f"Value must be one of {schema['enum']}", path))
                
        # Type-specific validations
        if isinstance(data, str):
            self._validate_string(data, schema, path, errors)
        elif isinstance(data, (int, float)):
            self._validate_number(data, schema, path, errors)
        elif isinstance(data, list):
            self._validate_array(data, schema, path, errors)
        elif isinstance(data, dict):
            self._validate_object(data, schema, path, errors)
        
        # Conditional validation
        if "if" in schema:
            self._validate_conditional(data, schema, path, errors)

        # Handle composition keywords
        if "allOf" in schema:
            self._validate_all_of(data, schema["allOf"], path, errors)
        if "anyOf" in schema:
            self._validate_any_of(data, schema["anyOf"], path, errors)
        if "oneOf" in schema:
            self._validate_one_of(data, schema["oneOf"], path, errors)
        if "not" in schema:
            self._validate_not(data, schema["not"], path, errors)
            
    def _validate_type(self, data: Any, type_def: Union[str, List[str]], path: str, errors: List[ValidationError]):
        """Validate JSON Schema type"""
        valid_types = type_def if isinstance(type_def, list) else [type_def]
        
        type_map = {
            "null": type(None),
            "boolean": bool,
            "integer": int,
            "number": (int, float),
            "string": str,
            "array": list,
            "object": dict
        }
        
        for valid_type in valid_types:
            expected_type = type_map.get(valid_type)
            if expected_type and isinstance(data, expected_type):
                if valid_type == "integer" and isinstance(data, float) and not data.is_integer():
                    continue
                return
                
        errors.append(ValidationError(f"Expected type {type_def}, got {type(data).__name__}", path))
        
    def _validate_string(self, data: str, schema: Dict, path: str, errors: List[ValidationError]):
        """String-specific validation"""
        if "minLength" in schema and len(data) < schema["minLength"]:
            errors.append(ValidationError(f"String too short (min: {schema['minLength']})", path))
            
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            errors.append(ValidationError(f"String too long (max: {schema['maxLength']})", path))
            
        if "pattern" in schema:
            if not re.search(schema["pattern"], data):
                errors.append(ValidationError(f"String does not match pattern: {schema['pattern']}", path))
                
        if "format" in schema:
            format_name = schema["format"]
            validator = self.FORMAT_VALIDATORS.get(format_name)
            if validator and not validator(data):
                errors.append(ValidationError(f"Invalid format: {format_name}", path))
                
    def _validate_number(self, data: Union[int, float], schema: Dict, path: str, errors: List[ValidationError]):
        """Number-specific validation"""
        if "minimum" in schema and data < schema["minimum"]:
            errors.append(ValidationError(f"Number too small (min: {schema['minimum']})", path))
            
        if "maximum" in schema and data > schema["maximum"]:
            errors.append(ValidationError(f"Number too large (max: {schema['maximum']})", path))
            
        if "exclusiveMinimum" in schema and data <= schema["exclusiveMinimum"]:
            errors.append(ValidationError(f"Number must be > {schema['exclusiveMinimum']}", path))
            
        if "exclusiveMaximum" in schema and data >= schema["exclusiveMaximum"]:
            errors.append(ValidationError(f"Number must be < {schema['exclusiveMaximum']}", path))
            
        if "multipleOf" in schema and data % schema["multipleOf"] != 0:
            errors.append(ValidationError(f"Number must be multiple of {schema['multipleOf']}", path))
            
    def _validate_array(self, data: List, schema: Dict, path: str, errors: List[ValidationError]):
        """Array-specific validation"""
        if "minItems" in schema and len(data) < schema["minItems"]:
            errors.append(ValidationError(f"Array too short (min: {schema['minItems']})", path))
            
        if "maxItems" in schema and len(data) > schema["maxItems"]:
            errors.append(ValidationError(f"Array too long (max: {schema['maxItems']})", path))
            
        if "uniqueItems" in schema and schema["uniqueItems"]:
            if len(data) != len(set(str(item) for item in data)):
                errors.append(ValidationError("Array items must be unique", path))
                
        # Validate items
        if "items" in schema:
            items_schema = schema["items"]
            for i, item in enumerate(data):
                self._validate_value(item, items_schema, f"{path}[{i}]", errors)
                
    def _validate_object(self, data: Dict, schema: Dict, path: str, errors: List[ValidationError]):
        """Object-specific validation"""
        if "minProperties" in schema and len(data) < schema["minProperties"]:
            errors.append(ValidationError(f"Object has too few properties (min: {schema['minProperties']})", path))
            
        if "maxProperties" in schema and len(data) > schema["maxProperties"]:
            errors.append(ValidationError(f"Object has too many properties (max: {schema['maxProperties']})", path))
            
        # Required properties
        required = schema.get("required", [])
        for prop in required:
            if prop not in data:
                errors.append(ValidationError(f"Required property '{prop}' is missing", path))
                
        # Validate properties
        properties = schema.get("properties", {})
        for prop_name, prop_value in data.items():
            if prop_name in properties:
                prop_schema = properties[prop_name]
                self._validate_value(prop_value, prop_schema, f"{path}.{prop_name}" if path else prop_name, errors)

    def _validate_conditional(self, data: Any, schema: Dict[str, Any], path: str, errors: List[ValidationError]):
        """Handle if/then/else conditional validation"""
        if_schema = schema["if"]
        then_schema = schema.get("then")
        else_schema = schema.get("else")

        # Check if 'if' schema passes (no errors means it passes)
        if_errors = []
        self._validate_value(data, if_schema, path, if_errors)
        
        if not if_errors:
            # 'if' condition passed → apply 'then' schema
            if then_schema:
                self._validate_value(data, then_schema, path, errors)
        else:
            # 'if' condition failed → apply 'else' schema
            if else_schema:
                self._validate_value(data, else_schema, path, errors)


    def _validate_all_of(self, data: Any, schemas: List[Dict], path: str, errors: List[ValidationError]):
        """Validate allOf - all schemas must pass"""
        for i, sub_schema in enumerate(schemas):
            sub_errors = self.validate(data, sub_schema, path)
            if sub_errors:
                errors.extend(sub_errors)
                
    def _validate_any_of(self, data: Any, schemas: List[Dict], path: str, errors: List[ValidationError]):
        """Validate anyOf - at least one schema must pass"""
        for sub_schema in schemas:
            sub_errors = self.validate(data, sub_schema, path)
            if not sub_errors:
                return  # Found valid schema
        errors.append(ValidationError("Value does not match any of the expected schemas", path))
        
    def _validate_one_of(self, data: Any, schemas: List[Dict], path: str, errors: List[ValidationError]):
        """Validate oneOf - exactly one schema must pass"""
        valid_count = 0
        for sub_schema in schemas:
            sub_errors = self.validate(data, sub_schema, path)
            if not sub_errors:
                valid_count += 1
                
        if valid_count == 0:
            errors.append(ValidationError("Value does not match any of the expected schemas", path))
        elif valid_count > 1:
            errors.append(ValidationError("Value matches more than one schema (oneOf violation)", path))
            
    def _validate_not(self, data: Any, schema: Dict, path: str, errors: List[ValidationError]):
        """Validate not - schema must not pass"""
        sub_errors = self.validate(data, schema, path)
        if not sub_errors:
            errors.append(ValidationError("Value matches forbidden schema", path))


class ErrorDisplayWidget(QWidget):
    """Widget to display validation errors"""
    
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        self.error_label = QLabel()
        self.error_label.setProperty("class", "error")
        self.error_label.setWordWrap(True)
        self.layout.addWidget(self.error_label)
        
        self.hide()
        
    def show_errors(self, errors: List[ValidationError]):
        if errors:
            error_text = "\n".join([f"• {error.message}" for error in errors[:5]])  # Show max 5 errors
            if len(errors) > 5:
                error_text += f"\n... and {len(errors) - 5} more errors"
            self.error_label.setText(error_text)
            self.show()
        else:
            self.hide()


class BaseFormWidget(QWidget):
    """Base class for all form widgets with validation support"""
    
    valueChanged = Signal()
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__()
        self.schema = schema
        self.resolver = resolver
        self.validator = validator
        self.path = path
        self.errors = []
        
        # Create error display
        self.error_widget = ErrorDisplayWidget()
        
    def get_value(self) -> Any:
        """Get the current value from the widget"""
        raise NotImplementedError
        
    def set_value(self, value: Any):
        """Set the widget value"""
        raise NotImplementedError
        
    def validate_value(self) -> List[ValidationError]:
        """Validate current value against schema"""
        try:
            value = self.get_value()
            return self.validator.validate(value, self.schema, self.path)
        except Exception as e:
            return [ValidationError(str(e), self.path)]
            
    def update_validation(self):
        """Update validation display"""
        self.errors = self.validate_value()
        self.error_widget.show_errors(self.errors)
        self.valueChanged.emit()


class StringWidget(BaseFormWidget):
    """Widget for string type with format support"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        layout = QVBoxLayout(self)
        
        # Determine widget type based on format
        format_type = schema.get("format", "")
        
        if format_type == "date":
            self.widget = QDateEdit()
            self.widget.setCalendarPopup(True)
            if "default" in schema:
                try:
                    default_date = QDate.fromString(str(schema["default"]), Qt.ISODate)
                    self.widget.setDate(default_date)
                except:
                    pass
        elif format_type == "time":
            self.widget = QTimeEdit()
            if "default" in schema:
                try:
                    default_time = QTime.fromString(str(schema["default"]), Qt.ISODate)
                    self.widget.setTime(default_time)
                except:
                    pass
        elif format_type == "date-time":
            self.widget = QDateTimeEdit()
            self.widget.setCalendarPopup(True)
            if "default" in schema:
                try:
                    default_datetime = QDateTime.fromString(str(schema["default"]), Qt.ISODate)
                    self.widget.setDateTime(default_datetime)
                except:
                    pass
        else:
            # Regular text input
            multiline = schema.get("maxLength", 0) > 100 or format_type in ["uri", "email"] and schema.get("maxLength", 0) > 50
            
            if multiline:
                self.widget = QTextEdit()
                self.widget.setMaximumHeight(100)
            else:
                self.widget = QLineEdit()
                
            if "default" in schema:
                if isinstance(self.widget, QTextEdit):
                    self.widget.setPlainText(str(schema["default"]))
                else:
                    self.widget.setText(str(schema["default"]))
                    
            # Set validation
            if "pattern" in schema:
                if isinstance(self.widget, QLineEdit):
                    validator = QRegularExpressionValidator()
                    validator.setRegularExpression(schema["pattern"])
                    self.widget.setValidator(validator)
                    
            # Set length constraints
            if isinstance(self.widget, QLineEdit):
                if "maxLength" in schema:
                    self.widget.setMaxLength(schema["maxLength"])
                    
        layout.addWidget(self.widget)
        layout.addWidget(self.error_widget)
        
        # Connect change signals
        if hasattr(self.widget, 'textChanged'):
            self.widget.textChanged.connect(self.update_validation)
        elif hasattr(self.widget, 'dateChanged'):
            self.widget.dateChanged.connect(self.update_validation)
        elif hasattr(self.widget, 'timeChanged'):
            self.widget.timeChanged.connect(self.update_validation)
        elif hasattr(self.widget, 'dateTimeChanged'):
            self.widget.dateTimeChanged.connect(self.update_validation)
            
    def get_value(self) -> str:
        if isinstance(self.widget, QTextEdit):
            return self.widget.toPlainText()
        elif isinstance(self.widget, QLineEdit):
            return self.widget.text()
        elif isinstance(self.widget, QDateEdit):
            return self.widget.date().toString(Qt.ISODate)
        elif isinstance(self.widget, QTimeEdit):
            return self.widget.time().toString(Qt.ISODate)
        elif isinstance(self.widget, QDateTimeEdit):
            return self.widget.dateTime().toString(Qt.ISODate)
        return ""
        
    def set_value(self, value: str):
        if isinstance(self.widget, QTextEdit):
            self.widget.setPlainText(str(value))
        elif isinstance(self.widget, QLineEdit):
            self.widget.setText(str(value))
        elif isinstance(self.widget, QDateEdit):
            date = QDate.fromString(str(value), Qt.ISODate)
            if date.isValid():
                self.widget.setDate(date)
        elif isinstance(self.widget, QTimeEdit):
            time = QTime.fromString(str(value), Qt.ISODate)
            if time.isValid():
                self.widget.setTime(time)
        elif isinstance(self.widget, QDateTimeEdit):
            datetime = QDateTime.fromString(str(value), Qt.ISODate)
            if datetime.isValid():
                self.widget.setDateTime(datetime)


class NumberWidget(BaseFormWidget):
    """Widget for number/integer types"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        layout = QVBoxLayout(self)
        
        is_integer = schema.get("type") == "integer"
        
        if is_integer:
            self.widget = QSpinBox()
            self.widget.setMinimum(schema.get("minimum", -2147483648))
            self.widget.setMaximum(schema.get("maximum", 2147483647))
        else:
            self.widget = QDoubleSpinBox()
            self.widget.setMinimum(schema.get("minimum", -1e9))
            self.widget.setMaximum(schema.get("maximum", 1e9))
            self.widget.setDecimals(6)
            
        if "default" in schema:
            self.widget.setValue(schema["default"])
            
        if "multipleOf" in schema:
            self.widget.setSingleStep(schema["multipleOf"])
            
        layout.addWidget(self.widget)
        layout.addWidget(self.error_widget)
        
        self.widget.valueChanged.connect(self.update_validation)
        
    def get_value(self) -> Union[int, float]:
        return self.widget.value()
        
    def set_value(self, value: Union[int, float]):
        self.widget.setValue(value)


class BooleanWidget(BaseFormWidget):
    """Widget for boolean type"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        layout = QVBoxLayout(self)
        
        self.widget = QCheckBox()
        if "default" in schema:
            self.widget.setChecked(bool(schema["default"]))
            
        layout.addWidget(self.widget)
        layout.addWidget(self.error_widget)
        
        self.widget.toggled.connect(self.update_validation)
        
    def get_value(self) -> bool:
        return self.widget.isChecked()
        
    def set_value(self, value: bool):
        self.widget.setChecked(bool(value))


class EnumWidget(BaseFormWidget):
    """Widget for enum constraints"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        layout = QVBoxLayout(self)
        
        self.widget = QComboBox()
        self.widget.setEditable(False)
        
        for item in schema["enum"]:
            self.widget.addItem(str(item), item)  # Store actual value as data
            
        if "default" in schema:
            index = self.widget.findData(schema["default"])
            if index >= 0:
                self.widget.setCurrentIndex(index)
                
        layout.addWidget(self.widget)
        layout.addWidget(self.error_widget)
        
        self.widget.currentIndexChanged.connect(self.update_validation)
        
    def get_value(self) -> Any:
        return self.widget.currentData()
        
    def set_value(self, value: Any):
        index = self.widget.findData(value)
        if index >= 0:
            self.widget.setCurrentIndex(index)


class ConstWidget(BaseFormWidget):
    """Widget for const values"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        layout = QVBoxLayout(self)
        
        self.const_value = schema["const"]
        self.widget = QLabel(str(self.const_value))
        self.widget.setStyleSheet("color: gray; font-style: italic;")
        
        layout.addWidget(self.widget)
        
    def get_value(self) -> Any:
        return self.const_value
        
    def set_value(self, value: Any):
        pass  # Const values cannot be changed


class ArrayWidget(BaseFormWidget):
    """Widget for array type with full Draft 2020-12 support"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        self.item_widgets = []
        self.items_schema = schema.get("items", {})
        
        layout = QVBoxLayout(self)
        
        # Header with add button
        header_layout = QHBoxLayout()
        array_title = schema.get("title", "Array Items")
        header_layout.addWidget(QLabel(f"{array_title}:"))
        header_layout.addStretch()
        
        self.add_button = QPushButton("Add Item")
        self.add_button.clicked.connect(self.add_item)
        header_layout.addWidget(self.add_button)
        
        layout.addLayout(header_layout)
        
        # Items container with better scrolling for complex items
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setMaximumHeight(400)
        
        items_container = QWidget()
        self.items_layout = QVBoxLayout(items_container)
        scroll_area.setWidget(items_container)
        
        layout.addWidget(scroll_area)
        layout.addWidget(self.error_widget)
        
        # Initialize with default items
        if "default" in schema and isinstance(schema["default"], list):
            for item in schema["default"]:
                self.add_item(item)
    
    def add_item(self, value: Any = None):
        """Enhanced item addition with better oneOf/anyOf handling"""
        index = len(self.item_widgets)
        item_path = f"{self.path}[{index}]"
        
        # Create item container with better layout
        item_container = QWidget()
        item_container.setProperty("class", "array-item")
        item_layout = QHBoxLayout(item_container)
        item_layout.setContentsMargins(10, 5, 10, 5)
        
        # Create index label for complex items
        if self._is_complex_schema(self.items_schema):
            index_label = QLabel(f"#{index + 1}")
            index_label.setMinimumWidth(30)
            index_label.setProperty("class", "array-index")
            item_layout.addWidget(index_label)
        
        # Create widget for item with parent value provider for conditionals
        item_widget = SchemaWidgetFactory.create_widget(
            self.items_schema, self.resolver, self.validator, item_path,
            parent_value_provider=lambda idx=index: self.get_item_context(idx)
        )
        
        # Set value if provided, with better error handling
        if value is not None:
            self._set_item_value_safely(item_widget, value)
                
        # Remove button
        remove_button = QPushButton("×")
        remove_button.setMaximumWidth(30)
        remove_button.setProperty("class", "remove-button")
        remove_button.clicked.connect(lambda: self.remove_item(index))
        
        item_layout.addWidget(item_widget, 1)  # Give item widget most space
        item_layout.addWidget(remove_button)
        
        self.items_layout.addWidget(item_container)
        self.item_widgets.append(item_widget)
        
        item_widget.valueChanged.connect(self.update_validation)
        self.update_validation()
    
    def _is_complex_schema(self, schema: Dict[str, Any]) -> bool:
        """Check if schema represents a complex type"""
        return any(key in schema for key in ["oneOf", "anyOf", "allOf", "if", "properties"])
    
    def _set_item_value_safely(self, item_widget: BaseFormWidget, value: Any):
        """Safely set item value with multiple fallback strategies"""
        try:
            item_widget.set_value(value)
        except Exception as e:
            print(f"Direct value setting failed: {e}")
            
            # Try type conversion based on schema
            try:
                converted_value = self._convert_value_for_schema(value, self.items_schema)
                item_widget.set_value(converted_value)
            except Exception as e2:
                print(f"Converted value setting failed: {e2}")
                
                # For oneOf/anyOf widgets, try setting empty and let them handle it
                if isinstance(item_widget, (OneOfWidget, AnyOfWidget)):
                    try:
                        # These widgets have their own value matching logic
                        item_widget.set_value(value)
                    except:
                        pass  # Let the widget remain with default values
    
    def get_item_context(self, index: int) -> Dict[str, Any]:
        """Get context for conditional evaluation in array items"""
        try:
            if 0 <= index < len(self.item_widgets):
                return {"index": index, "value": self.item_widgets[index].get_value()}
        except:
            pass
        return {"index": index}
    
    def remove_item(self, index: int):
        """Enhanced item removal with proper cleanup"""
        if 0 <= index < len(self.item_widgets):
            # Remove widget
            container = self.item_widgets[index].parent()
            self.items_layout.removeWidget(container)
            container.deleteLater()
            
            # Remove from list
            del self.item_widgets[index]
            
            # Update remaining item indices and labels
            for i, item_widget in enumerate(self.item_widgets):
                container = item_widget.parent()
                layout = container.layout()
                
                # Update index label if present
                if layout.count() > 2:  # Has index label
                    index_label = layout.itemAt(0).widget()
                    if isinstance(index_label, QLabel):
                        index_label.setText(f"#{i + 1}")
                
                # Update remove button
                remove_button = layout.itemAt(-1).widget()  # Last item
                remove_button.clicked.disconnect()
                remove_button.clicked.connect(lambda checked, idx=i: self.remove_item(idx))
            
            self.update_validation()


class ObjectWidget(BaseFormWidget):
    """Widget for object type with full property support"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        self.property_widgets = {}
        self.conditional_widgets = []
        
        layout = QVBoxLayout(self)
        
        # Create form for properties
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        if not properties:
            empty_label = QLabel("(No properties defined)")
            empty_label.setStyleSheet("color: gray; font-style: italic;")
            layout.addWidget(empty_label)
        
        for prop_name, prop_schema in properties.items():
            prop_path = f"{path}.{prop_name}" if path else prop_name
            
            label_text = self._get_property_label(prop_name, prop_schema, prop_name in required)
            label = QLabel(label_text)
            
            if prop_name in required:
                label.setProperty("class", "required")
                
            if "description" in prop_schema:
                desc_label = QLabel(prop_schema["description"])
                desc_label.setStyleSheet("color: gray; font-size: 10px; font-style: italic; margin-bottom: 5px;")
                desc_label.setWordWrap(True)
                layout.addWidget(desc_label)
                
            layout.addWidget(label)
            
            # Create widget for property
            #full_value_provider = self.parent_value_provider or (lambda: {})
            prop_widget = SchemaWidgetFactory.create_widget(
                prop_schema, self.resolver, self.validator, prop_path,
                parent_value_provider=lambda: self.get_value()
            )

            layout.addWidget(prop_widget)
            self.property_widgets[prop_name] = prop_widget
            
            # Track conditional widgets
            if isinstance(prop_widget, ConditionalWidget):
                self.conditional_widgets.append(prop_widget)
            
            prop_widget.valueChanged.connect(self._on_property_changed)
        
        layout.addWidget(self.error_widget)
        
        # Set default values
        if "default" in schema and isinstance(schema["default"], dict):
            for prop_name, value in schema["default"].items():
                if prop_name in self.property_widgets:
                    self.property_widgets[prop_name].set_value(value)
    
    def _on_property_changed(self):
        """Handle property value changes and update conditionals"""
        # Update all conditional child widgets
        current_data = self.get_value()
        for conditional_widget in self.conditional_widgets:
            conditional_widget.update_condition(current_data)
        
        # Emit our own change signal
        self.update_validation()
    
    def _get_property_label(self, prop_name: str, prop_schema: Dict[str, Any], is_required: bool) -> str:
        """Generate a meaningful label for a property"""
        if "title" in prop_schema:
            label_text = prop_schema["title"]
        else:
            label_text = prop_name.replace('_', ' ').title()
        
        if is_required:
            label_text += " *"
        
        return label_text
            
    def get_value(self) -> Dict[str, Any]:
        result = {}
        for prop_name, widget in self.property_widgets.items():
            try:
                value = widget.get_value()
                if value is not None:
                    result[prop_name] = value
            except Exception as e:
                print(f"Error getting value for {prop_name}: {e}")
        return result
        
    def set_value(self, value: Dict[str, Any]):
        if not isinstance(value, dict):
            return
            
        for prop_name, prop_value in value.items():
            if prop_name in self.property_widgets:
                try:
                    self.property_widgets[prop_name].set_value(prop_value)
                except Exception as e:
                    print(f"Error setting value for {prop_name}: {e}")
        
        # Update conditionals after setting values
        for conditional_widget in self.conditional_widgets:
            conditional_widget.update_condition(value)


class OneOfWidget(BaseFormWidget):
    """Widget for oneOf schema composition"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        self.option_widgets = []
        self.current_widget = None
        
        layout = QVBoxLayout(self)
        
        # Enhanced selector with better option titles
        self.selector = QComboBox()
        
        options = schema["oneOf"]
        for i, option in enumerate(options):
            title = self._generate_option_title(option, i)
            self.selector.addItem(title)
        
        layout.addWidget(QLabel("Select Option:"))
        layout.addWidget(self.selector)
        
        # Stacked widget container
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)
        
        # Create widgets for each option with parent value provider
        for i, option in enumerate(options):
            option_widget = SchemaWidgetFactory.create_widget(
                option, self.resolver, self.validator, f"{path}/oneOf[{i}]",
                parent_value_provider=lambda: self._get_parent_context()
            )
            self.option_widgets.append(option_widget)
            self.stacked_widget.addWidget(option_widget)
            option_widget.valueChanged.connect(self.update_validation)
        
        layout.addWidget(self.error_widget)
        
        self.selector.currentIndexChanged.connect(self.on_selection_changed)
        self.on_selection_changed(0)
    
    def _generate_option_title(self, option: Dict[str, Any], index: int) -> str:
        """Generate enhanced option titles"""
        if "title" in option:
            return option["title"]
        
        if "const" in option:
            return f"Constant: {option['const']}"
        
        # Handle nested compositions in titles
        if "oneOf" in option:
            return f"Choice of {len(option['oneOf'])} options"
        
        if "anyOf" in option:
            return f"Any of {len(option['anyOf'])} options"
        
        if "allOf" in option:
            return f"Combined schema"
        
        if "if" in option:
            return f"Conditional schema"
        
        if "properties" in option and option.get("type") == "object":
            props = list(option["properties"].keys())
            if len(props) <= 3:
                prop_str = ", ".join(props)
                return f"Object ({prop_str})"
            else:
                return f"Object ({len(props)} properties)"
        
        if "items" in option and option.get("type") == "array":
            items_schema = option["items"]
            if "type" in items_schema:
                return f"Array of {items_schema['type']}"
            else:
                return "Array"
        
        if "type" in option:
            return f"Type: {option['type']}"
        
        return f"Option {index + 1}"
    
    def _get_parent_context(self) -> Dict[str, Any]:
        """Get context for nested conditionals"""
        try:
            return {"selectedOption": self.selector.currentIndex()}
        except:
            return {}
    
    def set_value(self, value: Any):
        """Enhanced value setting with better matching"""
        best_match_index = 0
        best_match_score = float('inf')
        
        # Try each option to find the best match
        for i, widget in enumerate(self.option_widgets):
            try:
                # Create a copy to test without affecting the widget
                test_widget = SchemaWidgetFactory.create_widget(
                    self.schema["oneOf"][i], self.resolver, self.validator, f"test_{i}"
                )
                test_widget.set_value(value)
                errors = test_widget.validate_value()
                error_score = len(errors)
                
                # Prefer options with fewer validation errors
                if error_score < best_match_score:
                    best_match_score = error_score
                    best_match_index = i
                    
                # If we find a perfect match, use it immediately
                if error_score == 0:
                    self.selector.setCurrentIndex(i)
                    widget.set_value(value)
                    return
                    
            except Exception as e:
                continue
        
        # Use the best match we found
        self.selector.setCurrentIndex(best_match_index)
        try:
            self.option_widgets[best_match_index].set_value(value)
        except Exception as e:
            print(f"Could not set value on best match option: {e}")


class AnyOfWidget(BaseFormWidget):
    """Widget for anyOf schema composition"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        self.option_widgets = []
        self.checkboxes = []
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Select one or more options:"))
        
        options = schema["anyOf"]
        for i, option in enumerate(options):
            # Better title generation
            title = option.get("title", f"Option {i + 1}")
            
            if "const" in option:
                title = f"Constant: {option['const']}"
            elif option.get("type") == "object":
                if "properties" in option:
                    props = list(option["properties"].keys())
                    if len(props) == 1:
                        title = props[0].replace("_", " ").title()
                    elif "email" in props:
                        title = "Email Contact"
                    elif "phone" in props:
                        title = "Phone Contact"
                    else:
                        title = f"Contact Info ({', '.join(props)})"
            elif "type" in option:
                title = option["type"].title()
                
            checkbox = QCheckBox(title)
            option_widget = SchemaWidgetFactory.create_widget(
                option, self.resolver, self.validator, f"{path}/anyOf[{i}]",
                parent_value_provider=lambda: self.get_value()
            )
            
            # Initially hidden
            option_widget.setVisible(False)
            
            self.checkboxes.append(checkbox)
            self.option_widgets.append(option_widget)
            
            layout.addWidget(checkbox)
            layout.addWidget(option_widget)
            
            checkbox.toggled.connect(option_widget.setVisible)
            checkbox.toggled.connect(self.update_validation)
            option_widget.valueChanged.connect(self.update_validation)
            
        layout.addWidget(self.error_widget)
    
    def _get_option_title(self, option: Dict[str, Any], index: int) -> str:
        """Generate a meaningful title for an option"""
        if "title" in option:
            return option["title"]
        
        if "const" in option:
            return f"Constant: {option['const']}"
        
        if "properties" in option and option.get("type") == "object":
            # List key properties
            props = list(option["properties"].keys())[:3]  # First 3 properties
            prop_str = ", ".join(props)
            if len(option["properties"]) > 3:
                prop_str += "..."
            return f"Object ({prop_str})"
        
        if "type" in option:
            return f"Type: {option['type']}"
        
        return f"Option {index + 1}"
        
    def get_value(self) -> Any:
        """Return value from the first enabled option (not a list)"""
        for i, (checkbox, widget) in enumerate(zip(self.checkboxes, self.option_widgets)):
            if checkbox.isChecked():
                return widget.get_value()
        return None
        
    def set_value(self, value: Any):
        # Try to find which option matches the value
        for i, widget in enumerate(self.option_widgets):
            try:
                widget.set_value(value)
                errors = widget.validate_value()
                if not errors:
                    self.checkboxes[i].setChecked(True)
                    return
            except:
                continue


class AllOfWidget(BaseFormWidget):
    """Widget for allOf schema composition"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator, path: str = ""):
        super().__init__(schema, resolver, validator, path)
        
        layout = QVBoxLayout(self)
        
        # Check if any of the allOf schemas contain oneOf/anyOf
        self.has_nested_compositions = any(
            any(key in sub_schema for key in ["oneOf", "anyOf", "if"])
            for sub_schema in schema.get("allOf", [])
        )
        
        if self.has_nested_compositions:
            # Handle complex allOf with nested compositions
            self._create_complex_allof_widget(schema, layout)
        else:
            # Simple allOf - merge schemas and create single widget
            merged_schema = self.resolver.resolve_schema(schema)
            self.merged_widget = SchemaWidgetFactory.create_widget(
                merged_schema, self.resolver, self.validator, path
            )
            layout.addWidget(self.merged_widget)
            self.merged_widget.valueChanged.connect(self.update_validation)
        
        layout.addWidget(self.error_widget)
    
    def _create_complex_allof_widget(self, schema: Dict[str, Any], layout: QVBoxLayout):
        """Create widget for allOf with nested compositions"""
        self.sub_widgets = []
        all_of_schemas = schema["allOf"]
        
        # Create a container for all sub-widgets
        container = QWidget()
        container_layout = QVBoxLayout(container)
        
        # Create widgets for each allOf schema
        for i, sub_schema in enumerate(all_of_schemas):
            sub_path = f"{self.path}/allOf[{i}]"
            
            # Add separator for visual clarity
            if i > 0:
                separator = QFrame()
                separator.setFrameShape(QFrame.HLine)
                separator.setProperty("class", "allof-separator")
                container_layout.addWidget(separator)
            
            # Create widget for this sub-schema
            sub_widget = SchemaWidgetFactory.create_widget(
                sub_schema, self.resolver, self.validator, sub_path,
                parent_value_provider=lambda: self.get_combined_value()
            )
            
            container_layout.addWidget(sub_widget)
            self.sub_widgets.append(sub_widget)
            sub_widget.valueChanged.connect(self._on_sub_widget_changed)
        
        layout.addWidget(container)
        self.merged_widget = None  # Not used in complex mode
    
    def _on_sub_widget_changed(self):
        """Handle changes in sub-widgets"""
        # Update other sub-widgets that might have conditionals
        combined_value = self.get_combined_value()
        
        for widget in self.sub_widgets:
            if isinstance(widget, ConditionalWidget):
                widget.update_condition(combined_value)
        
        self.update_validation()
    
    def get_combined_value(self) -> Dict[str, Any]:
        """Get combined value from all sub-widgets"""
        if hasattr(self, 'sub_widgets'):
            combined = {}
            for widget in self.sub_widgets:
                try:
                    value = widget.get_value()
                    if isinstance(value, dict):
                        combined.update(value)
                except:
                    pass
            return combined
        return {}
    
    def get_value(self) -> Any:
        if self.merged_widget:
            return self.merged_widget.get_value()
        else:
            return self.get_combined_value()
    
    def set_value(self, value: Any):
        if self.merged_widget:
            self.merged_widget.set_value(value)
        else:
            # Set value on all sub-widgets
            for widget in self.sub_widgets:
                try:
                    widget.set_value(value)
                except:
                    pass


class ConditionalWidget(BaseFormWidget):
    """Enhanced conditional widget with deep nesting support"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator,
                 path: str = "", parent_value_provider: Optional[Callable[[], Any]] = None):
        super().__init__(schema, resolver, validator, path)
        
        self.if_schema = schema.get("if", {})
        self.then_schema = schema.get("then", {})
        self.else_schema = schema.get("else", {})
        self.parent_value_provider = parent_value_provider
        
        # Track nesting level to prevent infinite recursion
        self.nesting_level = getattr(parent_value_provider, '_nesting_level', 0) + 1
        self.max_nesting = 10
        
        self.layout = QVBoxLayout(self)
        self.active_widget = None
        self._current_value = None
        self._last_condition_result = None
        self._is_updating = False
        
        # Prevent infinite recursion
        if self.nesting_level > self.max_nesting:
            self._create_error_widget("Maximum conditional nesting exceeded")
            return
        
        # Start with a default widget
        self._create_default_widget()
    
    def _create_error_widget(self, message: str):
        """Create error display widget"""
        error_label = QLabel(f"Error: {message}")
        error_label.setStyleSheet("color: red; font-style: italic;")
        self.layout.addWidget(error_label)
        self.active_widget = error_label
    
    def _create_default_widget(self):
        """Create initial widget with better schema selection"""
        # Choose the most appropriate default schema
        default_schema = None
        
        if self.then_schema:
            default_schema = self.then_schema
        elif self.else_schema:
            default_schema = self.else_schema
        else:
            # Create a minimal fallback that handles common cases
            default_schema = {"type": "string", "title": "Conditional Field"}
        
        self._create_widget_for_schema(default_schema)
    
    def update_condition(self, parent_data: Any = None):
        """Enhanced condition update with recursion protection"""
        if self._is_updating or self.nesting_level > self.max_nesting:
            return
            
        self._is_updating = True
        try:
            if parent_data is None and self.parent_value_provider:
                try:
                    parent_data = self.parent_value_provider()
                except Exception as e:
                    print(f"Error getting parent data: {e}")
                    return
            
            # Evaluate condition
            condition_met = self._evaluate_condition(parent_data) if parent_data is not None else None
            
            # Only update if condition result changed
            if condition_met != self._last_condition_result:
                self._last_condition_result = condition_met
                
                # Choose appropriate schema
                target_schema = self._select_target_schema(condition_met)
                
                # Only recreate widget if schema actually changed
                current_schema = getattr(self, '_current_schema', None)
                if current_schema != target_schema:
                    self._current_schema = target_schema
                    self._create_widget_for_schema(target_schema)
        finally:
            self._is_updating = False
    
    def _select_target_schema(self, condition_met: Optional[bool]) -> Dict[str, Any]:
        """Select appropriate schema based on condition result"""
        if condition_met is True and self.then_schema:
            return self.then_schema
        elif condition_met is False and self.else_schema:
            return self.else_schema
        elif self.then_schema:  # Default to 'then' if condition can't be evaluated
            return self.then_schema
        elif self.else_schema:
            return self.else_schema
        else:
            # No schemas available - create empty object
            return {"type": "object", "properties": {}}
    
    def _evaluate_condition(self, data: Any) -> Optional[bool]:
        """Enhanced condition evaluation with better error handling"""
        if not self.if_schema:
            return True
            
        try:
            # Handle complex nested conditions
            if "allOf" in self.if_schema:
                return self._evaluate_all_of_condition(data, self.if_schema["allOf"])
            elif "anyOf" in self.if_schema:
                return self._evaluate_any_of_condition(data, self.if_schema["anyOf"])
            elif "oneOf" in self.if_schema:
                return self._evaluate_one_of_condition(data, self.if_schema["oneOf"])
            else:
                # Simple condition evaluation
                temp_resolver = SchemaResolver(self.if_schema)
                temp_validator = SchemaValidator(temp_resolver)
                errors = temp_validator.validate(data, self.if_schema)
                return len(errors) == 0
                
        except Exception as e:
            print(f"Condition evaluation error: {e}")
            return None
    
    def _evaluate_all_of_condition(self, data: Any, schemas: List[Dict]) -> bool:
        """Evaluate allOf condition"""
        for schema in schemas:
            temp_resolver = SchemaResolver(schema)
            temp_validator = SchemaValidator(temp_resolver)
            errors = temp_validator.validate(data, schema)
            if errors:
                return False
        return True
    
    def _evaluate_any_of_condition(self, data: Any, schemas: List[Dict]) -> bool:
        """Evaluate anyOf condition"""
        for schema in schemas:
            temp_resolver = SchemaResolver(schema)
            temp_validator = SchemaValidator(temp_resolver)
            errors = temp_validator.validate(data, schema)
            if not errors:
                return True
        return False
    
    def _evaluate_one_of_condition(self, data: Any, schemas: List[Dict]) -> bool:
        """Evaluate oneOf condition"""
        valid_count = 0
        for schema in schemas:
            temp_resolver = SchemaResolver(schema)
            temp_validator = SchemaValidator(temp_resolver)
            errors = temp_validator.validate(data, schema)
            if not errors:
                valid_count += 1
        return valid_count == 1
    
    def _create_widget_for_schema(self, schema: Dict[str, Any]):
        """Enhanced widget creation with nesting level tracking"""
        # Preserve current value
        if self.active_widget and hasattr(self.active_widget, 'get_value'):
            try:
                self._current_value = self.active_widget.get_value()
            except:
                pass
            
            # Clean up old widget
            self.layout.removeWidget(self.active_widget)
            self.active_widget.deleteLater()
        
        # Create new widget with nesting level tracking
        try:
            # Create parent value provider with nesting level
            nested_provider = None
            if self.parent_value_provider:
                def wrapped_provider():
                    result = self.parent_value_provider()
                    wrapped_provider._nesting_level = self.nesting_level
                    return result
                wrapped_provider._nesting_level = self.nesting_level
                nested_provider = wrapped_provider
            
            self.active_widget = SchemaWidgetFactory.create_widget(
                schema, self.resolver, self.validator, self.path,
                parent_value_provider=nested_provider
            )
        except Exception as e:
            print(f"Error creating conditional widget: {e}")
            # Fallback to simple string widget
            fallback_schema = {"type": "string", "title": f"Error: {str(e)}"}
            self.active_widget = StringWidget(fallback_schema, self.resolver, self.validator, self.path)
        
        self.layout.addWidget(self.active_widget)
        
        # Restore value if possible and compatible
        if self._current_value is not None:
            try:
                self.active_widget.set_value(self._current_value)
            except Exception as e:
                print(f"Could not restore value {self._current_value}: {e}")
        
        # Connect signals
        if hasattr(self.active_widget, 'valueChanged'):
            self.active_widget.valueChanged.connect(self.update_validation)
        
        self.update_validation()
    
    def get_value(self) -> Any:
        if self.active_widget and hasattr(self.active_widget, "get_value"):
            try:
                return self.active_widget.get_value()
            except Exception as e:
                print(f"ConditionalWidget: Error getting value: {e}")
                return None
        return None
    
    def set_value(self, value: Any):
        if self.active_widget and hasattr(self.active_widget, "set_value"):
            try:
                self.active_widget.set_value(value)
            except Exception as e:
                print(f"ConditionalWidget: Error setting value: {e}")


class SchemaWidgetFactory:
    """
    Enhanced factory for creating widgets from JSON Schema definitions
    Supports full Draft 2020-12 specification
    """
    
    @staticmethod
    def create_widget(schema: Dict[str, Any], resolver: SchemaResolver, 
                    validator: SchemaValidator, path: str = "", 
                    parent_value_provider: Optional[Callable[[], Any]] = None) -> BaseFormWidget:
        """Create appropriate widget for schema with better error handling"""
        
        # Track creation depth to prevent infinite recursion
        creation_depth = getattr(resolver, '_creation_depth', 0)
        if creation_depth > 20:
            error_schema = {"const": "Maximum widget creation depth exceeded"}
            return ConstWidget(error_schema, resolver, validator, path)
        
        resolver._creation_depth = creation_depth + 1
        
        try:
            # Handle boolean schemas
            if isinstance(schema, bool):
                schema = {"type": "object"} if schema else {"not": {}}
                
            if not isinstance(schema, dict):
                return ConstWidget({"const": "Invalid schema"}, resolver, validator, path)
            
            # Handle if/then/else conditionals FIRST (highest priority)
            if isinstance(schema, dict) and "if" in schema:
                return ConditionalWidget(schema, resolver, validator, path, parent_value_provider)
            
            # Resolve schema for other cases
            resolved_schema = resolver.resolve_schema(schema)
            
            # Handle const
            if "const" in resolved_schema:
                return ConstWidget(resolved_schema, resolver, validator, path)
                
            # Handle enum
            if "enum" in resolved_schema:
                return EnumWidget(resolved_schema, resolver, validator, path)
                
            # Handle composition keywords BEFORE type resolution
            # Use original schema to preserve composition structure
            if "oneOf" in schema:
                return OneOfWidget(schema, resolver, validator, path)
                
            if "anyOf" in schema:
                return AnyOfWidget(schema, resolver, validator, path)
                
            if "allOf" in schema:
                return AllOfWidget(schema, resolver, validator, path)
                
            # Handle type-based widgets
            schema_type = resolved_schema.get("type")
            
            if schema_type == "string":
                return StringWidget(resolved_schema, resolver, validator, path)
            elif schema_type in ["integer", "number"]:
                return NumberWidget(resolved_schema, resolver, validator, path)
            elif schema_type == "boolean":
                return BooleanWidget(resolved_schema, resolver, validator, path)
            elif schema_type == "array":
                return ArrayWidget(resolved_schema, resolver, validator, path)
            elif schema_type == "object":
                return ObjectWidget(resolved_schema, resolver, validator, path)
            elif schema_type == "null":
                return ConstWidget({"const": None}, resolver, validator, path)
                
            # Handle multiple types
            if isinstance(schema_type, list):
                type_schemas = []
                for t in schema_type:
                    type_schema = dict(resolved_schema)
                    type_schema["type"] = t
                    type_schemas.append(type_schema)
                multi_type_schema = {"oneOf": type_schemas}
                return OneOfWidget(multi_type_schema, resolver, validator, path)
            
            # Better fallback for schemas without explicit type
            if not schema_type:
                # Try to infer from other properties
                if "properties" in resolved_schema:
                    inferred_schema = dict(resolved_schema)
                    inferred_schema["type"] = "object"
                    return ObjectWidget(inferred_schema, resolver, validator, path)
                elif "items" in resolved_schema:
                    inferred_schema = dict(resolved_schema)
                    inferred_schema["type"] = "array"
                    return ArrayWidget(inferred_schema, resolver, validator, path)
                elif "enum" in resolved_schema:
                    return EnumWidget(resolved_schema, resolver, validator, path)
                else:
                    # Default to string input
                    return StringWidget({"type": "string"}, resolver, validator, path)
                    
        except Exception as e:
            print(f"Error creating widget for schema {schema}: {e}")
            # Return error widget instead of crashing
            error_schema = {"const": f"Schema Error: {str(e)}"}
            return ConstWidget(error_schema, resolver, validator, path)
        
        # Final fallback - should rarely reach here now
        return StringWidget({"type": "string", "title": "Unknown Schema"}, resolver, validator, path)


class JsonSchemaForm(QWidget):
    """
    Main JSON Schema form with full Draft 2020-12 support
    """
    
    def __init__(self, schema: Dict[str, Any], title: str = "JSON Schema Form"):
        super().__init__()
        
        self.setWindowTitle(title)
        self.setMinimumSize(800, 600)
        
        # Apply modern stylesheet
        self.setStyleSheet(MODERN_STYLESHEET)
        
        # Initialize components
        self.resolver = SchemaResolver(schema)
        self.validator = SchemaValidator(self.resolver)
        
        # Main layout with better spacing
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        if "title" in schema:
            title_label = QLabel(schema["title"])
            title_label.setProperty("class", "title")
            layout.addWidget(title_label)
            
        # Description
        if "description" in schema:
            desc_label = QLabel(schema["description"])
            desc_label.setProperty("class", "description")
            desc_label.setWordWrap(True)
            layout.addWidget(desc_label)
            
        # Form widget in scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        form_container = QWidget()
        form_layout = QVBoxLayout(form_container)
        
        self.form_widget = SchemaWidgetFactory.create_widget(
            schema, self.resolver, self.validator
        )
        form_layout.addWidget(self.form_widget)
        form_layout.addStretch()
        
        scroll_area.setWidget(form_container)
        layout.addWidget(scroll_area)
        
        # Modern button bar
        button_bar = QWidget()
        button_layout = QHBoxLayout(button_bar)
        
        self.validate_button = QPushButton("🔍 Validate")
        self.validate_button.clicked.connect(self.validate_form)
        
        self.get_data_button = QPushButton("📋 Get Data")
        self.get_data_button.clicked.connect(self.show_data)
        
        self.clear_button = QPushButton("🗑️ Clear")
        self.clear_button.clicked.connect(self.clear_form)
        
        button_layout.addStretch()
        button_layout.addWidget(self.validate_button)
        button_layout.addWidget(self.get_data_button)
        button_layout.addWidget(self.clear_button)
        
        layout.addWidget(button_bar)
        
    def get_form_data(self) -> Any:
        """Get current form data"""
        return self.form_widget.get_value()
        
    def set_form_data(self, data: Any):
        """Set form data"""
        self.form_widget.set_value(data)
        
    def validate_form(self):
        """Validate entire form and show results"""
        errors = self.form_widget.validate_value()
        
        if errors:
            error_text = "\n".join([f"• {error.path}: {error.message}" for error in errors])
            QMessageBox.warning(self, "Validation Errors", f"Found {len(errors)} errors:\n\n{error_text}")
        else:
            QMessageBox.information(self, "Validation", "Form is valid!")
            
    def show_data(self):
        """Show current form data as JSON"""
        try:
            data = self.get_form_data()
            json_text = json.dumps(data, indent=2, default=str)
            
            # Create dialog to show JSON
            from PySide6.QtWidgets import QDialog, QTextEdit
            dialog = QDialog(self)
            dialog.setWindowTitle("Form Data")
            dialog.setMinimumSize(500, 400)
            
            layout = QVBoxLayout(dialog)
            text_edit = QTextEdit()
            text_edit.setPlainText(json_text)
            layout.addWidget(text_edit)
            
            button_layout = QHBoxLayout()
            close_button = QPushButton("Close")
            close_button.clicked.connect(dialog.accept)
            button_layout.addStretch()
            button_layout.addWidget(close_button)
            layout.addLayout(button_layout)
            
            dialog.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to get form data: {str(e)}")
            
    def clear_form(self):
        """Clear all form data"""
        # This would require implementing clear methods on all widgets
        reply = QMessageBox.question(self, "Clear Form", "Are you sure you want to clear all data?")
        if reply == QMessageBox.Yes:
            # Recreate the form widget
            old_widget = self.form_widget
            self.form_widget = SchemaWidgetFactory.create_widget(
                self.resolver.root_schema, self.resolver, self.validator
            )
            
            # Replace in layout
            layout = self.layout()
            layout.replaceWidget(old_widget, self.form_widget)
            old_widget.deleteLater()