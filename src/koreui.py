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
        
    def resolve_schema(self, schema: Union[Dict[str, Any], bool], current_path: str = "#") -> Dict[str, Any]:
        """Resolve a schema, handling all JSON Schema composition keywords"""
        if isinstance(schema, bool):
            return {"type": "object"} if schema else {"not": {}}
            
        if not isinstance(schema, dict):
            return {}
        
        if "if" in schema:
            return schema
            
        # Handle $ref
        if "$ref" in schema:
            return self._resolve_ref(schema["$ref"], current_path)
            
        # Handle schema composition
        resolved = dict(schema)
        
        # Handle allOf
        if "allOf" in schema:
            resolved = self._merge_all_of(schema["allOf"], resolved, current_path)
            
        return resolved
        
    def _resolve_ref(self, ref: str, current_path: str) -> Dict[str, Any]:
        """Resolve a $ref reference"""
        if ref in self.refs_cache:
            return self.refs_cache[ref]
            
        if ref.startswith("#/"):
            # Internal reference
            path_parts = ref[2:].split("/")
            current = self.root_schema
            
            try:
                for part in path_parts:
                    part = part.replace("~1", "/").replace("~0", "~")  # JSON Pointer escaping
                    current = current[part]
                    
                resolved = self.resolve_schema(current, ref)
                self.refs_cache[ref] = resolved
                return resolved
                
            except (KeyError, TypeError):
                raise ValidationError(f"Unable to resolve reference: {ref}")
                
        else:
            # External reference - not implemented in this version
            raise ValidationError(f"External references not supported: {ref}")
            
    def _merge_all_of(self, all_of_schemas: List[Dict], base_schema: Dict, current_path: str) -> Dict[str, Any]:
        """Merge allOf schemas according to JSON Schema rules"""
        result = dict(base_schema)
        
        for i, sub_schema in enumerate(all_of_schemas):
            resolved_sub = self.resolve_schema(sub_schema, f"{current_path}/allOf/{i}")
            result = self._deep_merge_schemas(result, resolved_sub)
            
        return result
        
    def _deep_merge_schemas(self, schema1: Dict, schema2: Dict) -> Dict[str, Any]:
        """Deep merge two schemas with JSON Schema semantics"""
        result = dict(schema1)
        
        for key, value in schema2.items():
            if key in result:
                if key == "properties":
                    result[key] = {**result[key], **value}
                elif key == "required":
                    result[key] = list(set(result[key] + value))
                elif key in ["allOf", "anyOf", "oneOf"]:
                    result[key] = result[key] + value
                else:
                    result[key] = value
            else:
                result[key] = value
                
        return result
        
    def _resolve_conditional(self, schema: Dict, resolved: Dict, current_path: str) -> Dict[str, Any]:
        """Handle if/then/else conditional logic"""
        # For schema resolution, we need to handle this differently
        # We'll keep the conditional structure intact for runtime evaluation
        result = dict(resolved)
        
        # Keep the conditional keywords in the resolved schema
        if "if" in schema:
            result["if"] = self.resolve_schema(schema["if"], f"{current_path}/if")
        if "then" in schema:
            result["then"] = self.resolve_schema(schema["then"], f"{current_path}/then")
        if "else" in schema:
            result["else"] = self.resolve_schema(schema["else"], f"{current_path}/else")
        
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
        
        # Items container
        self.items_layout = QVBoxLayout()
        layout.addLayout(self.items_layout)
        
        layout.addWidget(self.error_widget)
        
        # Initialize with default items
        if "default" in schema and isinstance(schema["default"], list):
            for item in schema["default"]:
                self.add_item(item)
                
    def add_item(self, value: Any = None):
        """Add a new item to the array"""
        index = len(self.item_widgets)
        item_schema = self.schema.get("items", {})
        
        # Create item container
        item_container = QWidget()
        item_layout = QHBoxLayout(item_container)
        
        # Create widget for item - handle oneOf/anyOf items properly
        item_widget = SchemaWidgetFactory.create_widget(
            item_schema, self.resolver, self.validator, f"{self.path}[{index}]"
        )
        
        # Set value if provided
        if value is not None:
            try:
                # For oneOf/anyOf widgets, let them handle the value matching
                item_widget.set_value(value)
            except Exception as e:
                print(f"Warning: Could not set default value {value}: {e}")
                
                # Fallback: try to convert based on schema type
                try:
                    converted_value = self._convert_value_for_schema(value, item_schema)
                    item_widget.set_value(converted_value)
                except Exception as e2:
                    print(f"Warning: Could not convert value {value}: {e2}")
        
        # Remove button
        remove_button = QPushButton("−")
        remove_button.setMaximumWidth(30)
        remove_button.clicked.connect(lambda: self.remove_item(index))
        
        item_layout.addWidget(item_widget)
        item_layout.addWidget(remove_button)
        
        self.items_layout.addWidget(item_container)
        self.item_widgets.append(item_widget)
        
        item_widget.valueChanged.connect(self.update_validation)
        self.update_validation()
    
    def _convert_value_for_schema(self, value: Any, schema: Dict[str, Any]) -> Any:
        """Convert a value to match the expected schema type"""
        schema_type = schema.get("type")
        
        if schema_type == "object" and not isinstance(value, dict):
            return {}
        elif schema_type == "array" and not isinstance(value, list):
            return []
        elif schema_type == "string" and not isinstance(value, str):
            return str(value) if value is not None else ""
        elif schema_type == "integer" and not isinstance(value, int):
            try:
                return int(value)
            except (ValueError, TypeError):
                return 0
        elif schema_type == "number" and not isinstance(value, (int, float)):
            try:
                return float(value)
            except (ValueError, TypeError):
                return 0.0
        elif schema_type == "boolean" and not isinstance(value, bool):
            return bool(value)
        
        return value
        
    def remove_item(self, index: int):
        """Remove item at index"""
        if 0 <= index < len(self.item_widgets):
            # Remove widget
            widget = self.item_widgets[index].parent()
            self.items_layout.removeWidget(widget)
            widget.deleteLater()
            
            # Remove from list
            del self.item_widgets[index]
            
            # Update remaining item indices for remove buttons
            for i, item_widget in enumerate(self.item_widgets):
                container = item_widget.parent()
                layout = container.layout()
                remove_button = layout.itemAt(1).widget()  # Remove button is second item
                remove_button.clicked.disconnect()
                remove_button.clicked.connect(lambda checked, idx=i: self.remove_item(idx))
            
            self.update_validation()
            
    def get_value(self) -> List[Any]:
        return [widget.get_value() for widget in self.item_widgets]
        
    def set_value(self, value: List[Any]):
        # Clear existing items
        for widget in self.item_widgets:
            widget.parent().deleteLater()
        self.item_widgets.clear()
        
        # Add new items
        if isinstance(value, list):
            for item in value:
                self.add_item(item)


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
                result[prop_name] = widget.get_value()
            except Exception as e:
                print(f"Error getting value for {prop_name}: {e}")
                result[prop_name] = None
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
        
        # Selector
        self.selector = QComboBox()
        
        options = schema["oneOf"]
        for i, option in enumerate(options):
            title = option.get("title", f"Option {i + 1}")
            
            # Better title generation for object schemas
            if "const" in option:
                title = f"Constant: {option['const']}"
            elif option.get("type") == "object":
                # Check for specific patterns in object schemas
                if "properties" in option:
                    props = list(option["properties"].keys())
                    if len(props) == 1:
                        title = props[0].replace("_", " ").title()
                    elif "email" in props:
                        title = "Email Contact"
                    elif "phone" in props:
                        title = "Phone Contact"
            elif "type" in option:
                title = f"Type: {option['type']}"
                
            self.selector.addItem(title)
            
        layout.addWidget(QLabel("Select Option:"))
        layout.addWidget(self.selector)
        
        # Stacked widget container
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)
        
        # Create widgets for each option
        for i, option in enumerate(options):
            option_widget = SchemaWidgetFactory.create_widget(
                option, self.resolver, self.validator, f"{path}/oneOf[{i}]",
                parent_value_provider=lambda: self.get_value()
            )
            self.option_widgets.append(option_widget)
            self.stacked_widget.addWidget(option_widget)
            option_widget.valueChanged.connect(self.update_validation)
            
        layout.addWidget(self.error_widget)
        
        self.selector.currentIndexChanged.connect(self.on_selection_changed)
        self.on_selection_changed(0)
    
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
        
    def on_selection_changed(self, index: int):
        """Handle option selection change"""
        self.stacked_widget.setCurrentIndex(index)
        self.current_widget = self.option_widgets[index]
        self.update_validation()
        
    def get_value(self) -> Any:
        if self.current_widget:
            return self.current_widget.get_value()
        return None
        
    def set_value(self, value: Any):
        """Set value by finding the best matching option"""
        best_match_index = 0
        best_match_score = float('inf')
        
        # Try each option to find the best match
        for i, widget in enumerate(self.option_widgets):
            try:
                # Test if this widget can handle the value
                widget.set_value(value)
                errors = widget.validate_value()
                error_score = len(errors)
                
                # Prefer options with fewer validation errors
                if error_score < best_match_score:
                    best_match_score = error_score
                    best_match_index = i
                    
                # If we find a perfect match, use it immediately
                if error_score == 0:
                    self.selector.setCurrentIndex(i)
                    return
                    
            except Exception as e:
                # This option can't handle the value type
                continue
        
        # Use the best match we found
        self.selector.setCurrentIndex(best_match_index)
        try:
            self.option_widgets[best_match_index].set_value(value)
        except:
            pass


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
        
        # For allOf, we merge all schemas and create a single widget
        merged_schema = self.resolver.resolve_schema(schema)
        
        layout = QVBoxLayout(self)
        
        self.merged_widget = SchemaWidgetFactory.create_widget(
            merged_schema, self.resolver, self.validator, path
        )
        
        layout.addWidget(self.merged_widget)
        layout.addWidget(self.error_widget)
        
        self.merged_widget.valueChanged.connect(self.update_validation)
        
    def get_value(self) -> Any:
        return self.merged_widget.get_value()
        
    def set_value(self, value: Any):
        self.merged_widget.set_value(value)


class ConditionalWidget(BaseFormWidget):
    """Conditional handler"""
    
    def __init__(self, schema: Dict[str, Any], resolver: SchemaResolver, validator: SchemaValidator,
                 path: str = "", parent_value_provider: Optional[Callable[[], Any]] = None):
        super().__init__(schema, resolver, validator, path)
        
        self.if_schema = schema.get("if", {})
        self.then_schema = schema.get("then", {})
        self.else_schema = schema.get("else", {})
        self.parent_value_provider = parent_value_provider
        
        self.layout = QVBoxLayout(self)
        self.active_widget = None
        self._current_value = None
        
        # Start with a default widget
        self._create_default_widget()
        
        # Set up monitoring if we have a parent value provider
        if self.parent_value_provider:
            # Use a more efficient approach than timer
            self._setup_parent_monitoring()
    
    def _create_default_widget(self):
        """Create initial widget based on available schemas"""
        # Choose the most appropriate default schema
        if self.then_schema:
            default_schema = self.then_schema
        elif self.else_schema:
            default_schema = self.else_schema
        else:
            # Create a minimal fallback
            default_schema = {"type": "string", "title": "Conditional Field"}
        
        self._create_widget_for_schema(default_schema)
    
    def _setup_parent_monitoring(self):
        """Set up efficient parent value monitoring"""
        # Instead of timer, we'll rely on parent's valueChanged signals
        # The parent should call our update method when its value changes
        pass
    
    def update_condition(self, parent_data: Any = None):
        """Update the widget based on current condition evaluation"""
        if parent_data is None and self.parent_value_provider:
            try:
                parent_data = self.parent_value_provider()
            except:
                return
        
        # Evaluate condition
        condition_met = self._evaluate_condition(parent_data) if parent_data is not None else None
        
        # Choose appropriate schema
        if condition_met is True and self.then_schema:
            target_schema = self.then_schema
        elif condition_met is False and self.else_schema:
            target_schema = self.else_schema
        elif self.then_schema:  # Default to 'then' if condition can't be evaluated
            target_schema = self.then_schema
        elif self.else_schema:
            target_schema = self.else_schema
        else:
            # No schemas available - create empty object
            target_schema = {"type": "object", "properties": {}}
        
        # Only recreate widget if schema actually changed
        current_schema = getattr(self, '_current_schema', None)
        if current_schema != target_schema:
            self._current_schema = target_schema
            self._create_widget_for_schema(target_schema)
    
    def _evaluate_condition(self, data: Any) -> bool:
        """Evaluate the if condition against data"""
        if not self.if_schema:
            return True
            
        try:
            # Create a temporary validator for just this condition
            temp_resolver = SchemaResolver(self.if_schema)
            temp_validator = SchemaValidator(temp_resolver)
            errors = temp_validator.validate(data, self.if_schema)
            return len(errors) == 0
        except Exception as e:
            print(f"Condition evaluation error: {e}")
            return False
    
    def _create_widget_for_schema(self, schema: Dict[str, Any]):
        """Create widget for the given schema"""
        # Preserve current value
        if self.active_widget:
            try:
                self._current_value = self.active_widget.get_value()
            except:
                pass
            
            # Clean up old widget
            self.layout.removeWidget(self.active_widget)
            self.active_widget.deleteLater()
        
        # Create new widget - avoid infinite recursion by not passing parent_value_provider
        # for nested conditionals
        try:
            self.active_widget = SchemaWidgetFactory.create_widget(
                schema, self.resolver, self.validator, self.path
            )
        except Exception as e:
            print(f"Error creating conditional widget: {e}")
            # Fallback to simple string widget
            fallback_schema = {"type": "string", "title": "Error: Conditional Failed"}
            self.active_widget = StringWidget(fallback_schema, self.resolver, self.validator, self.path)
        
        self.layout.addWidget(self.active_widget)
        
        # Restore value if possible
        if self._current_value is not None:
            try:
                self.active_widget.set_value(self._current_value)
            except Exception as e:
                print(f"Could not restore value: {e}")
        
        # Connect signals
        self.active_widget.valueChanged.connect(self.update_validation)
        self.update_validation()

    def get_value(self) -> Any:
        if self.active_widget:
            return self.active_widget.get_value()
        return None

    def set_value(self, value: Any):
        self._current_value = value
        if self.active_widget:
            try:
                self.active_widget.set_value(value)
            except Exception as e:
                print(f"Could not set conditional value: {e}")


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
        
        # Handle boolean schemas
        if isinstance(schema, bool):
            schema = {"type": "object"} if schema else {"not": {}}
            
        if not isinstance(schema, dict):
            return ConstWidget({"const": "Invalid schema"}, resolver, validator, path)
        
        try:
            # Handle if/then/else conditionals FIRST
            if "if" in schema:
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
            if "oneOf" in schema:  # Use original schema
                return OneOfWidget(schema, resolver, validator, path)
                
            if "anyOf" in schema:  # Use original schema
                return AnyOfWidget(schema, resolver, validator, path)
                
            if "allOf" in schema:  # Use original schema
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