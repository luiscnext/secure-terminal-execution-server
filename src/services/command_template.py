"""
Command template engine for secure command execution.

Provides parameterized command templates with validation,
secure parameter substitution, and injection prevention.
"""

import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, validator

from src.core.exceptions import CommandNotFoundError, SecurityViolationError, ValidationError
from src.core.logging import get_logger

logger = get_logger(__name__)


class ParameterDefinition(BaseModel):
    """
    Definition of a command template parameter.
    """
    
    type: str = Field(description="Parameter type (string, int, float, bool, path, enum)")
    required: bool = Field(default=True, description="Whether parameter is required")
    default: Optional[Any] = Field(default=None, description="Default value if not provided")
    description: Optional[str] = Field(default=None, description="Parameter description")
    
    # Validation rules
    min_length: Optional[int] = Field(default=None, description="Minimum string length")
    max_length: Optional[int] = Field(default=None, description="Maximum string length")
    min_value: Optional[Union[int, float]] = Field(default=None, description="Minimum numeric value")
    max_value: Optional[Union[int, float]] = Field(default=None, description="Maximum numeric value")
    pattern: Optional[str] = Field(default=None, description="Regex pattern for validation")
    allowed_values: Optional[List[Any]] = Field(default=None, description="Enum values")
    
    # Path-specific validation
    allowed_paths: Optional[List[str]] = Field(default=None, description="Allowed path prefixes")
    forbidden_paths: Optional[List[str]] = Field(default=None, description="Forbidden path prefixes")
    
    @validator('type')
    def validate_type(cls, v):
        valid_types = ['string', 'int', 'float', 'bool', 'path', 'enum']
        if v not in valid_types:
            raise ValueError(f"Parameter type must be one of {valid_types}")
        return v


class CommandTemplate(BaseModel):
    """
    Command template definition.
    """
    
    name: str = Field(description="Template name")
    command: str = Field(description="Command template with {param} placeholders")
    description: Optional[str] = Field(default=None, description="Template description")
    category: Optional[str] = Field(default="general", description="Command category")
    
    # Parameters
    parameters: Dict[str, ParameterDefinition] = Field(
        default_factory=dict,
        description="Parameter definitions"
    )
    
    # Security settings
    permissions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Required permissions and constraints"
    )
    
    # Execution settings
    timeout: int = Field(default=300, description="Execution timeout in seconds")
    memory_limit: str = Field(default="512m", description="Memory limit")
    cpu_limit: float = Field(default=0.5, description="CPU limit")
    
    # Safety settings
    allow_network: bool = Field(default=False, description="Allow network access")
    allow_file_write: bool = Field(default=False, description="Allow file write operations")
    sandbox_image: Optional[str] = Field(default=None, description="Custom sandbox image")
    
    @validator('command')
    def validate_command_template(cls, v):
        # Check for dangerous patterns
        dangerous_patterns = [
            r'[;&|`$()]',  # Shell metacharacters
            r'\\',        # Backslashes
            r'\.\./',     # Directory traversal
            r'sudo|su ',  # Privilege escalation
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, v):
                raise ValueError(f"Command template contains dangerous pattern: {pattern}")
        
        return v


class ParameterValidator:
    """
    Validates command parameters against their definitions.
    """
    
    @staticmethod
    def validate_parameter(
        name: str,
        value: Any,
        definition: ParameterDefinition
    ) -> Any:
        """
        Validate a single parameter value.
        
        Args:
            name: Parameter name
            value: Parameter value
            definition: Parameter definition
            
        Returns:
            Validated and converted value
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            # Handle required parameters
            if value is None:
                if definition.required and definition.default is None:
                    raise ValidationError(f"Parameter '{name}' is required")
                value = definition.default
            
            if value is None:
                return None
            
            # Type conversion and validation
            if definition.type == "string":
                value = str(value)
                return ParameterValidator._validate_string(name, value, definition)
            
            elif definition.type == "int":
                value = int(value)
                return ParameterValidator._validate_numeric(name, value, definition)
            
            elif definition.type == "float":
                value = float(value)
                return ParameterValidator._validate_numeric(name, value, definition)
            
            elif definition.type == "bool":
                if isinstance(value, str):
                    value = value.lower() in ('true', '1', 'yes', 'on')
                return bool(value)
            
            elif definition.type == "path":
                value = str(value)
                return ParameterValidator._validate_path(name, value, definition)
            
            elif definition.type == "enum":
                return ParameterValidator._validate_enum(name, value, definition)
            
            else:
                raise ValidationError(f"Unknown parameter type: {definition.type}")
        
        except (ValueError, TypeError) as e:
            raise ValidationError(f"Parameter '{name}' validation failed: {e}")
    
    @staticmethod
    def _validate_string(name: str, value: str, definition: ParameterDefinition) -> str:
        """
        Validate string parameter.
        """
        # Length validation
        if definition.min_length is not None and len(value) < definition.min_length:
            raise ValidationError(f"Parameter '{name}' too short (min: {definition.min_length})")
        
        if definition.max_length is not None and len(value) > definition.max_length:
            raise ValidationError(f"Parameter '{name}' too long (max: {definition.max_length})")
        
        # Pattern validation
        if definition.pattern:
            if not re.match(definition.pattern, value):
                raise ValidationError(f"Parameter '{name}' does not match required pattern")
        
        # Check for dangerous content
        dangerous_chars = ['`', '$', ';', '&', '|', '>', '<', '\n', '\r']
        if any(char in value for char in dangerous_chars):
            raise SecurityViolationError(f"Parameter '{name}' contains dangerous characters")
        
        return value
    
    @staticmethod
    def _validate_numeric(name: str, value: Union[int, float], definition: ParameterDefinition) -> Union[int, float]:
        """
        Validate numeric parameter.
        """
        if definition.min_value is not None and value < definition.min_value:
            raise ValidationError(f"Parameter '{name}' below minimum (min: {definition.min_value})")
        
        if definition.max_value is not None and value > definition.max_value:
            raise ValidationError(f"Parameter '{name}' above maximum (max: {definition.max_value})")
        
        return value
    
    @staticmethod
    def _validate_path(name: str, value: str, definition: ParameterDefinition) -> str:
        """
        Validate path parameter with security checks.
        """
        # Normalize path
        path = Path(value).resolve()
        path_str = str(path)
        
        # Check for directory traversal
        if '..' in value or path_str != value:
            raise SecurityViolationError(f"Parameter '{name}' contains directory traversal")
        
        # Check allowed paths
        if definition.allowed_paths:
            allowed = any(path_str.startswith(allowed_path) for allowed_path in definition.allowed_paths)
            if not allowed:
                raise SecurityViolationError(f"Parameter '{name}' path not in allowed locations")
        
        # Check forbidden paths
        if definition.forbidden_paths:
            forbidden = any(path_str.startswith(forbidden_path) for forbidden_path in definition.forbidden_paths)
            if forbidden:
                raise SecurityViolationError(f"Parameter '{name}' path in forbidden location")
        
        return path_str
    
    @staticmethod
    def _validate_enum(name: str, value: Any, definition: ParameterDefinition) -> Any:
        """
        Validate enum parameter.
        """
        if not definition.allowed_values:
            raise ValidationError(f"Parameter '{name}' enum has no allowed values defined")
        
        if value not in definition.allowed_values:
            raise ValidationError(
                f"Parameter '{name}' must be one of {definition.allowed_values}, got {value}"
            )
        
        return value


class CommandTemplateEngine:
    """
    Command template engine for secure command execution.
    
    Loads templates from configuration, validates parameters,
    and generates safe command strings.
    """
    
    def __init__(self, config_path: str = "config/command_templates.yaml"):
        self.config_path = config_path
        self.templates: Dict[str, CommandTemplate] = {}
        self.validator = ParameterValidator()
        self.load_templates()
    
    def load_templates(self) -> None:
        """
        Load command templates from configuration file.
        
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValidationError: If template validation fails
        """
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            self.templates = {}
            
            for name, template_data in config.get('templates', {}).items():
                # Parse parameter definitions
                parameters = {}
                for param_name, param_data in template_data.get('parameters', {}).items():
                    parameters[param_name] = ParameterDefinition(**param_data)
                
                # Create template
                template_data['parameters'] = parameters
                template = CommandTemplate(name=name, **template_data)
                self.templates[name] = template
            
            logger.info(f"Loaded {len(self.templates)} command templates", config_path=self.config_path)
        
        except FileNotFoundError:
            logger.error(f"Command template config not found: {self.config_path}")
            raise
        except Exception as e:
            logger.error(f"Failed to load command templates: {e}")
            raise ValidationError(f"Template loading failed: {e}")
    
    def get_template(self, name: str) -> CommandTemplate:
        """
        Get a command template by name.
        
        Args:
            name: Template name
            
        Returns:
            Command template
            
        Raises:
            CommandNotFoundError: If template doesn't exist
        """
        if name not in self.templates:
            raise CommandNotFoundError(f"Command template '{name}' not found")
        
        return self.templates[name]
    
    def list_templates(self, category: Optional[str] = None) -> List[CommandTemplate]:
        """
        List available command templates.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of command templates
        """
        templates = list(self.templates.values())
        
        if category:
            templates = [t for t in templates if t.category == category]
        
        return templates
    
    def validate_parameters(
        self,
        template_name: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate parameters against template definition.
        
        Args:
            template_name: Template name
            parameters: Parameter values
            
        Returns:
            Validated parameters
            
        Raises:
            CommandNotFoundError: If template doesn't exist
            ValidationError: If validation fails
        """
        template = self.get_template(template_name)
        validated_params = {}
        
        # Check for unknown parameters
        unknown_params = set(parameters.keys()) - set(template.parameters.keys())
        if unknown_params:
            raise ValidationError(f"Unknown parameters: {unknown_params}")
        
        # Validate each parameter
        for param_name, param_def in template.parameters.items():
            value = parameters.get(param_name)
            validated_value = self.validator.validate_parameter(param_name, value, param_def)
            validated_params[param_name] = validated_value
        
        return validated_params
    
    def resolve_command(
        self,
        template_name: str,
        parameters: Dict[str, Any]
    ) -> str:
        """
        Resolve command template with parameters.
        
        Args:
            template_name: Template name
            parameters: Parameter values
            
        Returns:
            Resolved command string
            
        Raises:
            CommandNotFoundError: If template doesn't exist
            ValidationError: If validation fails
        """
        template = self.get_template(template_name)
        validated_params = self.validate_parameters(template_name, parameters)
        
        # Safely substitute parameters
        try:
            # Use format() with validated parameters for safe substitution
            resolved_command = template.command.format(**validated_params)
            
            # Final safety check - ensure no shell metacharacters were introduced
            if any(char in resolved_command for char in ['`', '$', ';', '&', '|']):
                raise SecurityViolationError("Resolved command contains dangerous characters")
            
            logger.info(
                "Command resolved",
                template=template_name,
                resolved_command=resolved_command,
                parameters=validated_params
            )
            
            return resolved_command
        
        except KeyError as e:
            raise ValidationError(f"Template parameter substitution failed: {e}")
        except Exception as e:
            raise ValidationError(f"Command resolution failed: {e}")


# Global template engine instance
_template_engine: Optional[CommandTemplateEngine] = None


def get_template_engine() -> CommandTemplateEngine:
    """
    Get the global command template engine instance.
    
    Returns:
        Command template engine
    """
    global _template_engine
    
    if _template_engine is None:
        _template_engine = CommandTemplateEngine()
    
    return _template_engine
