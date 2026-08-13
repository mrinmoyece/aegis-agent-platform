"""Strict JSON Schema validation at model and tool boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from aegis_agent_platform.domain import JsonSchema, JsonValue, ModelErrorClass
from aegis_agent_platform.domain.events import thaw_json
from aegis_agent_platform.domain.model import ModelGatewayError


def validate_schema(schema: JsonSchema) -> None:
    mutable_schema = cast(dict[str, object], thaw_json(schema.schema))
    try:
        Draft202012Validator.check_schema(mutable_schema)
    except SchemaError as error:
        raise ModelGatewayError(
            ModelErrorClass.SCHEMA,
            "invalid_json_schema",
            retryable=False,
        ) from error


def validate_object(
    value: Mapping[str, JsonValue],
    schema: JsonSchema,
) -> Mapping[str, JsonValue]:
    validate_schema(schema)
    mutable_schema = cast(dict[str, object], thaw_json(schema.schema))
    mutable_value = cast(dict[str, object], thaw_json(value))
    try:
        Draft202012Validator(mutable_schema).validate(mutable_value)
    except ValidationError as error:
        raise ModelGatewayError(
            ModelErrorClass.SCHEMA,
            "structured_output_validation_failed",
            retryable=False,
        ) from error
    return value


__all__ = ["validate_object", "validate_schema"]
