"""The small JSON Schema subset that conforms() checks responses with."""

import pytest
from estate import problems

API = {"components": {"schemas": {"Name": {"type": "string", "minLength": 1}}}}


@pytest.mark.parametrize(
    ("schema", "value", "ok"),
    [
        ({"type": "integer"}, 3, True),
        ({"type": "integer"}, True, False),
        ({"type": ["string", "null"]}, None, True),
        ({"type": "integer", "minimum": 1}, 0, False),
        ({"type": "integer", "minimum": 1}, 1, True),
        ({"type": "integer", "maximum": 200}, 200, True),
        ({"type": "integer", "maximum": 200}, 201, False),
        ({"type": "string", "minLength": 1}, "", False),
        ({"type": "string", "minLength": 1}, "a", True),
        ({"type": "string", "maxLength": 3}, "abcd", False),
        ({"type": "string", "maxLength": 3}, "abc", True),
        ({"type": "array", "minItems": 1}, [], False),
        ({"type": "array", "maxItems": 2}, [1, 2, 3], False),
        ({"type": "array", "maxItems": 2}, [1, 2], True),
        ({"type": "string", "enum": ["a"]}, "b", False),
        ({"$ref": "#/components/schemas/Name"}, "", False),
        ({"type": "object", "required": ["a"]}, {}, False),
        ({"type": "object", "additionalProperties": False, "properties": {}}, {"x": 1}, False),
        (
            {"type": "object", "properties": {"n": {"type": "integer", "maximum": 1}}},
            {"n": 2},
            False,
        ),
    ],
)
def test_problems(schema, value, ok):
    assert (problems(API, schema, value) == []) is ok, problems(API, schema, value)
