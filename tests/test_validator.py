"""Tests for hex TLV validators (Level 1: format, Level 2: structure, Level 3: semantic)."""

import pytest
from emv_tlv.validators import (
    validate_hex, ValidationResult, ValidationError, FormatValidator,
    StructureValidator, SemanticValidator,
)


# =============================================================================
# Format Validation (Level 1)
# =============================================================================

class TestFormatValidator:
    def test_valid_hex(self):
        """Valid hex string passes."""
        result = FormatValidator.validate("9A03210315")
        assert result.valid is True
        assert result.cleaned_hex == "9A03210315"
        assert len(result.errors) == 0

    def test_valid_hex_with_spaces(self):
        """Spaces are stripped."""
        result = FormatValidator.validate("9A 03 21 03 15")
        assert result.valid is True
        assert result.cleaned_hex == "9A03210315"

    def test_valid_hex_with_newlines(self):
        """Newlines are stripped."""
        result = FormatValidator.validate("9A03\n2103\n15")
        assert result.valid is True
        assert result.cleaned_hex == "9A03210315"

    def test_valid_hex_with_hyphens(self):
        """Hyphens are stripped."""
        result = FormatValidator.validate("9A-03-21-03-15")
        assert result.valid is True
        assert result.cleaned_hex == "9A03210315"

    def test_valid_hex_with_colons(self):
        """Colons are stripped."""
        result = FormatValidator.validate("9A:03:21:03:15")
        assert result.valid is True
        assert result.cleaned_hex == "9A03210315"

    def test_empty_input(self):
        """Empty input fails."""
        result = FormatValidator.validate("")
        assert result.valid is False
        assert any(e.code == "EMPTY_INPUT" for e in result.errors)

    def test_whitespace_only(self):
        """Whitespace-only input fails."""
        result = FormatValidator.validate("   \n  \t  ")
        assert result.valid is False
        assert any(e.code == "EMPTY_INPUT" for e in result.errors)

    def test_invalid_hex_char(self):
        """Non-hex character fails."""
        result = FormatValidator.validate("9A03Z10315")
        assert result.valid is False
        assert any(e.code == "INVALID_HEX_CHAR" for e in result.errors)

    def test_invalid_hex_special_chars(self):
        """Special characters like @ or ! fail."""
        result = FormatValidator.validate("9A03!2103@15")
        assert result.valid is False
        assert any(e.code == "INVALID_HEX_CHAR" for e in result.errors)

    def test_odd_length(self):
        """Odd length fails."""
        result = FormatValidator.validate("9A0321031")
        assert result.valid is False
        assert any(e.code == "ODD_LENGTH" for e in result.errors)

    def test_mixed_case(self):
        """Mixed case hex is accepted."""
        result = FormatValidator.validate("9a03Ab21C3D5")
        assert result.valid is True
        assert result.cleaned_hex == "9a03Ab21C3D5"

    def test_large_valid_data(self):
        """Large hex string validates."""
        hex_data = "6F" + "82" + "0100" + "00" * 256
        result = FormatValidator.validate(hex_data)
        assert result.valid is True
        assert result.metadata["byte_count"] == 260  # 1 + 2 + 513 + 512 = 1028 hex chars / 2 = 514 bytes? Let's calculate: 6F=1, 82=1, 0100=2, 00*256=256 => 1+1+2+256=260 bytes
        assert result.metadata["byte_count"] == 260

    def test_metadata_byte_count(self):
        """Metadata includes byte count."""
        result = FormatValidator.validate("9A03210315")
        assert result.metadata["byte_count"] == 5


# =============================================================================
# Structure Validation (Level 2)
# =============================================================================

class TestStructureValidator:
    def test_simple_primitive(self):
        """Simple primitive tag validates."""
        result = StructureValidator.validate("9A03210315")
        assert result.valid is True
        assert result.metadata["tag_count"] == 1
        assert result.metadata["leaf_count"] == 1

    def test_constructed_with_children(self):
        """Constructed tag with children validates."""
        result = StructureValidator.validate("6F088402A000A5025000")
        assert result.valid is True
        assert result.metadata["tag_count"] == 4  # 6F, 84, A5, 50
        assert result.metadata["max_depth"] == 2

    def test_multi_byte_tag(self):
        """Multi-byte tags (0x1F format) validate."""
        result = StructureValidator.validate("DF11050000000000")
        assert result.valid is True
        assert result.metadata["tag_count"] == 1

    def test_extended_length(self):
        """Extended length (0x81) validates."""
        # 0x81 followed by 1 byte length = 5, then 5 bytes of value
        data = "9F33" + "8105" + "AABBCCDDEE"
        result = StructureValidator.validate(data)
        assert result.valid is True
        assert result.metadata["tag_count"] == 1

    def test_truncated_value(self):
        """Truncated value fails."""
        result = StructureValidator.validate("9A05AB")
        assert result.valid is False
        assert any(e.code == "TRUNCATED_VALUE" for e in result.errors)

    def test_truncated_tag(self):
        """Truncated multi-byte tag fails."""
        # For a constructed tag with extended tag that's incomplete
        result = StructureValidator.validate("1F")
        assert result.valid is False
        assert any(e.code == "TRUNCATED_TAG" for e in result.errors)

    def test_invalid_length_encoding(self):
        """Invalid length prefix 0xFF fails."""
        result = StructureValidator.validate("E0FF01")
        assert result.valid is False
        assert any(e.code == "INVALID_LENGTH_ENCODING" for e in result.errors)

    def test_padding_bytes_skipped(self):
        """Padding bytes (0x00, 0xFF) before data are skipped."""
        result = StructureValidator.validate("00FF9A03210315")
        assert result.valid is True
        assert result.metadata["tag_count"] == 1

    def test_real_config_structure(self):
        """Real-world config TLV (E0/E2 with children)."""
        data = (
            "E012"  # E0 with short length = 18 bytes
            + "9F1A020280"  # Terminal Country Code
            + "DF1B020978"  # Terminal Currency
            + "DF1C0102"    # Currency Exponent
            + "9F350122"    # Terminal Type
            + "9F330360F8C8"  # Terminal Capabilities
        )
        result = StructureValidator.validate(data)
        assert result.valid is True
        assert result.metadata["tag_count"] > 1
        assert result.metadata["max_depth"] >= 1

    def test_max_depth_calculation(self):
        """Max depth is correctly calculated."""
        result = StructureValidator.validate("6F088402A000A5025000")
        assert result.metadata["max_depth"] == 2

    def test_warning_long_form_length(self):
        """Unnecessary long form length generates warning."""
        # 0x81 for length 2 (should be 0x02)
        data = "9A" + "8102" + "3031"
        result = StructureValidator.validate(data)
        assert result.valid is True
        assert any(e.code == "LONG_FORM_LENGTH" for e in result.warnings)


# =============================================================================
# Semantic Validation (Level 3)
# =============================================================================

class TestSemanticValidator:
    def test_known_tags_pass(self):
        """Known tags from dictionary pass."""
        result = SemanticValidator.validate("9A03210315", [
            {"tag": "9A", "is_constructed": False, "length": 3, "depth": 0}
        ])
        assert result.valid is True

    def test_unknown_tag_warning(self):
        """Unknown tag generates warning."""
        result = SemanticValidator.validate("ZZ03210315", [
            {"tag": "ZZ", "is_constructed": False, "length": 3, "depth": 0}
        ])
        assert result.valid is True
        assert any(e.code == "UNKNOWN_TAG" for e in result.warnings)

    def test_valid_tag_hierarchy(self):
        """Valid parent-child relationship passes."""
        # 6F (FCI Template) can contain 84 (DF Name)
        result = SemanticValidator.validate("6F048402A000", [
            {"tag": "6F", "is_constructed": True, "children": [
                {"tag": "84", "is_constructed": False}
            ], "depth": 0}
        ])
        assert result.valid is True

    def test_invalid_parent_warning(self):
        """Tag under wrong parent generates warning."""
        # E2 cannot contain 9F1A (9F1A's parent_tags are DF40, DF43, E0)
        result = SemanticValidator.validate("E2049F1A020280", [
            {"tag": "E2", "is_constructed": True, "children": [
                {"tag": "9F1A", "is_constructed": False}
            ], "depth": 0}
        ])
        assert result.valid is True
        assert any(e.code == "INVALID_PARENT" for e in result.warnings)

    def test_format_bitmask_validation(self):
        """Bitmask format check."""
        # 9F33 is bitmask, value should be 3 bytes (typical_length=0x03)
        result = SemanticValidator.validate("9F330360F8C8", [
            {"tag": "9F33", "is_constructed": False, "length": 3, "depth": 0}
        ])
        assert result.valid is True


# =============================================================================
# Unified API: validate_hex()
# =============================================================================

class TestValidateHex:
    def test_format_level(self):
        """Format level only."""
        result = validate_hex("9A 03 21 03 15", level="format")
        assert result.valid is True
        assert result.cleaned_hex == "9A03210315"

    def test_structure_level(self):
        """Structure level."""
        result = validate_hex("6F088402A000A5025000", level="structure")
        assert result.valid is True
        assert result.metadata["tag_count"] == 4

    def test_semantic_level(self):
        """Semantic level."""
        result = validate_hex("9A03210315", level="semantic")
        assert result.valid is True

    def test_format_error_stops_early(self):
        """Format error stops before structure check."""
        result = validate_hex("9A03Z10315", level="structure")
        assert result.valid is False
        assert any(e.code == "INVALID_HEX_CHAR" for e in result.errors)

    def test_strict_mode_raises(self):
        """Strict mode raises ValueError on error."""
        with pytest.raises(ValueError, match="Format validation failed"):
            validate_hex("invalid", level="format", strict=True)

    def test_strict_mode_structure(self):
        """Strict mode raises on structure error."""
        with pytest.raises(ValueError, match="Structure validation failed"):
            validate_hex("9A05AB", level="structure", strict=True)

    def test_bytes_input(self):
        """Bytes input is accepted."""
        result = validate_hex(bytes([0x9A, 0x03, 0x21, 0x03, 0x15]), level="format")
        assert result.valid is True

    def test_invalid_level(self):
        """Invalid level raises ValueError."""
        with pytest.raises(ValueError, match="Unknown validation level"):
            validate_hex("9A03", level="invalid")

    def test_result_to_dict(self):
        """ValidationResult.to_dict() works."""
        result = validate_hex("9A03210315", level="format")
        d = result.to_dict()
        assert d["valid"] is True
        assert d["cleaned_hex"] == "9A03210315"
        assert "metadata" in d

    def test_error_to_dict(self):
        """ValidationError.to_dict() works."""
        error = ValidationError(
            code="TEST_ERROR", message="Test", position=5, severity="error"
        )
        d = error.to_dict()
        assert d["code"] == "TEST_ERROR"
        assert d["position"] == 5
        assert d["severity"] == "error"