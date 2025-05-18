# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

from openjd.sessions._redaction import RedactionRegistry, pre_redact_command


class TestRedactionRegistry:
    """Tests for the RedactionRegistry class."""

    def test_singleton_pattern(self):
        """Test that RedactionRegistry follows the singleton pattern."""
        # GIVEN
        registry1 = RedactionRegistry.get_instance()
        registry2 = RedactionRegistry.get_instance()

        # THEN
        assert registry1 is registry2

    def test_add_redacted_value(self):
        """Test adding values to the redaction registry."""
        # GIVEN
        registry = RedactionRegistry()
        registry._redacted_values = []  # Reset for test

        # WHEN
        registry.add_redacted_value("secret")
        registry.add_redacted_value("password")
        registry.add_redacted_value("token")

        # THEN
        assert "secret" in registry._redacted_values
        assert "password" in registry._redacted_values
        assert "token" in registry._redacted_values

    def test_add_redacted_value_maintains_order(self):
        """Test that values are added in descending length order."""
        # GIVEN
        registry = RedactionRegistry()
        registry._redacted_values = []  # Reset for test

        # WHEN
        registry.add_redacted_value("short")
        registry.add_redacted_value("longer_value")
        registry.add_redacted_value("medium")

        # THEN
        assert registry._redacted_values == ["longer_value", "medium", "short"]

    def test_add_redacted_value_ignores_duplicates(self):
        """Test that duplicate values are not added."""
        # GIVEN
        registry = RedactionRegistry()
        registry._redacted_values = []  # Reset for test

        # WHEN
        registry.add_redacted_value("secret")
        registry.add_redacted_value("secret")

        # THEN
        assert registry._redacted_values.count("secret") == 1

    def test_redact_message(self):
        """Test redacting a message."""
        # GIVEN
        registry = RedactionRegistry()
        registry._redacted_values = ["secret", "password"]

        # WHEN
        redacted = registry.redact_message("My secret password is secret")

        # THEN
        assert "secret" not in redacted
        assert "password" not in redacted
        assert "My ******** ******** is ********" == redacted

    def test_redact_message_with_overlapping_values(self):
        """Test redacting a message with overlapping values."""
        # GIVEN
        registry = RedactionRegistry()
        registry._redacted_values = ["secret", "secret password"]

        # WHEN
        redacted = registry.redact_message("My secret password is important")

        # THEN
        assert "secret password" not in redacted
        assert "My ******** is important" == redacted

    def test_redact_message_with_empty_registry(self):
        """Test redacting a message with an empty registry."""
        # GIVEN
        registry = RedactionRegistry()
        registry._redacted_values = []

        # WHEN
        redacted = registry.redact_message("My secret password")

        # THEN
        assert redacted == "My secret password"

    def test_redact_message_with_non_string(self):
        """Test redacting a non-string message."""
        # GIVEN
        registry = RedactionRegistry()
        registry._redacted_values = ["secret"]

        # WHEN
        redacted = registry.redact_message(123)

        # THEN
        assert redacted == 123


class TestPreRedactCommand:
    """Tests for the pre_redact_command function."""

    def test_pre_redact_command_no_redaction_needed(self):
        """Test pre_redact_command with a string that doesn't need redaction."""
        # GIVEN
        command = "echo 'Hello, world!'"

        # WHEN
        result = pre_redact_command(command)

        # THEN
        assert result == command  # No change

    def test_pre_redact_command_with_redaction_needed(self):
        """Test pre_redact_command with a string that needs redaction."""
        # GIVEN
        command = "python -c \"print('openjd_redacted_env: PASSWORD=secret123')\""

        # WHEN
        result = pre_redact_command(command)

        # THEN
        assert "openjd_redacted_env:********" in result
        assert "secret123" not in result

    def test_pre_redact_command_with_multiple_occurrences(self):
        """Test pre_redact_command with multiple occurrences of the token."""
        # GIVEN
        command = (
            "echo 'openjd_redacted_env: KEY1=value1' && echo 'openjd_redacted_env: KEY2=value2'"
        )

        # WHEN
        result = pre_redact_command(command)

        # THEN
        assert "openjd_redacted_env:********" in result
        assert "value1" not in result
        assert "value2" not in result

    def test_pre_redact_command_with_token_at_start(self):
        """Test pre_redact_command with the token at the start of the string."""
        # GIVEN
        command = "openjd_redacted_env: PASSWORD=secret123"

        # WHEN
        result = pre_redact_command(command)

        # THEN
        assert result == "openjd_redacted_env:********"
        assert "PASSWORD=secret123" not in result

    def test_pre_redact_command_with_token_at_end(self):
        """Test pre_redact_command with the token at the end of the string."""
        # GIVEN
        command = "echo openjd_redacted_env:"

        # WHEN
        result = pre_redact_command(command)

        # THEN
        assert result == "echo openjd_redacted_env:********"
