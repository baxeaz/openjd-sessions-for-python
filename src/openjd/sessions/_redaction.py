# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

import logging


class RedactionRegistry:
    """A centralized registry for managing redacted values in log messages."""

    _instance = None

    @classmethod
    def get_instance(cls):
        """Get the singleton instance of the RedactionRegistry."""
        if cls._instance is None:
            cls._instance = RedactionRegistry()
        return cls._instance

    def __init__(self):
        self._redacted_values = []

    def add_redacted_value(self, value):
        """Add a value to the redaction list, maintaining descending length order.

        Args:
            value (str): The value to be redacted in log messages.
        """
        if value and value not in self._redacted_values:
            inserted = False
            for i, existing_value in enumerate(self._redacted_values):
                if len(value) >= len(existing_value):
                    self._redacted_values.insert(i, value)
                    inserted = True
                    break
            if not inserted:
                self._redacted_values.append(value)

    def redact_message(self, message):
        """Apply redactions to a message string.

        Args:
            message (str): The message to redact.

        Returns:
            str: The redacted message.
        """
        if not isinstance(message, str) or not self._redacted_values:
            return message

        # Find all segments that need redaction
        segments_to_redact = []
        
        # First, check for exact matches of sensitive values
        for value in self._redacted_values:
            if value:
                # Check for the value as a standalone word or part of a word
                start = 0
                while True:
                    pos = message.find(value, start)
                    if pos == -1:
                        break
                    segments_to_redact.append((pos, pos + len(value)))
                    start = pos + 1
        
        # If we found segments to redact, merge overlapping segments
        if segments_to_redact:
            # Sort segments by start position
            segments_to_redact.sort()
            
            # Merge overlapping segments
            merged_segments = []
            current_start, current_end = segments_to_redact[0]
            
            for start, end in segments_to_redact[1:]:
                # Check if this segment overlaps with the current one
                # We consider segments to overlap if one starts within the other
                # or if they are adjacent (no gap between them)
                if start <= current_end:
                    # Segments overlap, extend current segment
                    current_end = max(current_end, end)
                else:
                    # No overlap, add current segment and start new one
                    merged_segments.append((current_start, current_end))
                    current_start, current_end = start, end
            
            # Add the last segment
            merged_segments.append((current_start, current_end))
            
            # Apply redactions from end to start to avoid position shifts
            msg_chars = list(message)
            for start, end in reversed(merged_segments):
                msg_chars[start:end] = list("*" * 8)  # Always use 8 asterisks for redaction
            message = "".join(msg_chars)
        
        return message


def pre_redact_command(command_str: str) -> str:
    """
    Pre-redact sensitive information in command strings before they're processed by the regular redaction mechanism.

    This is used for cases where a command string might contain sensitive information that needs to be
    redacted before it's passed to the logger, especially for commands containing 'openjd_redacted_env:'.

    Args:
        command_str: The command string that might contain sensitive information

    Returns:
        The command string with sensitive information redacted
    """
    # Fast path for the common case where there's no redaction needed
    if "openjd_redacted_env:" not in command_str:
        return command_str

    # If this is a redacted env command, redact everything after the token
    prefix, rest = command_str.split("openjd_redacted_env:", 1)
    return f"{prefix}openjd_redacted_env:********"

class RedactionFilter(logging.Filter):
    """A filter that applies redactions to log messages.
    
    This filter should be applied after the ActionMonitoringFilter to ensure
    that sensitive values are extracted before redaction is applied.
    """
    
    def __init__(self, name=""):
        """Initialize the filter.
        
        Args:
            name (str, optional): If name is specified, it names a logger which, together
                with its children, will have its events allowed through the filter. If name
                is the empty string, allows every event. Defaults to "".
        """
        super().__init__(name)
    
    def filter(self, record):
        """Apply redactions to the log message.
        
        Args:
            record (logging.LogRecord): The log record to filter.
            
        Returns:
            bool: Always returns True to allow the record through.
        """
        if isinstance(record.msg, str):
            record.msg = RedactionRegistry.get_instance().redact_message(record.msg)
        return True
