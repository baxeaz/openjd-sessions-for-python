# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

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
        for value in self._redacted_values:
            if value:
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
