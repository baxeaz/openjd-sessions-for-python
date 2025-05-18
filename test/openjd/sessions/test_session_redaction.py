# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

import time
import uuid
import sys
import pytest

from openjd.model.v2023_09 import Action as Action_2023_09
from openjd.model.v2023_09 import StepActions as StepActions_2023_09
from openjd.model.v2023_09 import StepScript as StepScript_2023_09

from openjd.sessions import Session, SessionState
from openjd.sessions._logging import LOG


class TestSessionRedaction:
    """Tests for redaction functionality in Sessions."""

    def test_session_applies_redaction_filter(self, caplog):
        """Test that a Session always applies a RedactionFilter to the logger."""
        # GIVEN
        from openjd.sessions._redaction import RedactionFilter, RedactionRegistry
        session_id = uuid.uuid4().hex

        # WHEN
        with Session(
            session_id=session_id,
            job_parameter_values={},
        ) as session:
            # THEN
            # Verify that a RedactionFilter is applied to the logger
            filters = LOG.filters
            assert any(isinstance(f, RedactionFilter) for f in filters)

            # Test that redaction works by adding a value to the registry
            RedactionRegistry.get_instance().add_redacted_value("SECRET_VALUE")
            
            # Log a message with the sensitive value
            LOG.info("This contains SECRET_VALUE")
            
            # Verify that the message was redacted in the logs
            assert "SECRET_VALUE" not in caplog.text
            assert "This contains ********" in caplog.text

    def test_subprocess_logging_redaction(self, caplog):
        """Test that redaction is applied to subprocess logging."""
        # GIVEN
        from openjd.sessions._redaction import RedactionRegistry
        session_id = uuid.uuid4().hex
        
        # WHEN
        with Session(
            session_id=session_id,
            job_parameter_values={},
        ) as session:
            # Add a sensitive value to the redaction registry
            RedactionRegistry.get_instance().add_redacted_value("SENSITIVE_COMMAND_ARG")
            
            # Create a script that will run a command with the sensitive value
            script = StepScript_2023_09(
                actions=StepActions_2023_09(
                    onRun=Action_2023_09(
                        command=sys.executable,
                        args=[
                            "-c",
                            "print('This is a SENSITIVE_COMMAND_ARG test')",
                        ],
                    )
                ),
            )
            
            # Run the script
            session.run_task(
                step_script=script,
                task_parameter_values={},
            )
            
            # Wait for the task to complete
            while session.state == SessionState.RUNNING:
                time.sleep(0.1)
                
            # THEN
            # Verify that the sensitive value was redacted in the logs
            assert "SENSITIVE_COMMAND_ARG" not in caplog.text
            assert "This is a ******** test" in caplog.text
