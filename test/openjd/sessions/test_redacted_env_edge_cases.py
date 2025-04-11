# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

import logging
import pytest
from hashlib import sha256
from logging.handlers import QueueHandler
from queue import SimpleQueue
from unittest.mock import MagicMock

from openjd.sessions._action_filter import ActionMessageKind, ActionMonitoringFilter
from openjd.sessions._logging import LoggerAdapter


class TestRedactedEnvEdgeCases:
    """Tests for edge cases in the openjd_redacted_env functionality."""

    def build_logger(self, name: str, handler: QueueHandler, filter_obj) -> logging.Logger:
        """Helper to build a logger with the given handler and filter."""
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.addFilter(filter_obj)
        return logger

    @pytest.fixture
    def message_queue(self) -> SimpleQueue:
        return SimpleQueue()

    @pytest.fixture
    def queue_handler(self, message_queue: SimpleQueue) -> QueueHandler:
        return QueueHandler(message_queue)

    def test_redacted_env_with_space_before_value(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test case 1: If we get 'openjd_redacted_env: KEY= VALUE',
        the environment variable KEY is set to ' VALUE' and ' VALUE' is added to the redaction list.
        """
        # GIVEN
        message = "openjd_redacted_env: KEY= VALUE"
        h = sha256()
        h.update(message.encode("utf-8"))
        logger_name = "redacted_space_after" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # WHEN
        loga.info(message)

        # THEN
        # Check that the callback was called with the correct parameters
        # The key should be "KEY" and the value should be " VALUE" (with the leading space)
        callback_mock.assert_called_once_with(
            ActionMessageKind.ENV, {"name": "KEY", "value": " VALUE"}, False
        )

        # Check that the message in the log is redacted
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "openjd_redacted_env: KEY=********" in log_message
        assert " VALUE" not in log_message

        # Check that subsequent logs with the value are redacted
        # The space after KEY= is what's being redacted, not "VALUE" by itself
        loga.info("The value is: VALUE")
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is:********" in log_message  # The entire " VALUE" is redacted

        # Try with quotes around VALUE - this should not be redacted since it doesn't match " VALUE" exactly
        loga.info("The value is: 'VALUE'")
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: 'VALUE'" in log_message  # VALUE with quotes is not redacted

    def test_redacted_env_with_space_after_key(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test case 2: If we get 'openjd_redacted_env: KEY =VALUE',
        no environment variable is set, a warning is emitted, and VALUE is added to the redaction list.
        """
        # GIVEN
        message = "openjd_redacted_env: KEY =VALUE"
        h = sha256()
        h.update(message.encode("utf-8"))
        logger_name = "redacted_space_before" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # WHEN
        loga.info(message)

        # THEN
        # Check that the callback was NOT called (no env var should be set)
        callback_mock.assert_not_called()

        # Check that the message in the log is redacted
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "openjd_redacted_env: KEY =********" in log_message
        assert "VALUE" not in log_message

        # Check that subsequent logs with the value are redacted
        loga.info("The value is: VALUE")
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: ********" in log_message

    def test_redacted_env_without_equals(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test case 3: If we get 'openjd_redacted_env: KEYVALUE',
        a warning is emitted, no environment variable is set, and KEYVALUE is added to the redaction list.
        """
        # GIVEN
        message = "openjd_redacted_env: KEYVALUE"
        h = sha256()
        h.update(message.encode("utf-8"))
        logger_name = "redacted_no_equals" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # WHEN
        loga.info(message)

        # THEN
        # Check that the callback was NOT called (no env var should be set)
        callback_mock.assert_not_called()

        # Check that the message in the log is redacted
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "openjd_redacted_env: ********" in log_message
        assert "KEYVALUE" not in log_message

        # Check that subsequent logs with the value are redacted
        loga.info("The value is: KEYVALUE")
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: ********" in log_message

    def test_redacted_env_with_multiple_equals(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test handling of redacted_env with multiple equals signs."""
        # GIVEN
        message = "openjd_redacted_env: KEY=VALUE=MORE"
        h = sha256()
        h.update(message.encode("utf-8"))
        logger_name = "redacted_multiple_equals" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # WHEN
        loga.info(message)

        # THEN
        # Check that the callback was called with the correct parameters
        # The key should be "KEY" and the value should be "VALUE=MORE"
        callback_mock.assert_called_once_with(
            ActionMessageKind.ENV, {"name": "KEY", "value": "VALUE=MORE"}, False
        )

        # Check that the message in the log is redacted
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "openjd_redacted_env: KEY=********" in log_message
        assert "VALUE=MORE" not in log_message

        # Check that subsequent logs with the value are redacted
        loga.info("The value is: VALUE=MORE")
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: ********" in log_message

    def test_redacted_env_with_empty_value(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test that 'openjd_redacted_env: KEY=' sets an empty environment variable
        but doesn't add the empty string to the redaction list."""
        # GIVEN
        message = "openjd_redacted_env: KEY="
        h = sha256()
        h.update(message.encode("utf-8"))
        logger_name = "redacted_empty_value" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # WHEN
        loga.info(message)

        # THEN
        # Check that the callback was called with the correct parameters
        # The key should be "KEY" and the value should be an empty string
        callback_mock.assert_called_once_with(
            ActionMessageKind.ENV, {"name": "KEY", "value": ""}, False
        )

        # Check that the message in the log is not redacted (since there's nothing to redact)
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "openjd_redacted_env: KEY=" in log_message

        # Check that subsequent logs with empty strings are not redacted
        # This verifies that empty strings aren't added to the redaction list
        loga.info("The value is: ")
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: " in log_message  # Not redacted

    def test_redaction_preserves_spaces(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test that when redacting values in an f-string, spaces around the value are preserved.
        For example, if we have 'SECRETVAR is {os.environ.get("SECRETVAR")}' and SECRETVAR=SECRETVAL,
        it should be redacted as 'SECRETVAR is ********' (preserving the space after 'is')."""
        # GIVEN
        h = sha256()
        h.update(b"redaction_spaces")
        logger_name = "redacted_spaces" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # Set up redaction
        loga.info("openjd_redacted_env: SECRETVAR=SECRETVAL")

        # Clear the queue of the setup messages
        while not message_queue.empty():
            message_queue.get()

        # WHEN - Message with token
        loga.info("SECRETVAR is . SECRETVAL ;")

        # THEN - The spaces should be preserved in the redacted output
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "SECRETVAR is . ******** ;" in log_message  # Spaces should be preserved
        assert "SECRETVAL" not in log_message

    def test_overlapping_redactions(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test that overlapping redactions are handled correctly.
        For example, if we have two redactions 'FOOOBAR' and 'BARKEY',
        and the string 'FOOOBARKEY' appears, it should be completely redacted."""
        # GIVEN
        h = sha256()
        h.update(b"overlapping_redactions")
        logger_name = "redacted_overlapping" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # Test case 1: Overlapping redactions at boundary
        loga.info("openjd_redacted_env: KEY1=FOOOBAR")
        loga.info("openjd_redacted_env: KEY2=BARKEY")

        # Clear the queue of the setup messages
        while not message_queue.empty():
            message_queue.get()

        # Log a message containing the overlapping string
        loga.info("The value is: FOOOBARKEY")

        # The entire overlapping string should be redacted
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: ********" in log_message
        assert "FOOOBARKEY" not in log_message

        # Test case 2: One redaction completely contained within another
        loga.info("openjd_redacted_env: KEY3=SUPERSECRETPASSWORD")
        loga.info("openjd_redacted_env: KEY4=SECRET")

        # Clear the queue of the setup messages
        while not message_queue.empty():
            message_queue.get()

        # Log a message containing the nested redaction
        loga.info("The value is: SUPERSECRETPASSWORD")

        # The entire string should be redacted with a single redaction
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: ********" in log_message
        assert "SUPERSECRETPASSWORD" not in log_message

    def test_redaction_persists_after_unset(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test that when we unset a redacted environment variable:
        1. The variable is unset (via callback)
        2. The value continues to be redacted in logs"""
        # GIVEN
        h = sha256()
        h.update(b"redaction_unset")
        logger_name = "redacted_unset" + h.hexdigest()[0:32]
        callback_mock = MagicMock()
        filter = ActionMonitoringFilter(
            session_id="foo", callback=callback_mock, enabled_extensions=["REDACTED_ENV_VARS"]
        )
        log = self.build_logger(logger_name, queue_handler, filter)
        loga = LoggerAdapter(log, extra={"session_id": "foo"})

        # Set up redaction
        loga.info("openjd_redacted_env: SECRETVAR=SECRETVAL")

        # Clear the queue of the setup messages
        while not message_queue.empty():
            message_queue.get()

        # WHEN - Unset the variable
        loga.info("openjd_unset_env: SECRETVAR")

        # THEN - The callback should be called to unset the var
        callback_mock.assert_called_with(ActionMessageKind.UNSET_ENV, "SECRETVAR", False)

        # Clear the queue of the unset message
        while not message_queue.empty():
            message_queue.get()

        # AND - The value should still be redacted in logs
        loga.info("The value is: SECRETVAL")
        assert message_queue.qsize() == 1
        log_message = message_queue.get(block=False).getMessage()
        assert "The value is: ********" in log_message
        assert "SECRETVAL" not in log_message

    def test_behavior_consistency_with_openjd_env(
        self, message_queue: SimpleQueue, queue_handler: QueueHandler
    ) -> None:
        """Test that openjd_redacted_env behaves the same as openjd_env for setting environment variables,
        except for the redaction behavior."""
        # GIVEN
        test_cases = [
            # Normal case
            "KEY=VALUE",
            # Case with space after equals
            "KEY= VALUE",
            # Case with multiple equals
            "KEY=VALUE=MORE",
            # Case with empty value
            "KEY=",
        ]

        # Test cases that are expected to fail (no env var set)
        fail_cases = [
            # Case with space before equals
            "KEY =VALUE",
            # Case with no equals
            "KEYVALUE",
        ]

        # Test the cases where both commands should succeed
        for case in test_cases:
            # Create a fresh filter and mock for each test case
            callback_mock_env = MagicMock()
            filter_env = ActionMonitoringFilter(session_id="foo", callback=callback_mock_env)
            log_env = self.build_logger(f"env_test_{case}", queue_handler, filter_env)
            loga_env = LoggerAdapter(log_env, extra={"session_id": "foo"})

            callback_mock_redacted = MagicMock()
            filter_redacted = ActionMonitoringFilter(
                session_id="foo",
                callback=callback_mock_redacted,
                enabled_extensions=["REDACTED_ENV_VARS"],
            )
            log_redacted = self.build_logger(
                f"redacted_test_{case}", queue_handler, filter_redacted
            )
            loga_redacted = LoggerAdapter(log_redacted, extra={"session_id": "foo"})

            # Run both commands with the same input
            loga_env.info(f"openjd_env: {case}")
            loga_redacted.info(f"openjd_redacted_env: {case}")

            # Clear the queue
            while not message_queue.empty():
                message_queue.get()

            # Compare the callback calls
            env_calls = callback_mock_env.call_args_list
            redacted_calls = callback_mock_redacted.call_args_list

            # Both should have the same number of calls (should be 1 for these cases)
            assert (
                len(env_calls) == len(redacted_calls) == 1
            ), f"Case '{case}': Different number of calls"

            # The parameters should be the same
            env_args = env_calls[0][0]
            redacted_args = redacted_calls[0][0]

            # The first argument should be ActionMessageKind.ENV for both
            assert (
                env_args[0] == redacted_args[0] == ActionMessageKind.ENV
            ), f"Case '{case}': Different message kinds"

            # The second argument should be the same dictionary (name and value)
            assert (
                env_args[1] == redacted_args[1]
            ), f"Case '{case}': Different environment variable settings"

            # The third argument should be the same boolean
            assert env_args[2] == redacted_args[2], f"Case '{case}': Different third argument"

            # The third argument should be False
            assert not redacted_args[2], f"Case '{case}': Third argument not false"

        # Test the cases where both commands should fail
        for case in fail_cases:
            # Create a fresh filter and mock for each test case
            callback_mock_env = MagicMock()
            filter_env = ActionMonitoringFilter(session_id="foo", callback=callback_mock_env)
            log_env = self.build_logger(f"env_fail_test_{case}", queue_handler, filter_env)
            loga_env = LoggerAdapter(log_env, extra={"session_id": "foo"})

            callback_mock_redacted = MagicMock()
            filter_redacted = ActionMonitoringFilter(
                session_id="foo",
                callback=callback_mock_redacted,
                enabled_extensions=["REDACTED_ENV_VARS"],
            )
            log_redacted = self.build_logger(
                f"redacted_fail_test_{case}", queue_handler, filter_redacted
            )
            loga_redacted = LoggerAdapter(log_redacted, extra={"session_id": "foo"})

            # Run both commands with the same input
            loga_env.info(f"openjd_env: {case}")
            loga_redacted.info(f"openjd_redacted_env: {case}")

            # Clear the queue
            while not message_queue.empty():
                message_queue.get()

            # The key thing we're testing is that neither command should set an environment variable
            # in these failure cases. The specific error handling approach may differ.

            # For openjd_env, verify it doesn't set an environment variable
            # (it calls the callback with an error message instead)
            all_env_calls = callback_mock_env.call_args_list
            filtered_env_calls = [
                call
                for call in all_env_calls
                if call[0][0] == ActionMessageKind.ENV and isinstance(call[0][1], dict)
            ]
            assert (
                len(filtered_env_calls) == 0
            ), f"Case '{case}': openjd_env should not set environment variable"

            # For openjd_redacted_env, verify it doesn't set an environment variable
            all_redacted_calls = callback_mock_redacted.call_args_list
            filtered_redacted_calls = [
                call
                for call in all_redacted_calls
                if call[0][0] == ActionMessageKind.ENV and isinstance(call[0][1], dict)
            ]
            assert (
                len(filtered_redacted_calls) == 0
            ), f"Case '{case}': openjd_redacted_env should not set environment variable"
