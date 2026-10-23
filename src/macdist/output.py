"""Presentation-only workflow events. Never drive workflow decisions from output."""

import codecs
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time

_current = ContextVar("macdist_reporter", default=None)
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[78])")


def clean(value):
    value = ANSI.sub("", str(value))
    value = re.sub(r"[\r\n\t]+", " ", value)
    return "".join(c for c in value if ord(c) >= 32 and not 127 <= ord(c) < 160)


class Reporter:
    def __init__(self, mode="auto", stream=None, clock=time.monotonic):
        self.stream = sys.stdout if stream is None else stream
        self.mode = ("human" if self.stream.isatty() else "plain") if mode == "auto" else mode
        self.clock = clock
        self.sequence = 0
        self.run = None
        self.progress_state = {}
        self.active_line = False
        self.result = {}

    def finish_line(self):
        if self.active_line:
            self.stream.write("\n")
            self.active_line = False

    def emit(self, name, message=None, **fields):
        self.sequence += 1
        if self.mode == "jsonl":
            record = {"schema": 1, "event": name, "sequence": self.sequence,
                      "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                      "run": str(self.run) if self.run else None, **fields}
            if message is not None:
                record["message"] = clean(message)
            self.stream.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
        elif message is not None:
            self.finish_line()
            rendered = "\n".join(clean(line) for line in str(message).splitlines()) if self.mode == "human" else clean(str(message).replace("\n", " · "))
            self.stream.write(rendered + "\n")
        self.stream.flush()

    def progress(self, phase, percent):
        if not 0 <= percent <= 100:
            return
        now = self.clock()
        previous = self.progress_state.get(phase)
        if previous:
            last, when = previous
            # Ignore duplicate/regressing values. Emit at most once a second,
            # and only every 5 points or 10 seconds; always report completion.
            if percent <= last or (percent != 100 and (now - when < 1 or (percent - last < 5 and now - when < 10))):
                return
        self.progress_state[phase] = (percent, now)
        if self.mode == "human":
            self.stream.write(f"\r\x1b[2K{phase}: {percent:.1f}%")
            self.stream.flush()
            self.active_line = True
        else:
            self.emit(phase + ".progress", f"{phase}: {percent:.1f}%", percent=percent)


@contextmanager
def reporting(reporter):
    token = _current.set(reporter)
    try:
        yield reporter
    finally:
        reporter.finish_line()
        _current.reset(token)


def current():
    return _current.get()


def event(name, message=None, **fields):
    reporter = current()
    if reporter is not None:
        reporter.emit(name, message, **fields)
    elif message is not None:
        print(message, flush=True)


def command(argv):
    # Full arguments remain in command evidence, not in the agent event stream.
    reporter = current()
    if reporter is None or reporter.mode == "human":
        event("command.started", "Running: " + " ".join(map(str, argv)))


def result(**fields):
    reporter = current()
    if reporter is not None:
        reporter.result.update(fields)


class UploadProgress:
    """Incremental PTY parser; never forwards raw terminal data to the renderer."""

    def __init__(self):
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending = ""
        self.dropping = False
        self.escape = False
        self.reporter = current() or Reporter()

    def feed(self, chunk, final=False):
        text = self.decoder.decode(chunk, final=final)
        for character in text:
            if self.escape:
                self.escape = False
                if character in "78":
                    # notarytool redraws with DEC save/restore cursor rather than
                    # newlines. The ESC and its digit may arrive in separate reads.
                    self.frame()
                    continue
                self.append("\x1b")
            if character == "\x1b":
                self.escape = True
            elif character in "\r\n":
                self.frame()
            else:
                self.append(character)
        if final:
            self.frame()

    def append(self, text):
        if not self.dropping:
            self.pending += text
            if len(self.pending) > 65536:
                self.pending = ""
                self.dropping = True

    def frame(self):
        if not self.dropping:
            matches = re.findall(r"Upload progress:\s*([0-9]+(?:\.[0-9]+)?)%", clean(self.pending))
            if matches:
                self.reporter.progress("upload", float(matches[-1]))
        self.pending = ""
        self.dropping = False
