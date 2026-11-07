"""sast_agent — LLM + Semgrep + Joern investigation agent.

A-class (sink-based) investigation is the tracer state machine
(tracer.py + trace_engine.py + trace_schema.py + trace_prompts.py);
verifier.py adversarially reviews every vulnerable verdict.
Kept import-light so the package itself does not require pydantic until
contracts/pipeline/tools are imported explicitly.
"""
