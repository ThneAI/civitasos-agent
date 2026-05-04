"""H.1 scaffolding package (LLM-judge phase)."""

from .llm_judge import (
    DisabledJudge,
    JudgeBackendUnavailable,
    JudgeRequest,
    JudgeResult,
    JudgeResponseInvalid,
    LLMJudge,
    OpenAICompatibleJudge,
    build_judge_from_env,
)
from .calibration import (
    DEFAULT_MIN_ADVERSARIAL_ACCURACY,
    DEFAULT_MIN_AGREEMENT,
    MIN_ADVERSARIAL_BOUNDARY_SAMPLES,
    MIN_CALIBRATION_SAMPLES,
    CalibrationSample,
    calibration_row,
    evaluate_calibration,
    load_calibration_samples,
    summarize_calibration_rows,
)
from .success_criteria import (
    DEFAULT_MIN_LLM_JUDGE_PASS_RATE,
    LLM_CRITERIA_REPORT_SCHEMA,
    disabled_llm_judge_report,
    evaluate_llm_judge_success_criteria,
    failure_llm_judge_report,
    summarize_llm_judge_rows,
    validate_calibration_report,
    write_llm_judge_report,
)
from .telos import build_telos_alignment, served_intent_layer_for_action

__all__ = [
    "build_telos_alignment",
    "DisabledJudge",
    "JudgeBackendUnavailable",
    "JudgeRequest",
    "JudgeResult",
    "JudgeResponseInvalid",
    "LLMJudge",
    "OpenAICompatibleJudge",
    "build_judge_from_env",
    "served_intent_layer_for_action",
    "CalibrationSample",
    "DEFAULT_MIN_ADVERSARIAL_ACCURACY",
    "DEFAULT_MIN_AGREEMENT",
    "MIN_ADVERSARIAL_BOUNDARY_SAMPLES",
    "MIN_CALIBRATION_SAMPLES",
    "calibration_row",
    "evaluate_calibration",
    "load_calibration_samples",
    "summarize_calibration_rows",
    "DEFAULT_MIN_LLM_JUDGE_PASS_RATE",
    "LLM_CRITERIA_REPORT_SCHEMA",
    "disabled_llm_judge_report",
    "evaluate_llm_judge_success_criteria",
    "failure_llm_judge_report",
    "summarize_llm_judge_rows",
    "validate_calibration_report",
    "write_llm_judge_report",
]
