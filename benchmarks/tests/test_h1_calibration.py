from __future__ import annotations

from benchmarks.h1.calibration import evaluate_calibration, load_calibration_samples
from benchmarks.h1.llm_judge import JudgeRequest, JudgeResult


class LabelJudge:
    def __init__(self, labels: dict[str, bool], flip: set[str] | None = None) -> None:
        self.labels = labels
        self.flip = flip or set()

    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        passed = self.labels[req.sample_id]
        if req.sample_id in self.flip:
            passed = not passed
        return JudgeResult(
            passed=passed,
            score=0.9 if passed else 0.1,
            rationale="synthetic test judge",
            model="judge-test-model",
            prompt_version="h1-judge-v1",
            prompt_hash="sha256:test",
        )


class SkippingJudge:
    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        return JudgeResult(passed=None, score=None, rationale=req.sample_id, skipped=True)


def test_default_calibration_dataset_meets_h1c_counts() -> None:
    samples = load_calibration_samples()
    regular = [sample for sample in samples if not sample.adversarial_boundary]
    boundary = [sample for sample in samples if sample.adversarial_boundary]

    assert len(regular) >= 50
    assert len(boundary) >= 10
    assert {sample.gold_passed for sample in samples} == {False, True}
    assert len({sample.sample_id for sample in samples}) == len(samples)


def test_calibration_passes_when_judge_matches_gold() -> None:
    samples = load_calibration_samples()
    labels = {sample.sample_id: sample.gold_passed for sample in samples}
    report = evaluate_calibration(samples, LabelJudge(labels))

    assert report["passed"] is True
    assert report["agreement"] == 1.0
    assert report["adversarial_boundary_accuracy"] == 1.0
    assert report["models"] == ["judge-test-model"]
    assert report["prompt_hashes"] == ["sha256:test"]


def test_calibration_fails_below_agreement_threshold() -> None:
    samples = load_calibration_samples()
    labels = {sample.sample_id: sample.gold_passed for sample in samples}
    flip = {sample.sample_id for sample in samples[:20]}
    report = evaluate_calibration(samples, LabelJudge(labels, flip=flip))

    assert report["passed"] is False
    assert report["agreement"] < 0.80


def test_calibration_fails_when_adversarial_boundary_is_weak() -> None:
    samples = load_calibration_samples()
    labels = {sample.sample_id: sample.gold_passed for sample in samples}
    boundary_ids = {
        sample.sample_id for sample in samples if sample.adversarial_boundary
    }
    report = evaluate_calibration(samples, LabelJudge(labels, flip=boundary_ids))

    assert report["passed"] is False
    assert report["adversarial_boundary_accuracy"] == 0.0


def test_calibration_fails_closed_on_skipped_judge() -> None:
    samples = load_calibration_samples()
    report = evaluate_calibration(samples, SkippingJudge())

    assert report["passed"] is False
    assert report["skipped_samples"] == len(samples)
    assert report["judged_samples"] == 0
