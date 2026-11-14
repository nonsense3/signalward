#!/usr/bin/env python3
"""Train SignalWard's small URL-structure logistic model from a labeled CSV.

Example:
  python scripts/train_url_model.py --csv phishing_urls.csv --url-col url --label-col label \
    --positive-label phishing --negative-label benign --dataset-id kaggle-owner/dataset@version

The script does not download data or invent samples. It creates a host-disjoint holdout and
chooses a review threshold from the holdout negatives to bound the measured false-positive rate.
The script writes both a JSON artifact and a base64url artifact for SIGNALWARD_URL_MODEL_B64.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

FEATURES = [
    "url_length", "host_length", "path_length", "query_length", "host_label_count",
    "extra_host_label_count", "digit_ratio", "hyphen_count", "query_param_count",
    "percent_escape_count", "suspicious_keyword_count", "host_entropy", "is_ip", "has_userinfo",
]
SUSPICIOUS = ("login", "signin", "verify", "account", "secure", "update", "password", "wallet", "bank", "kyc", "otp", "refund", "claim")
PERCENT = re.compile(r"%[0-9a-f]{2}", re.I)


def normalize(raw: str) -> tuple[str, str, str, str, bool, bool]:
    value = raw.strip().replace("hxxp", "http").replace("[.]", ".").replace("[dot]", ".")
    if not value or any(char.isspace() for char in value):
        raise ValueError("empty URL or embedded whitespace")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value.lstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("only public HTTP(S) URLs are supported")
    had_userinfo = parsed.username is not None or parsed.password is not None
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is not None:
        host = address.compressed.lower()
        is_ip = True
    else:
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
            is_ip = False
        except UnicodeError as error:
            raise ValueError("invalid internationalized host") from error
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid host or port") from error
    if not host or len(host) > 253:
        raise ValueError("invalid host")
    if port == (80 if parsed.scheme.lower() == "http" else 443):
        port = None
    # IPv6 literals retain brackets in a normalized URL but not in the extracted hostname.
    is_ipv6 = isinstance(address, ipaddress.IPv6Address)
    host_in_url = f"[{host}]" if is_ipv6 else host
    netloc = host_in_url if port is None else f"{host_in_url}:{port}"
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="!$&'()*+,;=:/?@-._~%")
    normalized = f"{parsed.scheme.lower()}://{netloc}{path}" + (f"?{query}" if query else "")
    return normalized, host, path, query, had_userinfo, is_ip


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(char) / len(value)) * math.log2(value.count(char) / len(value)) for char in set(value))


def vector(raw: str) -> tuple[list[float], str]:
    normalized, host, path, query, had_userinfo, is_ip = normalize(raw)
    labels = [part for part in host.split(".") if part]
    digits = sum(char.isdigit() for char in host)
    inspect = (host + path + query).lower()
    query_count = len([part for part in query.split("&") if part])
    query_with_mark = f"?{query}" if query else ""
    values = [
        min(math.log1p(len(normalized)) / 10, 1),
        min(math.log1p(len(host)) / 6, 1),
        min(math.log1p(len(path)) / 8, 1),
        min(math.log1p(len(query_with_mark)) / 8, 1),
        min(len(labels) / 8, 1),
        min(max(0, len(labels) - 2) / 6, 1),
        digits / max(len(host), 1),
        min(host.count("-") / 6, 1),
        min(query_count / 10, 1),
        min(len(PERCENT.findall(normalized)) / 6, 1),
        min(sum(term in inspect for term in SUSPICIOUS) / 5, 1),
        min(shannon_entropy(host) / 5, 1),
        1.0 if is_ip else 0.0,
        1.0 if had_userinfo else 0.0,
    ]
    return values, host


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, help="Path to a licensed, labeled Kaggle URL CSV")
    parser.add_argument("--url-col", default="url")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--positive-label", required=True, help="Exact label value to treat as malicious")
    parser.add_argument("--negative-label", required=True, help="Exact label value to treat as benign")
    parser.add_argument("--dataset-id", required=True, help="Dataset owner/name and snapshot/version")
    parser.add_argument("--max-fpr", type=float, default=0.01, help="Maximum validation false-positive rate, 0 < value < 1")
    parser.add_argument("--min-validation-negatives", type=int, default=100, help="Minimum benign holdout examples before selecting the false-positive threshold")
    parser.add_argument("--output", default=".signalward/url-risk-model.json")
    parser.add_argument("--output-b64", default=".signalward/url-risk-model.b64", help="Base64url artifact for SIGNALWARD_URL_MODEL_B64")
    args = parser.parse_args()
    if not 0 < args.max_fpr < 1:
        parser.error("--max-fpr must be between 0 and 1")
    if args.min_validation_negatives < 20:
        parser.error("--min-validation-negatives must be at least 20")

    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import average_precision_score, confusion_matrix, precision_score, recall_score
        from sklearn.model_selection import GroupShuffleSplit
    except ImportError:
        print("Install the training dependencies first: python -m pip install numpy scikit-learn", file=sys.stderr)
        return 2

    rows: dict[str, tuple[list[float], int, str, int]] = {}
    conflicting_urls: set[str] = set()
    duplicate_rows = 0
    conflicting_rows = 0
    skipped = 0
    with open(args.csv, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or args.url_col not in reader.fieldnames or args.label_col not in reader.fieldnames:
            parser.error(f"CSV must have columns {args.url_col!r} and {args.label_col!r}; found {reader.fieldnames}")
        for row in reader:
            label = (row.get(args.label_col) or "").strip().casefold()
            if label not in (args.positive_label.casefold(), args.negative_label.casefold()):
                skipped += 1
                continue
            try:
                raw = row.get(args.url_col) or ""
                values, host = vector(raw)
                normalized, *_ = normalize(raw)
            except ValueError:
                skipped += 1
                continue
            target = int(label == args.positive_label.casefold())
            if normalized in conflicting_urls:
                conflicting_rows += 1
                continue
            previous = rows.get(normalized)
            if previous:
                if previous[1] != target:
                    # Exclude every copy of an ambiguous URL; never choose a class arbitrarily.
                    conflicting_rows += previous[3] + 1
                    conflicting_urls.add(normalized)
                    del rows[normalized]
                else:
                    duplicate_rows += 1
                    rows[normalized] = (previous[0], previous[1], previous[2], previous[3] + 1)
            else:
                rows[normalized] = (values, target, host, 1)

    data = [(features, label, host) for features, label, host, _count in rows.values()]
    if len(data) < 500 or len({row[1] for row in data}) != 2:
        parser.error(f"Need at least 500 unique valid URLs with both labels; got {len(data)}")
    x = np.asarray([row[0] for row in data], dtype=np.float64)
    y = np.asarray([row[1] for row in data], dtype=np.int8)
    groups = np.asarray([row[2] for row in data])
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, validation_idx = next(splitter.split(x, y, groups))
    if len(set(y[train_idx])) != 2 or len(set(y[validation_idx])) != 2:
        parser.error("Hostname-disjoint split did not contain both labels in train and validation; provide a larger, better-balanced dataset")
    if len(set(groups[train_idx])) < 2 or len(set(groups[validation_idx])) < 2:
        parser.error("Need at least two distinct hostnames in both train and validation; provide more hostname diversity")
    validation_negative_samples = int(np.sum(y[validation_idx] == 0))
    if validation_negative_samples < args.min_validation_negatives:
        parser.error(
            f"Validation holdout has only {validation_negative_samples} benign URLs; need at least "
            f"{args.min_validation_negatives} to select a useful false-positive threshold. Use a larger, more balanced dataset."
        )

    model = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)
    model.fit(x[train_idx], y[train_idx])
    probabilities = model.predict_proba(x[validation_idx])[:, 1]
    y_validation = y[validation_idx]
    negative_scores = probabilities[y_validation == 0]
    # Pick the lowest threshold that keeps the measured validation FPR within the requested bound.
    candidates = sorted(set(float(score) for score in probabilities) | {0.0, 1.0})
    valid_thresholds = [threshold for threshold in candidates if float(np.mean(negative_scores >= threshold)) <= args.max_fpr]
    threshold = min(valid_thresholds) if valid_thresholds else 1.0
    predictions = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(y_validation, predictions, labels=[0, 1]).ravel()
    precision = float(precision_score(y_validation, predictions, zero_division=0))
    recall = float(recall_score(y_validation, predictions, zero_division=0))
    fpr = float(fp / max(1, fp + tn))
    average_precision = float(average_precision_score(y_validation, probabilities))
    positive_samples = int(np.sum(y_validation == 1))
    negative_samples = int(np.sum(y_validation == 0))
    validation_hosts = int(len(set(groups[validation_idx])))
    dataset_sha256 = sha256_file(args.csv)

    artifact = {
        "schema": "signalward.url-risk-model/v1",
        "modelVersion": f"url-logreg-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "datasetId": args.dataset_id,
        "datasetSha256": dataset_sha256,
        "trainedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "features": FEATURES,
        "coefficients": [float(value) for value in model.coef_[0]],
        "intercept": float(model.intercept_[0]),
        "threshold": float(threshold),
        "validation": {
            "split": "hostname-disjoint",
            "samples": int(len(validation_idx)),
            "validationHosts": validation_hosts,
            "positiveSamples": positive_samples,
            "negativeSamples": negative_samples,
            "precision": precision,
            "recall": recall,
            "falsePositiveRate": fpr,
            "averagePrecision": average_precision,
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.output_b64)), exist_ok=True)
    artifact_json = json.dumps(artifact, separators=(",", ":"), sort_keys=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(artifact_json + "\n")
    encoded = base64.urlsafe_b64encode(artifact_json.encode("utf-8")).decode("ascii").rstrip("=")
    with open(args.output_b64, "w", encoding="ascii", newline="\n") as handle:
        handle.write(encoded + "\n")
    print(json.dumps({"output": args.output, "base64urlOutput": args.output_b64, "uniqueLabeledUrls": len(data), "duplicateRowsRemoved": duplicate_rows, "conflictingUrlsRemoved": len(conflicting_urls), "conflictingRowsRemoved": conflicting_rows, "otherRowsSkipped": skipped, "datasetSha256": dataset_sha256, "hostnameDisjointValidation": artifact["validation"], "threshold": threshold}, indent=2))
    print("Configure local .env from the base64url file, or run: Get-Content -Raw '.signalward/url-risk-model.b64' | npx wrangler secret put SIGNALWARD_URL_MODEL_B64")
    print("These are holdout metrics on this dataset snapshot, not production accuracy. Retrain and revalidate on new snapshots before relying on a model update.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
