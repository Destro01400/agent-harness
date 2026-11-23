#!/usr/bin/env python3
"""Zero-dependency CLI scaffolder for agent-harness starter templates.

Usage:
  python scaffold_harness.py --list
  python scaffold_harness.py --template python-runtime-eval --name my-agent --out ./my-agent
  python scaffold_harness.py --template typescript-runtime-eval --name my-ts-agent --out ./my-ts-agent
  python scaffold_harness.py --template eval-suite-standalone --name my-evals --out ./my-evals --force
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import keyword
from pathlib import Path
import re
import sys

PROJECT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
SKIP_NAMES = {"__pycache__", ".git", "node_modules", "dist", ".venv"}
SKIP_SUFFIXES = {".pyc", ".pyo"}

TEMPLATES: dict[str, str] = {
    "python-runtime-eval": (
        "Python 3.11+ zero-deps runtime + eval harness "
        "(Model-visible<=>logged JSONL, budgets, spill, checkpoints, pass@k/pass^k)"
    ),
    "typescript-runtime-eval": (
        "TypeScript ESM (Node 24+) zero-deps runtime + eval harness "
        "(AbortSignal, budgets, spill, checkpoints, pass@k/pass^k)"
    ),
    "eval-suite-standalone": (
        "Python 3.11+ standalone multi-trial eval harness "
        "(outcome graders, nonce-hardened judge, pass@k/pass^k, Wilson CI, regression gate)"
    ),
}


@dataclass(frozen=True)
class ScaffoldResult:
    """Summary returned by scaffold_project."""

    template: str
    project_name: str
    package_name: str
    description: str
    output_dir: Path
    files: tuple[Path, ...]


def get_templates_root() -> Path:
    return Path(__file__).resolve().parent.parent / "assets" / "templates"


def validate_project_name(name: str) -> str:
    if not name or not PROJECT_NAME_RE.fullmatch(name):
        raise ValueError(
            f"Invalid --name '{name}'. Expected identifier matching ^[A-Za-z][A-Za-z0-9_-]*$."
        )
    return name


def derive_package_name(name: str) -> str:
    """Derive a safe snake_case package identifier from a project name."""
    raw = re.sub(r"[^a-z0-9_]", "_", name.strip().lower().replace("-", "_"))
    raw = re.sub(r"_+", "_", raw).strip("_")
    if not raw:
        raise ValueError(f"Cannot derive valid package name from '{name}'.")
    if raw[0].isdigit():
        raw = f"pkg_{raw}"
    if keyword.iskeyword(raw):
        raw = f"{raw}_pkg"
    return raw


def _apply_tokens(value: str, tokens: dict[str, str]) -> str:
    for placeholder, replacement in tokens.items():
        value = value.replace(placeholder, replacement)
    return value


def scaffold_project(
    template: str,
    project_name: str,
    output_dir: Path,
    description: str | None = None,
    force: bool = False,
    templates_root: Path | None = None,
) -> ScaffoldResult:
    """Generate a starter harness project from a template directory into output_dir."""
    if template not in TEMPLATES:
        available = ", ".join(TEMPLATES)
        raise ValueError(f"Unknown template '{template}'. Choose one of: {available}.")

    validated_name = validate_project_name(project_name)
    package_name = derive_package_name(validated_name)
    resolved_desc = (
        description.strip()
        if description is not None and description.strip()
        else f"{validated_name} - {TEMPLATES[template]}"
    )

    root = (templates_root or get_templates_root()) / template
    if not root.is_dir():
        raise FileNotFoundError(f"Template directory does not exist: {root}")

    resolved_out = output_dir.resolve()
    if resolved_out.exists():
        if not resolved_out.is_dir():
            raise FileExistsError(f"Target path exists and is not a directory: {resolved_out}")
        if any(resolved_out.iterdir()) and not force:
            raise FileExistsError(
                f"Target directory is not empty: {resolved_out}. Pass --force to overwrite."
            )

    resolved_out.mkdir(parents=True, exist_ok=True)
    tokens = {
        "{{PROJECT_NAME}}": validated_name,
        "{{PACKAGE_NAME}}": package_name,
        "{{DESCRIPTION}}": resolved_desc,
    }

    written: list[Path] = []
    for src_path in sorted(root.rglob("*")):
        if not src_path.is_file():
            continue
        rel_src = src_path.relative_to(root)
        if any(part in SKIP_NAMES for part in rel_src.parts):
            continue
        if src_path.suffix.lower() in SKIP_SUFFIXES:
            continue

        rel_parts = [_apply_tokens(part, tokens) for part in rel_src.parts]
        dest_path = (resolved_out.joinpath(*rel_parts)).resolve()
        if resolved_out not in dest_path.parents and dest_path != resolved_out:
            raise ValueError(f"Refusing path outside target directory: {dest_path}")

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            content = src_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            dest_path.write_bytes(src_path.read_bytes())
        else:
            rendered = _apply_tokens(content, tokens)
            dest_path.write_text(rendered, encoding="utf-8", newline="\n")

        written.append(dest_path)

    return ScaffoldResult(
        template=template,
        project_name=validated_name,
        package_name=package_name,
        description=resolved_desc,
        output_dir=resolved_out,
        files=tuple(written),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scaffold a zero-dependency agent harness or eval suite project "
            "(Python runtime+eval, TypeScript ESM runtime+eval, or standalone eval suite)."
        )
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available starter templates and exit",
    )
    parser.add_argument(
        "--template",
        choices=tuple(TEMPLATES.keys()),
        help="Starter template to generate",
    )
    parser.add_argument(
        "--name",
        help="Project name (must match ^[A-Za-z][A-Za-z0-9_-]*$)",
    )
    parser.add_argument(
        "--out",
        help="Destination directory path",
    )
    parser.add_argument(
        "--description",
        default=None,
        help="Optional project description (defaults to template summary)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow writing into a non-empty target directory and overwriting existing files",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        print("Available templates:")
        for key, desc in TEMPLATES.items():
            print(f"  {key:<25} {desc}")
        return 0

    missing = [
        flag
        for flag, val in (("--template", args.template), ("--name", args.name), ("--out", args.out))
        if not val
    ]
    if missing:
        parser.error(f"the following arguments are required: {', '.join(missing)}")

    try:
        result = scaffold_project(
            template=args.template,
            project_name=args.name,
            output_dir=Path(args.out),
            description=args.description,
            force=args.force,
        )
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Scaffolded '{result.template}' as '{result.project_name}' "
        f"(package={result.package_name}) -> {result.output_dir}"
    )
    print(f"Created {len(result.files)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
