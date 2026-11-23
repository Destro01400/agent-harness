#!/usr/bin/env python3
"""Unit tests for scaffold_harness.py."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scaffold_harness as sh


class TestScaffoldHarness(unittest.TestCase):
    def test_validate_project_name_accepts_valid_identifiers(self) -> None:
        for valid in ("my-agent", "Agent_1", "evalSuite2", "a"):
            self.assertEqual(sh.validate_project_name(valid), valid)

    def test_validate_project_name_rejects_invalid_identifiers(self) -> None:
        for bad in ("", "1agent", "-agent", "my agent", "agent/bad", "agent.name", "../escape"):
            with self.assertRaises(ValueError):
                sh.validate_project_name(bad)

    def test_derive_package_name_snake_case_and_safety(self) -> None:
        self.assertEqual(sh.derive_package_name("My-Agent-Harness"), "my_agent_harness")
        self.assertEqual(sh.derive_package_name("simple_pkg"), "simple_pkg")
        self.assertEqual(sh.derive_package_name("123-demo"), "pkg_123_demo")
        self.assertEqual(sh.derive_package_name("class"), "class_pkg")

    def test_templates_dict_contains_all_three_templates(self) -> None:
        self.assertEqual(
            set(sh.TEMPLATES.keys()),
            {"python-runtime-eval", "typescript-runtime-eval", "eval-suite-standalone"},
        )

    def test_scaffold_replaces_placeholders_in_paths_and_contents_and_skips_junk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            tpl_root = tmp_root / "templates"
            tpl_dir = tpl_root / "python-runtime-eval"
            (tpl_dir / "src" / "{{PACKAGE_NAME}}").mkdir(parents=True)
            (tpl_dir / "__pycache__").mkdir(parents=True)
            (tpl_dir / "node_modules").mkdir(parents=True)
            (tpl_dir / ".git").mkdir(parents=True)

            (tpl_dir / "README.md").write_text(
                "# {{PROJECT_NAME}}\n\n{{DESCRIPTION}}\nPackage: {{PACKAGE_NAME}}\n",
                encoding="utf-8",
            )
            (tpl_dir / "src" / "{{PACKAGE_NAME}}" / "__init__.py").write_text(
                '"""{{PROJECT_NAME}} ({{PACKAGE_NAME}})"""\n',
                encoding="utf-8",
            )
            (tpl_dir / "__pycache__" / "junk.pyc").write_bytes(b"\x00\x01")
            (tpl_dir / "node_modules" / "skip.js").write_text("skip", encoding="utf-8")
            (tpl_dir / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (tpl_dir / "binary.bin").write_bytes(b"\xff\xfe\x00\x80")

            out_dir = tmp_root / "out-project"
            res = sh.scaffold_project(
                template="python-runtime-eval",
                project_name="My-Agent",
                output_dir=out_dir,
                description="Custom agent harness",
                templates_root=tpl_root,
            )

            self.assertEqual(res.project_name, "My-Agent")
            self.assertEqual(res.package_name, "my_agent")
            self.assertEqual(res.description, "Custom agent harness")
            self.assertTrue((out_dir / "README.md").is_file())
            self.assertTrue((out_dir / "src" / "my_agent" / "__init__.py").is_file())
            self.assertTrue((out_dir / "binary.bin").is_file())
            self.assertFalse((out_dir / "__pycache__").exists())
            self.assertFalse((out_dir / "node_modules").exists())
            self.assertFalse((out_dir / ".git").exists())

            readme = (out_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("# My-Agent", readme)
            self.assertIn("Custom agent harness", readme)
            self.assertIn("Package: my_agent", readme)
            self.assertNotIn("{{", readme)

    def test_non_empty_target_requires_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            tpl_root = tmp_root / "templates"
            (tpl_root / "eval-suite-standalone").mkdir(parents=True)
            (tpl_root / "eval-suite-standalone" / "eval.py").write_text("# {{PROJECT_NAME}}\n", encoding="utf-8")

            out_dir = tmp_root / "existing"
            out_dir.mkdir()
            (out_dir / "keep.txt").write_text("occupied", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                sh.scaffold_project(
                    template="eval-suite-standalone",
                    project_name="eval-one",
                    output_dir=out_dir,
                    force=False,
                    templates_root=tpl_root,
                )

            res = sh.scaffold_project(
                template="eval-suite-standalone",
                project_name="eval-one",
                output_dir=out_dir,
                force=True,
                templates_root=tpl_root,
            )
            self.assertEqual(len(res.files), 1)
            self.assertTrue((out_dir / "eval.py").is_file())

    def test_cli_list_and_errors(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sh.main(["--list"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("python-runtime-eval", out)
        self.assertIn("typescript-runtime-eval", out)
        self.assertIn("eval-suite-standalone", out)

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            rc_bad = sh.main(["--template", "python-runtime-eval", "--name", "123-bad", "--out", "./tmp"])
        self.assertEqual(rc_bad, 1)
        self.assertIn("Invalid --name", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
