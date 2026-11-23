#!/usr/bin/env python3
"""Unit tests for scaffold_harness.py."""

from __future__ import annotations

import ast
import contextlib
import io
import json
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

    def test_derive_package_name_snake_case_camelcase_and_keywords(self) -> None:
        self.assertEqual(sh.derive_package_name("My-Agent-Harness"), "my_agent_harness")
        self.assertEqual(sh.derive_package_name("AcmeAgent"), "acme_agent")
        self.assertEqual(sh.derive_package_name("MyHTTPServer"), "my_http_server")
        self.assertEqual(sh.derive_package_name("acme-agent"), "acme_agent")
        self.assertEqual(sh.derive_package_name("simple_pkg"), "simple_pkg")
        self.assertEqual(sh.derive_package_name("123-demo"), "pkg_123_demo")
        self.assertEqual(sh.derive_package_name("class"), "class_pkg")
        # Soft keywords (Python 3.10+/3.12+)
        self.assertEqual(sh.derive_package_name("match"), "match_pkg")
        self.assertEqual(sh.derive_package_name("case"), "case_pkg")
        self.assertEqual(sh.derive_package_name("type"), "type_pkg")

    def test_derive_package_slug_kebab_case(self) -> None:
        self.assertEqual(sh.derive_package_slug("AcmeAgent"), "acme-agent")
        self.assertEqual(sh.derive_package_slug("my_agent"), "my-agent")
        self.assertEqual(sh.derive_package_slug("MyHTTPServer"), "my-http-server")
        self.assertEqual(sh.derive_package_slug("my-ts-agent"), "my-ts-agent")

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
                "# {{PROJECT_NAME}}\n\n{{DESCRIPTION}}\nPackage: {{PACKAGE_NAME}} ({{PACKAGE_SLUG}})\n",
                encoding="utf-8",
            )
            (tpl_dir / "src" / "{{PACKAGE_NAME}}" / "__init__.py").write_text(
                '"""{{PROJECT_NAME}} ({{PACKAGE_NAME}}): {{DESCRIPTION}}"""\n',
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
            self.assertEqual(res.package_slug, "my-agent")
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
            self.assertIn("Package: my_agent (my-agent)", readme)
            self.assertNotIn("{{", readme)

    def test_format_aware_description_escaping_json_py_md(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            tpl_root = tmp_root / "templates"
            tpl_dir = tpl_root / "typescript-runtime-eval"
            (tpl_dir / "src" / "{{PACKAGE_NAME}}").mkdir(parents=True)
            (tpl_dir / "package.json").write_text(
                '{\n  "name": "{{PACKAGE_SLUG}}",\n  "description": "{{DESCRIPTION}}"\n}\n',
                encoding="utf-8",
            )
            (tpl_dir / "src" / "{{PACKAGE_NAME}}" / "__init__.py").write_text(
                '"""{{PROJECT_NAME}}: {{DESCRIPTION}}"""\nVALUE = "{{DESCRIPTION}}"\n',
                encoding="utf-8",
            )
            (tpl_dir / "README.md").write_text(
                "# {{PROJECT_NAME}}\n\n{{DESCRIPTION}}\n",
                encoding="utf-8",
            )

            tricky_desc = 'Agent "alpha" with """triple""" quotes\nline2\\trail"'
            out_dir = tmp_root / "out"
            res = sh.scaffold_project(
                template="typescript-runtime-eval",
                project_name="AcmeAgent",
                output_dir=out_dir,
                description=tricky_desc,
                templates_root=tpl_root,
            )

            self.assertEqual(res.package_name, "acme_agent")
            self.assertEqual(res.package_slug, "acme-agent")

            # Valid JSON with exact unescaped description round-trip
            pkg_json = json.loads((out_dir / "package.json").read_text(encoding="utf-8"))
            self.assertEqual(pkg_json["name"], "acme-agent")
            self.assertEqual(pkg_json["description"], tricky_desc)

            # Valid Python AST with docstring and string literal
            py_src = (out_dir / "src" / "acme_agent" / "__init__.py").read_text(encoding="utf-8")
            parsed_ast = ast.parse(py_src)
            doc = ast.get_docstring(parsed_ast)
            self.assertIsNotNone(doc)
            self.assertIn('"""triple"""', doc or "")

            # Markdown collapses newlines cleanly
            md = (out_dir / "README.md").read_text(encoding="utf-8")
            desc_line = md.splitlines()[2]
            self.assertNotIn("\n", desc_line)
            self.assertIn("line2", desc_line)

    def test_post_render_assertion_detects_unresolved_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            tpl_root = tmp_root / "templates"
            tpl_dir = tpl_root / "python-runtime-eval"
            tpl_dir.mkdir(parents=True)
            (tpl_dir / "README.md").write_text("{{DESCRIPTION}}\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                sh.scaffold_project(
                    template="python-runtime-eval",
                    project_name="AcmeAgent",
                    output_dir=tmp_root / "out",
                    description="Contains {{PACKAGE_NAME}} literally",
                    templates_root=tpl_root,
                )

    def test_non_empty_target_requires_force_and_warns_to_stderr(self) -> None:
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

            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                res = sh.scaffold_project(
                    template="eval-suite-standalone",
                    project_name="eval-one",
                    output_dir=out_dir,
                    force=True,
                    templates_root=tpl_root,
                )
            self.assertEqual(len(res.files), 1)
            self.assertTrue((out_dir / "eval.py").is_file())
            self.assertTrue((out_dir / "keep.txt").is_file())
            self.assertIn("Warning:", err_buf.getvalue())
            self.assertIn("preserving existing unrelated files", err_buf.getvalue())

    def test_cli_list_quickstart_and_errors(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sh.main(["--list"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("python-runtime-eval", out)
        self.assertIn("typescript-runtime-eval", out)
        self.assertIn("eval-suite-standalone", out)

        with tempfile.TemporaryDirectory() as tmp:
            py_out = Path(tmp) / "py-proj"
            buf_py = io.StringIO()
            with contextlib.redirect_stdout(buf_py):
                rc_py = sh.main(["--template", "python-runtime-eval", "--name", "AcmeAgent", "--out", str(py_out)])
            self.assertEqual(rc_py, 0)
            out_py = buf_py.getvalue()
            self.assertIn("package=acme_agent", out_py)
            self.assertIn("slug=acme-agent", out_py)
            self.assertIn("Next steps:", out_py)
            self.assertIn("python -B -m unittest", out_py)

            ts_out = Path(tmp) / "ts-proj"
            buf_ts = io.StringIO()
            with contextlib.redirect_stdout(buf_ts):
                rc_ts = sh.main(["--template", "typescript-runtime-eval", "--name", "AcmeAgent", "--out", str(ts_out)])
            self.assertEqual(rc_ts, 0)
            out_ts = buf_ts.getvalue()
            self.assertIn("node --test", out_ts)

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            rc_bad = sh.main(["--template", "python-runtime-eval", "--name", "123-bad", "--out", "./tmp"])
        self.assertEqual(rc_bad, 1)
        self.assertIn("Invalid --name", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
