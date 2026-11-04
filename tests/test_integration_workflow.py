import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "integration.yml"


@unittest.skipUnless(shutil.which("jq"), "jq is required to exercise the workflow selector")
class IntegrationBinarySelectionTest(unittest.TestCase):
    def select_binary(self, suite, artifacts):
        assignment = next(
            line.strip()
            for line in WORKFLOW.read_text().splitlines()
            if line.strip().startswith("binary=$(")
        )
        # Feed Cargo messages through the workflow's actual selection pipeline.
        selector = assignment.split("|", 1)[1].removesuffix(")")
        return subprocess.run(
            [
                "bash", "-e", "-o", "pipefail", "-c",
                "suite=$1\n" + selector, "selector", suite,
            ],
            input="".join(json.dumps(artifact) + "\n" for artifact in artifacts),
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def artifact(name, kind, executable):
        return {
            "reason": "compiler-artifact",
            "target": {"name": name, "kind": [kind]},
            "executable": executable,
        }

    def test_selects_requested_test_regardless_of_artifact_order(self):
        for suite in ("tpm_flow", "web_status_flow", "multi_server_flow"):
            executable = f"/target/debug/deps/{suite}-0123456789abcdef"
            requested = self.artifact(suite, "test", executable)
            others = [
                self.artifact("mysyncfiles", "lib", None),
                self.artifact("other_suite", "test", "/target/debug/deps/other_suite"),
                self.artifact(suite, "bin", f"/target/debug/{suite}"),
                self.artifact("mysync", "bin", "/target/debug/mysync"),
            ]
            finished = {"reason": "build-finished", "success": True}
            for artifacts in (
                [requested, *others, finished],
                [*others, requested, finished],
            ):
                with self.subTest(suite=suite, artifacts=artifacts):
                    result = self.select_binary(suite, artifacts)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, executable + "\n")

    def test_missing_test_executable_fails(self):
        for artifacts in (
            [],
            [self.artifact("mysync", "bin", "/target/debug/mysync")],
            [self.artifact("other_suite", "test", "/target/debug/deps/other_suite")],
            [self.artifact("tpm_flow", "test", None)],
        ):
            with self.subTest(artifacts=artifacts):
                result = self.select_binary("tpm_flow", artifacts)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
