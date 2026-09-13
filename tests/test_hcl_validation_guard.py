#!/usr/bin/env python3
"""Regression tests for deterministic OpenBao HCL validation."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HclValidationGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "scripts/validate_hcl.sh").read_text(encoding="utf-8")

    def test_cached_exact_image_is_reused_before_registry_pull(self) -> None:
        cache_probe = self.source.index(
            'if ! docker image inspect "$image" >/dev/null 2>&1; then'
        )
        pull = self.source.index(
            'timeout --signal=TERM 120s docker pull --platform linux/amd64 "$image"'
        )
        cache_block_end = self.source.index("\nfi\n", pull)
        startup = self.source.index(
            'timeout --signal=TERM 8s docker run --rm --pull=never --platform linux/amd64'
        )
        self.assertLess(cache_probe, pull)
        self.assertLess(pull, cache_block_end)
        self.assertLess(cache_block_end, startup)
        self.assertIn('docker image inspect "$image" >/dev/null', self.source)

    def test_terminal_pull_and_startup_diagnostics_are_preserved(self) -> None:
        self.assertIn("OpenBao image pull failed with status", self.source)
        self.assertIn(
            'tail -n 80 "$verify_dir/image-pull.log" >&2',
            self.source,
        )
        self.assertIn(
            "OpenBao server did not reach the started state inside the bounded probe.",
            self.source,
        )
        self.assertIn(
            'tail -n 80 "$verify_dir/server.log" >&2',
            self.source,
        )

    def test_all_runtime_validation_uses_local_exact_image(self) -> None:
        self.assertEqual(self.source.count("--pull=never"), 2)
        self.assertEqual(self.source.count("--platform linux/amd64"), 3)
        self.assertIn(
            "ghcr.io/openbao/openbao@sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff",
            self.source,
        )

    def test_both_containers_keep_least_privilege_boundary(self) -> None:
        self.assertEqual(self.source.count("--cap-drop ALL"), 2)
        self.assertEqual(
            self.source.count('--user "$(id -u):$(id -g)"'),
            2,
        )
        self.assertNotIn("--user root", self.source)
        self.assertIn("--entrypoint bao", self.source)
        self.assertIn("--entrypoint sh", self.source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
