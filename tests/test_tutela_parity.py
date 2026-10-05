"""Differential conformance: the Python oracle against the shared parity corpus.

The F# authority runs the same corpus in tests/Tutela.Core.Tests. Both must
reproduce every case's posture and reasons exactly (TUT-1804, TUT-1807).
"""
import importlib.util
import json
import unittest
from pathlib import Path

from src.tutela_gate import exception_rejections, load_role_registry, sensitive_match

HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location("parity_corpus",HERE/"parity"/"generate_corpus.py")
corpus_module=importlib.util.module_from_spec(spec); spec.loader.exec_module(corpus_module)
CORPUS=json.loads((HERE/"parity"/"corpus.json").read_text())

class ParityCorpusTests(unittest.TestCase):
    def test_corpus_is_regenerated_from_reviewed_cases(self):
        self.assertEqual(json.dumps(corpus_module.build(),indent=1)+"\n",(HERE/"parity"/"corpus.json").read_text())

    def test_corpus_is_not_trivially_small(self):
        self.assertGreaterEqual(len(CORPUS["cases"]),80)
        self.assertEqual({"PASS","CONDITIONAL","BLOCKED","INDETERMINATE"},{c["expect"]["posture"] for c in CORPUS["cases"]})

    def test_oracle_reproduces_every_case(self):
        for c in CORPUS["cases"]:
            with self.subTest(case=c["name"]):
                posture,reasons=corpus_module.oracle(c)
                self.assertEqual(c["expect"]["posture"],posture)
                self.assertEqual(c["expect"]["reasons"],reasons)

    def test_oracle_exception_rejection_codes(self):
        for c in CORPUS["cases"]:
            if "exceptionRejections" not in c: continue
            with self.subTest(case=c["name"]):
                e=corpus_module.expand(c["assessment"])["exceptions"][0]
                got=exception_rejections(e,c.get("roleRegistry") or load_role_registry(),corpus_module.parse_at(c["at"]))
                self.assertEqual(c["exceptionRejections"],got)

class SensitiveCatalogTests(unittest.TestCase):
    # TUT-0401: the gate's sensitive-data rules come from the single catalog.
    def test_catalog_key_rule_ids_are_reported(self):
        self.assertEqual(("field","TUTELA-SD-K003"),sensitive_match({"nested":[{"PassWd":"x"}]}))

    def test_catalog_value_rule_ids_are_reported(self):
        self.assertEqual(("value","TUTELA-SD-V004"),sensitive_match(["key "+"AKIA"+"ABCDEFGHIJKLMNOP"]))

    def test_lookalike_words_do_not_match(self):
        self.assertIsNone(sensitive_match({"method":"task-description-for-the-risk-assessment","tokenizer":"x"}))

if __name__=="__main__": unittest.main()
