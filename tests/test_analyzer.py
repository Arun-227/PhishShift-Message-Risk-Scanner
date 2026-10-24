import unittest
from analyzer import analyze_message


class TestPhishShift(unittest.TestCase):

    def test_result_fields(self):
        result = analyze_message(
            "The meeting is tomorrow at 10 AM."
        )

        required_fields = [
            "score",
            "risk",
            "reasons",
            "prediction",
            "confidence"
        ]

        for field in required_fields:
            self.assertIn(field, result)

    def test_score_range(self):
        result = analyze_message(
            "Urgent! Verify your password at http://example.com"
        )

        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_risk_category(self):
        result = analyze_message("Hello, how are you?")

        self.assertIn(
            result["risk"],
            ["Low Risk", "Medium Risk", "High Risk"]
        )

    def test_reasons_are_returned(self):
        result = analyze_message(
            "Click here to verify your password"
        )

        self.assertTrue(len(result["reasons"]) > 0)


if __name__ == "__main__":
    unittest.main()