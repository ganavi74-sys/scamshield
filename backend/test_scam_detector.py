
from services.scam_detector import detect_scam


def run_test(name, message, expected_level, expected_indicator=None):
    result = detect_scam(message)

    passed = result["risk_level"] == expected_level

    if expected_indicator:
        passed = passed and expected_indicator in result["indicators"]

    status = "PASS" if passed else "FAIL"

    print(f"\n[{status}] {name}")
    print(f"  Message: {message}")
    print(f"  Score: {result['risk_score']}/100")
    print(f"  Level: {result['risk_level']}")
    print(f"  Indicators: {result['indicators']}")

    return passed


tests = [
    (
        "Harmless greeting",
        "Hi, good morning! Hope you have a wonderful day. See you in class tomorrow.",
        "SAFE",
        None,
    ),
    (
        "Suspicious bank message",
        "URGENT: Your bank account will be blocked today. Click this link to verify your password and OTP immediately.",
        "HIGH",
        "Credential or sensitive information request",
    ),
    (
        "Account verification message",
        "Your account needs verification. Please review your account using this link.",
        "LOW",
        "Account verification request detected",
    ),
    (
        "Prize with processing fee",
        "Congratulations! You have won ₹50,000. Pay a processing fee to claim your prize.",
        "MEDIUM",
        "Financial scam language detected",
    ),
    (
        "Suspicious mobile hacking message",
        "your mobile is hacked send me your bank account number",
        "MEDIUM",
        "Financial or banking reference",
    ),
]

passed_count = 0

for test in tests:
    if run_test(*test):
        passed_count += 1

print("\n" + "=" * 40)
print(f"Tests passed: {passed_count}/{len(tests)}")
print(f"Tests failed: {len(tests) - passed_count}/{len(tests)}")
