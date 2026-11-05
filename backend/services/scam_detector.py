
import re


def detect_scam(message):
    message = str(message or "").lower().strip()

    risk_score = 0
    indicators = []
    explanations = []

    def contains_any(words):
        """Match complete words or phrases, avoiding partial-word matches."""
        return any(
            re.search(
                r"(?<!\w)" + re.escape(word) + r"(?!\w)",
                message
            )
            for word in words
        )

    def add_indicator(name, points, reason):
        """Add a warning and explain why it affects the score."""
        nonlocal risk_score

        risk_score += points
        indicators.append(name)
        explanations.append({
            "indicator": name,
            "points": points,
            "reason": reason
        })

    # 1. Urgency
    urgency_words = [
        "urgent",
        "immediately",
        "right now",
        "act now",
        "hurry",
        "as soon as possible"
    ]

    if contains_any(urgency_words):
        add_indicator(
            "Urgency detected",
            15,
            "The message uses urgent language to pressure "
            "the recipient to act quickly."
        )

    # 2. Credentials and sensitive information
    credential_words = [
        "password",
        "otp",
        "one time password",
        "pin",
        "cvv",
        "verification code",
        "security code"
    ]

    if contains_any(credential_words):
        add_indicator(
            "Credential or sensitive information request",
            25,
            "The message refers to credentials or sensitive "
            "information that could be misused. Never share "
            "passwords, OTPs, PINs, or CVVs with an unverified sender."
        )

    # 3. Banking and financial references
    banking_words = [
        "bank",
        "bank account",
        "account number",
        "bank details",
        "account details",
        "credit card",
        "debit card",
        "card number",
        "upi",
        "upi id",
        "payment",
        "transaction"
    ]
    if contains_any(banking_words) and contains_any([
        "send", "share", "provide","give", "enter", "submit",
        "confirm", "verify", "update", "click",
        "urgent", "immediately", "blocked", "suspended",
        "kyc", "processing fee", "registration fee",
        "pay now", "transfer money", "password", "otp",
        "pin", "cvv", "won", "prize", "reward"
    ]):
        add_indicator(
            "Financial or banking reference",
            10,
            "The message refers to banking or financial information "
            "alongside a potentially risky action or request. "
            "Verify unexpected requests through your bank's "
            "official channel."
        )

    # 4. Requests to share sensitive information
    request_words = [
        "send",
        "send me",
        "send us",
        "share",
        "share with me",
        "provide",
        "give me",
        "give",
        "tell me",
        "reply with",
        "enter",
        "submit",
        "type",
        "confirm",
        "verify",
        "update"
    ]

    sensitive_data_words = [
        "password",
        "otp",
        "one time password",
        "pin",
        "upi pin",
        "cvv",
        "security code",
        "verification code",
        "bank account number",
        "account number",
        "bank details",
        "account details",
        "credit card number",
        "debit card number",
        "card number",
        "bank credentials",
        "banking credentials"
    ]

    request_pattern = (
        r"\b(?:send|share|provide|give|tell|reply|enter|submit|"
        r"type|confirm|verify|update)\b"
        r"[\s\S]{0,60}?"
        r"\b(?:password|otp|one time password|pin|upi pin|cvv|"
        r"security code|verification code|bank account number|"
        r"account number|bank details|account details|"
        r"credit card number|debit card number|card number|"
        r"bank credentials|banking credentials)\b"
    )

    reverse_request_pattern = (
        r"\b(?:password|otp|one time password|pin|upi pin|cvv|"
        r"security code|verification code|bank account number|"
        r"account number|bank details|account details|"
        r"credit card number|debit card number|card number|"
        r"bank credentials|banking credentials)\b"
        r"[\s\S]{0,40}?"
        r"\b(?:send|share|provide|give|tell|reply|enter|submit|"
        r"type|confirm|verify|update)\b"
    )

    asks_for_sensitive_data = (
        contains_any(request_words)
        and contains_any(sensitive_data_words)
        and (
            re.search(request_pattern, message)
            or re.search(reverse_request_pattern, message)
        )
    )

    if asks_for_sensitive_data:
        add_indicator(
            "Request for sensitive information detected",
            30,
            "The message appears to ask for sensitive credentials "
            "or financial details. Do not share passwords, OTPs, "
            "PINs, CVVs, or banking details in response to an "
            "unexpected message."
        )

    # 5. Account verification requests
    verification_words = [
        "verify your account",
        "account verification",
        "account needs verification",
        "verify your identity",
        "confirm your account",
        "review your account"
    ]

    if contains_any(verification_words):
        add_indicator(
            "Account verification request detected",
            15,
            "The message asks the recipient to verify or review "
            "an account. Check the request through the official "
            "website or app before using any link."
        )

    # 6. Suspicious links or click requests
    link_words = [
        "click",
        "click here",
        "open the link",
        "visit the link",
        "verify using this link"
    ]

    if contains_any(link_words):
        add_indicator(
            "Suspicious link or click request",
            20,
            "The message asks the recipient to click or open "
            "a link. Verify the destination before using it."
        )

    # 7. URL detection
    url_pattern = r"https?://\S+|www\.\S+"

    if re.search(url_pattern, message):
        add_indicator(
            "URL detected",
            20,
            "The message contains a web address. Check the "
            "destination carefully because a URL alone "
            "does not prove a scam."
        )

    # 8. Threats and account/device compromise claims
    threat_words = [
        "blocked",
        "suspended",
        "deactivated",
        "account will be closed",
        "account will be blocked",
        "account will be suspended",
        "legal action"
    ]

    if contains_any(threat_words):
        add_indicator(
            "Threat or account suspension detected",
            20,
            "The message threatens account suspension or another "
            "consequence, which may pressure the recipient to act."
        )

    compromise_words = [
        "hacked",
        "compromised",
        "been hacked",
        "account was hacked"
    ]

    if contains_any(compromise_words):
        add_indicator(
            "Possible account or device compromise claim detected",
            15,
            "The message claims that an account or device has "
            "been hacked or compromised. Verify the claim "
            "independently before sharing information or paying."
        )

    # 9. KYC
    kyc_words = [
        "kyc",
        "kyc expired",
        "update kyc",
        "complete kyc",
        "verify kyc"
    ]

    if contains_any(kyc_words):
        add_indicator(
            "KYC verification request detected",
            20,
            "The message refers to KYC verification or updates. "
            "Verify such requests through the institution's "
            "official website or app."
        )

    # 10. Prize and reward
    reward_words = [
        "won",
        "winner",
        "prize",
        "reward",
        "lottery",
        "cashback",
        "free money",
        "congratulations"
    ]

    if contains_any(reward_words):
        add_indicator(
            "Prize or financial reward detected",
            20,
            "The message mentions a prize or reward, which can "
            "be used to attract people into fraudulent schemes. "
            "Check the context before deciding."
        )

    # 11. Financial scam language
    financial_words = [
        "refund",
        "investment",
        "loan",
        "cash prize",
        "money transfer",
        "double your money",
        "registration fee",
        "processing fee",
        "send money",
        "pay now"
    ]

    if contains_any(financial_words):
        add_indicator(
            "Financial scam language detected",
            15,
            "The message mentions a financial transaction, fee, "
            "refund, loan, or investment that should be independently "
            "verified."
        )

    # 12. Job scams
    job_words = [
        "work from home",
        "work-from-home",
        "job offer",
        "job opportunity",
        "registration fee",
        "joining fee",
        "offer letter",
        "earn money from home"
    ]

    if contains_any(job_words):
        add_indicator(
            "Potential job scam detected",
            15,
            "The message mentions a job or work opportunity that "
            "should be verified, especially if fees or advance "
            "payments are requested."
        )

    # 13. Possible impersonation
    impersonation_words = [
        "customer care",
        "customer support",
        "bank officer",
        "bank manager",
        "police officer",
        "government officer"
    ]

    if contains_any(impersonation_words):
        add_indicator(
            "Possible impersonation detected",
            15,
            "The message refers to an authority or support role. "
            "Verify the sender's identity through an official channel."
        )

    # Additional warning for prize messages requesting a fee
    fee_words = [
        "processing fee",
        "registration fee",
        "claim fee",
        "advance fee",
        "pay a fee",
        "pay fee"
    ]

    claims_reward = contains_any(reward_words)
    requests_fee = contains_any(fee_words)

    if claims_reward and requests_fee:
        add_indicator(
            "Prize claim fee warning",
            25,
            "The message combines a prize or reward claim with "
            "a fee request. This is a common scam pattern; "
            "verify independently and do not pay to claim an "
            "unexpected prize."
        )

    # Keep the score within 0–100
    risk_score = min(risk_score, 100)

    # Risk level
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    # Safety recommendation
    if risk_level == "HIGH":
        recommendation = (
            "Do not click suspicious links or share passwords, OTPs, "
            "PINs, CVVs, or financial information. Verify the message "
            "using an official source."
        )
    elif risk_level == "MEDIUM":
        recommendation = (
            "Be cautious. Verify the sender independently and avoid "
            "sharing sensitive information, clicking suspicious links, "
            "or making unexpected payments."
        )
    elif risk_level == "LOW":
        recommendation = (
            "Some suspicious indicators were detected. Verify the "
            "sender and check the context before acting."
        )
    else:
        recommendation = (
            "No major scam indicators were detected by the current "
            "rules. This does not guarantee that the message is safe."
        )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "explanations": explanations,
        "recommendation": recommendation
    }
