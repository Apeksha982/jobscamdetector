# checks.py 
import re
import difflib

NL = chr(10)

FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
             "icloud.com", "proton.me", "protonmail.com", "mail.com", "gmx.com"}
RISKY_TLDS = (".xyz", ".top", ".click", ".icu", ".shop", ".live", ".work", ".buzz", ".site", ".online")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at")
KNOWN_PLATFORMS = ("greenhouse.io", "lever.co", "myworkdayjobs.com", "workdayjobs.com",
                   "smartrecruiters.com", "icims.com", "ashbyhq.com", "linkedin.com",
                   "indeed.com", "joinhandshake.com", "glassdoor.com")

# (name, regex, weight, hard_stop, why)   weight 1-5, hard_stop = strong scam signal on its own
PATTERNS = [
    ("Payment request",
     "(registration|training|equipment|processing|application|onboarding|starter kit|background check|security deposit)[ ]+(fee|payment|deposit|cost)"
     "|pay[ ]+(for|the)[ ]+(your )?(training|equipment|kit|laptop)"
     "|wire[ ]+(me|the)[ ]+(money|funds)|gift[ ]?cards?|zelle|cash[ ]?app|venmo",
     5, True, "Real employers do not charge you to get hired."),
    ("Crypto request",
     "bitcoin|crypto|usdt|ethereum|binance|wallet address",
     5, True, "Job offers involving crypto payments or wallets are a common scam pattern."),
    ("Fake-check scheme",
     "cashier.?s check|send you a check|deposit (the|this|your) check|mobile deposit|purchase (your )?(own )?equipment",
     5, True, "Fake-check scams send a check, then ask you to send money back before the check bounces."),
    ("SSN / bank information requested",
     "(?<![a-z])ssn(?![a-z])|social security|bank account|routing number|account number|passport|driver.?s license|credit card|debit card",
     4, True, "Legitimate employers collect these only after a formal offer, through official HR systems."),
    ("Telegram / WhatsApp contact",
     "telegram|whatsapp|signal app|wechat|t[.]me/|wa[.]me/|text me|dm me",
     3, False, "Scammers move chats to private apps so they cannot be traced or reported."),
    ("No interview / instant hire",
     "no interview|hired immediately|instantly hired|without (an )?interview|you are hired|no resume",
     3, False, "Real hiring involves screening or interviews."),
    ("Urgency / pressure",
     "act now|urgent(ly)?|limited (slots|spots|positions)|apply today|respond (asap|immediately)|today only|hurry|last chance|offer expires",
     1, False, "Urgency is used to stop you from checking the offer."),
    ("Too-easy work claims",
     "no experience (needed|required|necessary)|guaranteed (income|pay|salary)|easy money|work from home and earn",
     1, False, "Offers that promise high pay for no skills are a common scam signal."),
    ("Generic form or chat application",
     "forms[.]gle|docs[.]google[.]com/forms|typeform[.]com|wa[.]me/|t[.]me/",
     2, False, "Applications collected through generic forms or chat links skip any real employer system."),
]

SALARY_RE = "[$][ ]?([0-9][0-9,]*)(?:[.][0-9]+)?[ ]*(?:/|per|a|an|each)[ ]*(hour|hr|day|week|month)"


def normalize_domain(value):
    if not value:
        return ""
    d = value.strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    d = d.split("/")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def find_emails(text):
    return re.findall("[a-z0-9._+-]+@([a-z0-9-]+(?:[.][a-z0-9-]+)+)", text.lower())


def find_url_domains(text):
    found = re.findall("https?://(?:www[.])?([a-z0-9.-]+)", text.lower())
    return [d.strip(".") for d in found]


def _flag(name, weight, evidence, why, hard=False):
    return {"name": name, "weight": weight, "evidence": evidence, "why": why, "hard": hard}


def analyze_text(text):
    """Pattern rules plus salary check."""
    t = text.lower()
    flags = []
    for name, pattern, weight, hard, why in PATTERNS:
        m = re.search(pattern, t)
        if m:
            flags.append(_flag(name, weight, m.group(0).strip(), why, hard))

    no_exp = re.search("no experience|entry.level|no skills|no degree", t) is not None
    for m in re.finditer(SALARY_RE, t):
        try:
            amount = float(m.group(1).replace(",", ""))
        except ValueError:
            continue
        unit = m.group(2)
        hourly = {"hour": amount, "hr": amount, "day": amount / 8, "week": amount / 40, "month": amount / 160}[unit]
        if hourly >= 80 or (hourly >= 45 and no_exp):
            flags.append(_flag("Unrealistic salary", 3, m.group(0).strip(),
                               "Very high pay for little or no experience is a classic scam hook."))
            break
    return flags


def check_email(text, sender_email="", company_domain=""):
    """Checks every email domain found in the text (and the sender, if given)."""
    cd = normalize_domain(company_domain)
    domains = set(find_emails(text))
    if sender_email and "@" in sender_email:
        domains.add(sender_email.strip().lower().split("@")[-1])
    flags, positives = [], []
    base = cd.split(".")[0] if cd else ""
    for d in sorted(domains):
        if d in FREE_MAIL:
            flags.append(_flag("Free email used for recruiting", 2, d,
                               "Companies recruit from their own domain, not Gmail or Yahoo."))
        elif cd and (d == cd or d.endswith("." + cd)):
            positives.append("Email domain matches the company website (" + d + ")")
        elif cd and ((len(base) >= 4 and base in d) or difflib.SequenceMatcher(None, d, cd).ratio() >= 0.8):
            flags.append(_flag("Look-alike email domain", 5, d + " vs " + cd,
                               "This domain imitates the company but is not the company's real domain.", True))
        elif cd:
            flags.append(_flag("Email domain does not match company", 4, d + " vs " + cd,
                               "Compare the sender's domain with the company's real website, letter by letter."))
        if d.endswith(RISKY_TLDS):
            flags.append(_flag("Unusual domain ending", 2, d,
                               "Cheap domain endings are common in throwaway scam sites."))
    return flags, positives


def check_company(text, company_domain=""):
    """Checks links in the text against the company website."""
    cd = normalize_domain(company_domain)
    flags, positives = [], []
    for d in sorted(set(find_url_domains(text))):
        if d in SHORTENERS:
            flags.append(_flag("Shortened link", 2, d, "Short links hide where they really lead."))
        elif cd and (d == cd or d.endswith("." + cd)):
            positives.append("Contains a link on the company's own website (" + d + ")")
        elif cd and not d.endswith(KNOWN_PLATFORMS):
            flags.append(_flag("Link goes to a different site than the company", 3, d + " vs " + cd,
                               "Check that application links lead to the company's real site or a known hiring platform."))
    return flags, positives


def run_checks(text, company_domain="", sender_email=""):
    t = text.lower()
    flags = analyze_text(text)
    f2, p2 = check_email(text, sender_email, company_domain)
    f3, p3 = check_company(text, company_domain)
    flags += f2 + f3
    positives = p2 + p3

    asks_money_or_private = any(f["name"] in ("Payment request", "Crypto request", "Fake-check scheme",
                                              "SSN / bank information requested", "Telegram / WhatsApp contact")
                                for f in flags)
    if re.search("interview|phone screen|video call", t) and "no interview" not in t and "without" not in t:
        positives.append("Mentions a normal interview or screening step")
    if len(text) >= 200 and not asks_money_or_private:
        positives.append("No payment, sensitive-data, or private-chat requests found")

    rule_points = min(100, sum(f["weight"] * 12 for f in flags))
    return {"flags": flags, "positives": positives, "rule_points": rule_points}


def level_for(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


RECOMMENDATIONS = {
    "LOW": "No major red flags found. Still check the company on its official website before sharing personal information.",
    "MEDIUM": "Be careful. Verify the recruiter and the company independently before replying with any personal details.",
    "HIGH": "Do not send money or personal documents. Verify the offer through the company's official website, and consider reporting it.",
    "CRITICAL": "This looks like a scam. Do not pay, do not share documents, stop contact, and report it at reportfraud.ftc.gov and on the platform where you found it.",
}


def calculate_risk(rules, model_prob, text_len):
    rule_points = rules["rule_points"]
    model_points = model_prob * 100
    score = max(0.7 * rule_points + 0.3 * model_points, 0.6 * model_points)

    hard = [f for f in rules["flags"] if f["hard"]]
    if hard:
        score = max(score, 60)
    elif rules["flags"] and rules["positives"]:
        score -= min(15, 5 * len(rules["positives"]))
    score = int(round(max(0, min(100, score))))
    level = level_for(score)

    model_says_scam = model_prob >= 0.5
    rules_say_scam = rule_points >= 36
    if hard and len(rules["flags"]) >= 2:
        confidence, reason = "High", "Several strong scam signals were found in the message itself."
    elif hard:
        confidence, reason = "Medium", "One strong scam signal was found, such as a payment request."
    elif text_len < 150:
        confidence, reason = "Low", "The message is short, so the model has little text to work with."
    elif model_says_scam == rules_say_scam and (len(rules["flags"]) >= 3 or (not rules["flags"] and model_prob < 0.15)):
        confidence, reason = "High", "The model and the rules agree, and there is clear evidence."
    elif model_says_scam != rules_say_scam:
        confidence, reason = "Low", "The model and the rules disagree, so treat this result carefully."
    else:
        confidence, reason = "Medium", "The model and rules lean the same way, but the evidence is limited."

    return {"score": score, "level": level, "confidence": confidence, "confidence_reason": reason,
            "recommendation": RECOMMENDATIONS[level], "model_prob": model_prob}


def generate_report(risk, rules, snippet=""):
    lines = ["JobScam Guard report", "",
             "Risk score: " + str(risk["score"]) + "/100 (" + risk["level"] + ")",
             "Confidence: " + risk["confidence"] + " - " + risk["confidence_reason"],
             "Model scam probability: " + str(round(risk["model_prob"] * 100)) + "%", "",
             "Recommendation: " + risk["recommendation"], "", "Red flags:"]
    if rules["flags"]:
        for f in rules["flags"]:
            lines.append("- " + f["name"] + " | evidence: " + f["evidence"] + " | " + f["why"])
    else:
        lines.append("- none found")
    lines += ["", "Positive signals:"]
    if rules["positives"]:
        for p in rules["positives"]:
            lines.append("- " + p)
    else:
        lines.append("- none found")
    if snippet:
        lines += ["", "Message start: " + snippet[:120]]
    lines += ["", "This is a risk signal, not proof. Always verify the employer on its official website."]
    return NL.join(lines)
