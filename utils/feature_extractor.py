import re

def extract_features(url):
    return [
        len(url),
        int(url.startswith("https")),
        int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))),
        url.count("."),
        url.count("/"),
        int("login" in url.lower()),
        int("verify" in url.lower()),
        int("bank" in url.lower()),
        int("secure" in url.lower())
    ]
