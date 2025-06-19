import whois

class WhoisTool:
    @staticmethod
    def lookup(domain: str):
        try:
            w = whois.whois(domain)
            return w
        except Exception as e:
            return {"error": str(e)}
