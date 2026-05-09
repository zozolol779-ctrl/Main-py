import random


class PhishingCampaigner:
    def __init__(self, db):
        self.db = db

    def generate_scenario(self, target_ip: str) -> dict:
        """
        Generates a custom phishing scenario for a target node.
        """
        nodes = self.db.db.get("nodes", {})
        target_data = nodes.get(f"neighbor_{target_ip}", {})

        os_env = target_data.get("os", "Generic Server")

        scenarios = [
            {
                "title": "System Update (Critical)",
                "subject": f"Action Required: {os_env} Patch Verification",
                "body": f"A critical vulnerability has been detected on {target_ip}. Direct patches are available at [LINK].",
                "type": "Technical Phishing",
            },
            {
                "title": "IT Asset Verification",
                "subject": "Inventory Check: New Asset Detected",
                "body": f"An unauthorized node ({target_ip}) was detected on the network. Please confirm ownership at [LINK].",
                "type": "Compliance Bait",
            },
            {
                "title": "VPN Migration",
                "subject": "Sovereign Gateway: VPN Transition",
                "body": "Your access gateway is being migrated. Please download the new configuration from the internal portal.",
                "type": "Credential Harvesting",
            },
        ]

        return random.choice(scenarios)

    def get_all_campaigns(self):
        nodes = self.db.db.get("nodes", {})
        campaigns = []
        for nid, data in nodes.items():
            ip = data.get("ip")
            if ip:
                campaigns.append(
                    {"target_ip": ip, "scenario": self.generate_scenario(ip)}
                )
        return campaigns
