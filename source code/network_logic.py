import requests

class NetworkManager:
    @staticmethod
    def search_games(query):
        url = f"https://store.steampowered.com/api/storesearch/?term={requests.utils.quote(query)}&l=english&cc=US"
        resp = requests.get(url, timeout=6)
        return resp.json().get('items') if resp.ok else []

    @staticmethod
    def get_manifest_url(server_template, appid):
        branches = ["main", "master"]
        for branch in branches:
            url = server_template.format(branch=branch, appid=appid)
            if requests.head(url, timeout=5).status_code == 200:
                return url
        return None