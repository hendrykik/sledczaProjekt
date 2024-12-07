import requests

def check_hash_with_circl(hash_value):
    """
    Sprawdza hash pliku w CIRCL Hash Lookup API.
    
    :param hash_value: Hash (MD5, SHA1, SHA256) pliku do sprawdzenia.
    :return: Słownik z wynikami lub None, jeśli hash nie został znaleziony.
    """
    url = f"https://hashlookup.circl.lu/api/{hash_value}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data
        elif response.status_code == 404:
            return None
        else:
            response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error connecting to CIRCL API: {e}")
        return None

def check_file_with_hybridanalysis(content, filename):
    headers = {
            "User-Agent": "Falcon Sandbox",
            "api-key": HYBRID_API_KEY
        }
    files = {"file": (filename, content)}

    try:
        response = requests.post(HYBRID_API_URL, headers=headers, files=files)
        if response.status_code == 200:
            return response.json()
        else:
            return {}
    except requests.RequestException as e:
        return {}