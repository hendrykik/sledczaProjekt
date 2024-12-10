import requests

HYBRID_API_KEY = "jjobpld635c09646twoqqvf98eaf8c7bjoeydv5gda5b52cfkc3txfic571c3e0b"
HYBRID_API_URL = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
HYBRID_REPORT_URL = "https://www.hybrid-analysis.com/api/v2/report/"

def checkHashWithCircl(hash_value):
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

def checkFileWithHybridanalysis(content, filename):
    headers = {
            "User-Agent": "Falcon Sandbox",
            "api-key": HYBRID_API_KEY
            # Secret: 71a532df33f4ba0ba9d13c313983c88fdb7f0f4920b5ed19
        }

    try:
        response = requests.post(
            HYBRID_API_URL,
            headers=headers,
            files={
                "file": (filename, content),  # Plik (nazwa i zawartość)
                "scan_type": (None, "lookup_ha")   # Parametr "scan_type"
            }
        )        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Błąd podczas przesyłania pliku: {response.status_code} - {response.text}")
            return {}
    except requests.RequestException as e:
        print(f"Błąd połączenia z Hybrid Analysis API: {e}")
        return {}
    
def checkReports(reportIds):
    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": HYBRID_API_KEY
    }
    maliciousCount = 0  
    totalReports = len(reportIds)
    totalThreatScore = 0

    for reportId in reportIds:
        url = f"{HYBRID_REPORT_URL}{reportId}/summary"
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data.get("verdict") == "malicious":
                    maliciousCount += 1
                threatScore = data.get("threat_score", 0)
                totalThreatScore += threatScore
            else:
                print(f"Błąd podczas pobierania raportu {reportId}: {response.status_code}")
        except requests.RequestException as e:
            print(f"Błąd połączenia z Hybrid Analysis API dla raportu {reportId}: {e}")

    tScore = totalThreatScore / totalReports if totalReports > 0 else 0
    print(f"Wynik: {maliciousCount}/{totalReports} raportów oznaczonych jako 'malicious'.")
    print(f"Średni threat_score: {tScore:.2f}")
    return maliciousCount, totalReports, tScore

def fileCheck(file, filename):
    response = checkFileWithHybridanalysis(file, filename)
    reportIds = response.get("reports", [])
    if reportIds:
        return checkReports(reportIds)
    return 0, 0, 0