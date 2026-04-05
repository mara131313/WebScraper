import pandas as pd
import requests
import urllib3
import os
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# dezactiveaza avertismentele SSL pentru a putea accesa mai multe domenii fara intreruperi
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# configureaza un user agent real pentru a evita blocajele de tip "bot protection"
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
# timpul maxim de asteptare pentru un server
TIMEOUT = 10
# numarul de fire de executie paralele pentru accelerarea scanarii listei de domenii
MAX_WORKERS = 30

def load_signatures(folder_path):
    """ functie pentru incarcarea tuturor fisierelor json cu regulile de recunoastere ale tehnologiilor"""
    all_sigs = {}
    if not os.path.exists(folder_path):
        return all_sigs
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(folder_path, filename), 'r', encoding="utf-8") as f:
                    all_sigs.update(json.load(f))
            except:
                continue
    print(f"Signatures loaded: {len(all_sigs)}")
    return all_sigs


def fetch_extra(url):
    """ functie pentru descarcarea resurselor externe """
    try:
        r = requests.get(url, timeout=5, verify=False, headers={'User-Agent': USER_AGENT})
        if r.status_code == 200:
            return r.text[:150000]  # limitare a dimensiunii pentru memorie
    except:
        pass
    return ""


def resolve_implies(detected, signatures):
    """ adauga automat tehnologiile care sunt implicit prezente prin detectarea altei tehnologii """
    res = {t['technology']: t for t in detected}
    added = True
    while added:
        added = False
        for name in list(res.keys()):
            implied = signatures.get(name, {}).get('implies', [])
            if isinstance(implied, str):
                implied = [implied]
            for i_tech in implied:
                clean_i = i_tech.split('\\;')[0]
                if clean_i not in res:
                    res[clean_i] = {"technology": clean_i, "proof": f"Implied by {name}"}
                    added = True
    return list(res.values())


def identify_technologies(site_data, signatures):
    """ motorul principal de analiza care compara datele site-ului cu semnaturile Wappalyzer """
    detected = []
    html = site_data.get("html", "")
    headers = site_data.get("headers", {})
    cookies = site_data.get("cookies", {})

    # se extrag elementele cheie din HTML
    script_srcs = re.findall(r'src=["\']([^"\']+)["\']', html, re.I)
    meta_tags = re.findall(r'<meta[^>]+>', html, re.I)
    iframe_srcs = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.I)
    css_classes = " ".join(re.findall(r'class=["\']([^"\']+)["\']', html, re.I)).lower()
    html_lower = html.lower()

    # incepe verificarea tehnologiilor in diferite zone
    for tech_name, rules in signatures.items():
        found = False
        proof = ""

        # in COOKIES
        if "cookies" in rules:
            for c_name, p in rules["cookies"].items():
                if c_name.lower() in cookies:
                    val = cookies[c_name.lower()]
                    if not p or re.search(p.split('\\;')[0], val, re.I):
                        found = True
                        proof = f"Cookie: {c_name}"
                        break

        # HEADERS
        if not found and "headers" in rules:
            for h_name, p in rules["headers"].items():
                val = headers.get(h_name.lower())
                if val and re.search(p.split('\\;')[0], val, re.I):
                    found = True
                    proof = f"Header: {h_name}"
                    break

        # DOM
        if not found and "dom" in rules:
            d_rules = [rules["dom"]] if isinstance(rules["dom"], str) else rules["dom"]
            for sel in d_rules:
                if isinstance(sel, str) and sel.startswith('.') and sel[1:].lower() in css_classes:
                    found = True
                    proof = f"CSS Class: {sel}"
                    break

        # in script uri externe
        if not found and "scriptSrc" in rules:
            p_list = [rules["scriptSrc"]] if isinstance(rules["scriptSrc"], str) else rules["scriptSrc"]
            for pat in p_list:
                clean_p = pat.split('\\;')[0]
                for src in script_srcs:
                    if re.search(clean_p, src, re.I):
                        found = True
                        proof = "Script source"
                        break
                if found: break

        # META TAGS
        if not found and "meta" in rules:
            for m_name, patterns in rules["meta"].items():
                p_list = [patterns] if isinstance(patterns, str) else patterns
                for pat in p_list:
                    clean_p = pat.split('\\;')[0]
                    for tag in meta_tags:
                        if re.search(clean_p, tag, re.I):
                            found = True
                            proof = f"Meta: {m_name}"
                            break
                    if found: break

        # IFRAME
        if not found and "iframeSrc" in rules:
            p_list = [rules["iframeSrc"]] if isinstance(rules["iframeSrc"], str) else rules["iframeSrc"]
            for pat in p_list:
                clean_p = pat.split('\\;')[0]
                for src in iframe_srcs:
                    if re.search(clean_p, src, re.I):
                        found = True
                        proof = "Iframe source"
                        break
                if found: break

        # HTML
        if not found and "html" in rules:
            p_list = [rules["html"]] if isinstance(rules["html"], str) else rules["html"]
            for p in p_list:
                clean_p = p.split('\\;')[0]
                if re.search(clean_p, html, re.I):
                    found = True
                    proof = "HTML pattern"
                    break

        if found:
            detected.append({"technology": tech_name, "proof": proof})

    return resolve_implies(detected, signatures)


def process_domain(domain, signatures):
    """ se ocupa de conexiunea cu un domeniu si colecteaza toate datele pentru analiza """
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})
    data = None
    last_error = "Unknown Error"

    # incearca HTTPS si daca nu merge, trece la HTTP
    for proto in ["https", "http"]:
        try:
            r = session.get(f"{proto}://{domain}", timeout=TIMEOUT, verify=False, allow_redirects=True)
            data = {
                "html": r.text[:800000],
                "headers": {k.lower(): str(v).lower() for k, v in r.headers.items()},
                "cookies": {k.lower(): str(v).lower() for k, v in session.cookies.get_dict().items()},
                "url": r.url
            }
            break
        except Exception as e:
            last_error = str(e)
            continue

    if not data:
        return domain, None, last_error

    # pentru a cauta tehnologii in fisierele externe
    css_links = re.findall(r'<link [^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\']', data["html"], re.I)
    extra_content = ""
    # descarca primele 10 fisiere CSS pentru a identifica framework-uri de design
    for link in css_links[:10]:
        full_url = link if link.startswith('http') else data["url"].rstrip('/') + '/' + link.lstrip('/')
        extra_content += fetch_extra(full_url)

    # verifica ads.txt pentru platforme de publicitate si wp-json pentru prezenta API-ului WordPress
    extra_content += fetch_extra(data["url"].rstrip('/') + "/ads.txt")
    extra_content += fetch_extra(data["url"].rstrip('/') + "/wp-json/")

    # combina codul HTML principal cu datele extra
    data["html"] += "\n" + extra_content
    techs = identify_technologies(data, signatures)
    return domain, techs, None


def main():
    # se initializeaza folderul cu regulile de detectare si fisierul cu domenii
    signatures = load_signatures('technologies')
    df = pd.read_parquet('input.snappy.parquet')
    domains = df['root_domain'].tolist()
    results = {}
    failed_domains = []

    print(f"Starting analysis for {len(domains)} domains...\n")

    # se foloseste ThreadPoolExecuter pentru procesarea paralela a domeniilor
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_domain, d, signatures): d for d in domains}
        for future in as_completed(futures):
            dom, techs, error = future.result()
            if error:
                print(f"FAILED {dom}: {error}")
                failed_domains.append(dom)
            else:
                results[dom] = techs

    # se salveaza raportul final in output.json
    with open('output.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)

    # identificarea site-urilor cu 0 tehnologii
    zero_tech_domains = [dom for dom, techs in results.items() if len(techs) == 0]
    unique_techs = {t['technology'] for techs in results.values() for t in techs}

    print(f"\nSTATS:")
    print(f"Accessed domains: {len(results)} / {len(domains)}")
    print(f"Unique technologies: {len(unique_techs)}")
    print(f"Total detections: {sum(len(t) for t in results.values())}")
    print(f"Total domains with 0 technologies detected: {len(zero_tech_domains)}")
    if zero_tech_domains:
        for d in zero_tech_domains:
            print(f" - {d}")
    print(f"\nRESULTS can be found in 'output.json'")


if __name__ == "__main__":
    main()