import argparse
import requests
import threading
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

BANNER = r"""

     +--^----------,--------,-----,--------^-,       
     | |||||||||   `--------'     |          O       
     `+---------------------------^----------|       
       `\_,---------,---------,--------------'       
         / XXXXXX /'|       /'                        
        / XXXXXX /  `\    /'                         
       / XXXXXX /`-------'                          
      / XXXXXX /                                    
     / XXXXXX /                                     
    (________(                By NK             
     `------'                                       

┌─────────────────────────────────────────────┐
│  🎯 GRAPHQL INTROSPECTION VULN SNIPER       │
└─────────────────────────────────────────────┘

"""

INTROSPECTION_QUERY_LIGHT = {
    "query": """
    query {
      __schema {
        queryType { name }
        mutationType { name }
        types { name }
      }
    }
    """
}

INTROSPECTION_QUERY_FULL = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
      }
    }
    """
}

stop_spinner = False
vulnerable = []
verbose_mode = False

def spinner():
    while not stop_spinner:
        for c in '|/-\\':
            sys.stdout.write(f'\r\033[94m[🔍] Scanning... {c}\033[0m')
            sys.stdout.flush()
            time.sleep(0.1)

def print_banner():
    print(BANNER)
    print("\033[92mProbing GraphQL endpoints for introspection...\033[0m")
    print("-" * 50)

def send_query(url, query):
    try:
        return requests.post(url, json=query, timeout=8).json()
    except Exception:
        if verbose_mode:
            print(f"\033[93m[NOT VULNERABLE]\033[0m {url}")
        return {}

def check_introspection(url):
    data = send_query(url, INTROSPECTION_QUERY_LIGHT)
    schema = data.get("data", {}).get("__schema", {})
    if schema and schema.get("types"):
        print(f"\n\033[91m[VULNERABLE]\033[0m {url} → introspection enabled (light)")
        vulnerable.append((url, schema))
        return

    data_full = send_query(url, INTROSPECTION_QUERY_FULL)
    schema_full = data_full.get("data", {}).get("__schema", {})
    if schema_full and (schema_full.get("types") or schema_full.get("directives")):
        print(f"\n\033[91m[VULNERABLE]\033[0m {url} → introspection enabled (fallback)")
        vulnerable.append((url, schema_full))
    elif verbose_mode:
        print(f"\033[93m[NOT VULNERABLE]\033[0m {url}")

def clean_url(u):
    u = u.strip()
    if not u.startswith("http"):
        u = "https://" + u
    return u

def write_html_report(results):
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    d = f"graphql_report_{now}"
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "report.html")
    with open(path, "w") as f:
        f.write("<html><body><h1>GraphQL Introspection Report</h1><table border=1>")
        f.write("<tr><th>URL</th><th>Query Type</th><th>Mutation Type</th></tr>")
        for url, schema in results:
            f.write(f"<tr><td>{url}</td><td>{schema.get('queryType', {}).get('name')}</td>")
            f.write(f"<td>{schema.get('mutationType', {}).get('name', '-')}</td></tr>")
        f.write("</table></body></html>")
    print(f"\n\033[92m[✔] HTML report saved to {path}\033[0m")

def main():
    global stop_spinner, verbose_mode
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Single GraphQL endpoint")
    group.add_argument("--list", help="File with endpoints")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode (show not vulnerable too)")
    parser.add_argument("--threads", type=int, default=20, help="Number of concurrent threads (default: 20)")
    args = parser.parse_args()

    verbose_mode = args.verbose
    print_banner()

    if not verbose_mode:
        spinner_thread = threading.Thread(target=spinner)
        spinner_thread.start()
    else:
        print("[VERBOSE] Starting scan...\n")

    try:
        targets = []
        if args.url:
            targets = [clean_url(args.url)]
        elif args.list:
            with open(args.list) as f:
                targets = [clean_url(line) for line in f if line.strip()]

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            executor.map(check_introspection, targets)

    finally:
        if not verbose_mode:
            stop_spinner = True
            spinner_thread.join()
        print("\n\033[92m[✔] Scan completed.\033[0m")

    if vulnerable:
        write_html_report(vulnerable)
    else:
        print("\033[93m[!] No introspection-enabled endpoints found.\033[0m")

if __name__ == "__main__":
    main()
