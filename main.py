from flask import Flask, request, render_template
import requests
from urllib.parse import urljoin
import vt

#config.py
import config

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        all_links = extract_links(url)
        results = scan_with_virustotal(all_links)
        return render_template('results.html', results=results)
    return render_template('index.html')

# URL'lerden linkleri çıkarma fonksiyonu
def extract_links(url):
    urls = set()
    urls.add(url)

    from bs4 import BeautifulSoup
    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href')
            if href:
                # Use urljoin to construct full URLs and filter out invalid ones
                full_url = urljoin(url, href)
                if not full_url.startswith('#') and not full_url.startswith('/'):
                    urls.add(full_url)
    return urls

def scan_with_virustotal(urls): 
    client = vt.Client(config.API_KEY)
    results = []

    for url in urls:
        try:
            url_id = vt.url_id(url)
            analysis = client.get_object("/urls/{}", url_id)
            result = analysis.last_analysis_stats
            results.append({"url": url, "results": {"status": "result", "message": str(result)}})
        except vt.error.APIError as e:
            print(f"Error fetching data for {url}: {e}")
            results.append({"url": url, "results": {"status": "error", "message": str(e)}})
    client.close()
    return results

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')