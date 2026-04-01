from urllib import response
import requests
from flask import Flask, render_template, request, jsonify
import os
import traceback

app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  
app.config['SESSION_COOKIE_SECURE'] = True        
app.config['SESSION_COOKIE_HTTPONLY'] = True      
app.config['SESSION_COOKIE_NAME'] = '__Secure-Session'
app.secret_key = os.environ.get('FLASK_SECRET', 'hello_cracker_change_production')

session = requests.Session()


session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none', 
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
    'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Referer': 'https://www.google.com/'
})

SECURITY_HEADERS_CONFIG = {
    'Strict-Transport-Security': {
        'weight': 30, 
        'label': 'HSTS',
        'risk_msg': 'HSTS tidak aktif. Rentan terhadap serangan SSL Stripping / Downgrade.',
        'rec_msg': 'Aktifkan HSTS (Strict-Transport-Security) untuk memaksa browser menggunakan HTTPS.'
    },
    'Content-Security-Policy': {
        'weight': 25, 
        'label': 'CSP',
        'risk_msg': 'CSP tidak ditemukan. Rentan terhadap serangan XSS (Cross-Site Scripting) dan Data Injection.',
        'rec_msg': 'Implementasikan Content-Security-Policy (CSP) untuk membatasi sumber script yang diizinkan.'
    },
    'X-Frame-Options': {
        'weight': 15, 
        'label': 'X-Frame-Options',
        'risk_msg': 'Header hilang. Website bisa di-embed di iframe orang lain (Clickjacking risk).',
        'rec_msg': 'Set X-Frame-Options ke DENY atau SAMEORIGIN untuk mencegah serangan Clickjacking.'
    },
    'X-Content-Type-Options': {
        'weight': 10, 
        'label': 'X-Content-Type-Options',
        'risk_msg': 'Risiko MIME-sniffing. Browser mungkin mengeksekusi file gambar sebagai script.',
        'rec_msg': 'Set header ini ke "nosniff" agar browser mematuhi tipe konten yang dideklarasikan.'
    },
    'Referrer-Policy': {
        'weight': 10, 
        'label': 'Referrer-Policy',
        'risk_msg': 'Kebijakan Referrer belum diatur. Privasi user mungkin bocor ke situs pihak ketiga.',
        'rec_msg': 'Atur Referrer-Policy (misal: strict-origin-when-cross-origin) untuk menjaga privasi user.'
    },
    'Permissions-Policy': {
        'weight': 5, 
        'label': 'Permissions-Policy',
        'risk_msg': 'Akses fitur browser (kamera/mic) tidak dibatasi secara eksplisit.',
        'rec_msg': 'Gunakan Permissions-Policy untuk membatasi fitur browser apa saja yang boleh digunakan situs.'
    },
    'X-XSS-Protection': {
        'weight': 5, 
        'label': 'X-XSS-Protection',
        'risk_msg': 'Proteksi XSS legacy tidak aktif (Hanya untuk browser lama, CSP lebih penting).',
        'rec_msg': 'Aktifkan header ini untuk perlindungan tambahan pada browser lama.'
    }
}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')

@app.route('/analyze', methods=['POST'])
def analyze():

    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL tidak boleh kosong.'}), 400
    

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        response = session.get(url, timeout=20, verify=True)
        
        server_headers = response.headers
        results = []
        recommendations = []
        score = 0
        max_score = sum(h['weight'] for h in SECURITY_HEADERS_CONFIG.values())


        for header_key, config in SECURITY_HEADERS_CONFIG.items():
            value = None
            for k in server_headers.keys():
                if k.lower() == header_key.lower():
                    value = server_headers[k]
                    break
            
            present = value is not None

            if present:
                score += config['weight']
            else:

                recommendations.append(config['rec_msg'])


            results.append({
                'header': header_key,
                'label': config['label'],
                'present': present,
                'value': value if value else "Not Set / Missing",
                'risk_msg': config['risk_msg'] if not present else None
            })

        final_score = int((score / max_score) * 100)

        waf_suspected = False
         
        blocked_codes = [403, 429] 

        if (response.status_code == 200 or response.status_code in blocked_codes) and final_score == 0:
            waf_suspected = True
            
            if response.status_code == 403:
                reason = "Akses Ditolak (403)"
            elif response.status_code == 429:
                reason = "Akses Ditolak (429)"
            else:
                reason = "Header Disembunyikan"
                
            recommendations.insert(0, f"⚠️ <strong>Firewall Terdeteksi:</strong> {reason}. Scanner diblokir.")

        return jsonify({
            'target': url,
            'score': final_score,
            'headers_analyzed': results,
            'recommendations': recommendations,
            'waf_suspected': waf_suspected,
            'status_code': response.status_code  
        })

    except requests.exceptions.SSLError:
        return jsonify({'error': 'SSL Error: Sertifikat keamanan situs target tidak valid atau kedaluwarsa.'}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'Connection Failed: Website tidak dapat dijangkau atau domain salah.'}), 400
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Timeout: Server merespons terlalu lama (lebih dari 20 detik).'}), 400
    except Exception as e:
        print(f"[INTERNAL ERROR] URL: {url} | Error: {str(e)}")
        traceback.print_exc() 
        
        return jsonify({'error': 'Terjadi kesalahan internal pada server saat memproses permintaan. Silakan coba lagi nanti.'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)