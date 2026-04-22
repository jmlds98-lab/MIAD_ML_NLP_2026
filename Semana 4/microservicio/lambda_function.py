import joblib
import os
import json
import numpy as np
import sys
import hashlib

def lambda_handler(event, context):

    pkl_path = os.path.dirname(__file__) + '/phishing_clf.pkl'

    # DIAGNÓSTICO: información del archivo y entorno
    diag = {
        "python_version": sys.version,
        "joblib_version": joblib.__version__,
        "numpy_version": np.__version__,
        "pkl_exists": os.path.exists(pkl_path),
        "pkl_path": pkl_path,
        "files_in_task_dir": sorted(os.listdir(os.path.dirname(__file__))),
    }

    if os.path.exists(pkl_path):
        size = os.path.getsize(pkl_path)
        with open(pkl_path, 'rb') as f:
            head = f.read(20)
            f.seek(0)
            md5 = hashlib.md5(f.read()).hexdigest()
        diag["pkl_size"] = size
        diag["pkl_first_bytes_hex"] = head.hex()
        diag["pkl_md5"] = md5

    print("DIAG:", json.dumps(diag, indent=2))

    try:
        clf = joblib.load(pkl_path)
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e), "diag": diag})
        }

    try:
        import sklearn
        diag["sklearn_version"] = sklearn.__version__
    except Exception:
        pass

    url = event.get('url')
    url_ = {'url': url}
    keywords = ['https', 'login', '.php', '.html', '@', 'sign']
    for keyword in keywords:
        url_['keyword_' + keyword] = int(keyword in url_['url'])
    url_['lenght'] = len(url_['url']) - 2
    domain = url_['url'].split('/')[2]
    url_['lenght_domain'] = len(domain)
    url_['isIP'] = int((url_['url'].replace('.', '') * 1).isnumeric())
    url_['count_com'] = url_['url'].count('com')
    url_.pop('url')

    p1 = clf.predict_proba(np.array(list(url_.values())).reshape(1, -1))[0, 1]

    return {
        "statusCode": 200,
        "body": json.dumps({"result": p1, "diag": diag})
    }
