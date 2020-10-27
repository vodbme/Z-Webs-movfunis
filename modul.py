import base64
import hashlib
import hmac
import re
import os
from datetime import datetime

import pytz
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import request, render_template
from pymongo import MongoClient

gsite = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'  # dev
gsecret = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'  # dev
enkey = "w2QrMBq%zqkAe$3R3okFKkjdX7NxmSUF&m@1oRGvB$HwUirN@z"
clientweb = MongoClient('mongodb://vxzusr:NsTC6CJG&ScMcv69@vdb-02.vodb.ch:14086/?replicaSet=rs0&authSource=voxzer&readPreference=secondary')
dbweb = clientweb['voxzer']
clientlog = MongoClient('mongodb+srv://vxz:scraper2017@cluster0.e3ukx.mongodb.net/vxzusr?retryWrites=true&w=majority')
dblog = clientlog['vxzusr']
wcdn = "https://cdn.123movies.fun"
strm_uri = "https://crewplayer.fun"
imgcdn = "https://img.vxdn.net"
host_url = "https://123moviesfun.is"

per_page = 40


def encrypt(self):
    ikey = enkey.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=ikey, iterations=1000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(ikey))
    f = Fernet(key)
    return f.encrypt(self)


def hmacenc(self):
    hmac_sha1 = hmac.HMAC(key=enkey.encode(), msg=self, digestmod=hashlib.sha1).hexdigest()
    return format(hmac_sha1)


def utcnow(p):
    now = (datetime.now(pytz.timezone('UTC'))).strftime(p)
    return now



def ts_now():
    p = '%Y-%m-%dT%H:%M:%S.%fZ'
    my_date = (datetime.now(pytz.timezone('UTC'))).strftime(p)
    epoch = int((datetime.strptime(my_date, p) - datetime(1970, 1, 1)).total_seconds())
    return epoch


def ts_day():
    p = '%Y-%m-%d'
    my_date = (datetime.now(pytz.timezone('UTC'))).strftime(p)
    epoch = int((datetime.strptime(my_date, p) - datetime(1970, 1, 1)).total_seconds())
    return epoch


def user_ip():
    if not request.headers.getlist("X-Forwarded-For"):
        return request.remote_addr
    else:
        return request.headers['X-Forwarded-For'].split(', ')[0]


def bot_ip():
    return request.headers['X-Forwarded-For']


def check_recaptcha(gcaptcha):
    url = 'https://www.google.com/recaptcha/api/siteverify?secret=' + gsecret + '&response=' + gcaptcha
    req = requests.get(url)
    if 'success' in req.text:
        data = req.json()
        if data['success']:
            return True
        else:
            return False
    else:
        return False


def is_valid_email(email):
    pattern = re.compile(r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
    if not re.match(pattern, email):
        return "bad"
    else:
        return "ok"


def activation_email(email):
    items = dbweb.users.find_one({"email": email})
    if items:
        htpl = render_template('backend/email/activation.html', items=items, host_url=host_url)
        uri = "https://api.mailgun.net/v3/mx.flixhub.co/messages"
        sgapi = "5069f7ba06a5c64782bc6c036067adff-4836d8f5-2c8e6a53"
        sbj = "Flixhub account verification"
        efrom = "Flixhub Support <no-replay@flixhub.co>"
        return requests.post(uri, auth=("api", sgapi),
                             data={"from": efrom, "to": ["" + email + ""], "subject": sbj, "html": "" + htpl + ""})


def forgot_password_email(email):
    items = dbweb.users.find_one({"email": email})
    if items:
        htpl = render_template('backend/email/forgot-password.html', items=items, host_url=host_url)
        uri = "https://api.mailgun.net/v3/mx.flixhub.co/messages"
        sgapi = "5069f7ba06a5c64782bc6c036067adff-4836d8f5-2c8e6a53"
        sbj = "Flixhub password reset request"
        efrom = "Flixhub Support <no-replay@flixhub.co>"
        return requests.post(uri, auth=("api", sgapi),
                             data={"from": efrom, "to": ["" + email + ""], "subject": sbj, "html": "" + htpl + ""})


def chk_type(slug, page):
    offset_page = (page - 1) * int(per_page)
    if slug == 'all':
        return dbweb.items.find().sort('data_id', -1).skip(offset_page).limit(per_page)
    elif slug == 'series':
        return dbweb.items.find({"type": 'series'}).sort('data_id', -1).skip(offset_page).limit(per_page)
    elif slug == 'movies':
        return dbweb.items.find({"type": 'movies'}).sort('data_id', -1).skip(offset_page).limit(per_page)
    else:
        return


def related(slug):
    items = dbweb.items.find_one({"slug": slug}, {'_id': False})
    if items:
        badkey = ["Season"]
        akey = [item for item in items['title'].split() if not (len(item) <= 3 or item.isdigit() or item in badkey)]
        bkey = [item['name'] for item in items['actors']]
        ckey = [item['slug'] for item in items['keyword']]
        relate = dbweb.items.find({
            "slug": {"$ne": slug},
            "$or": [{"title": {"$regex": '|'.join(akey), "$options": "i"}},
                    {"actors.name": {"$regex": '|'.join(bkey), "$options": "i"}},
                    {"keyword.slug": {"$regex": '|'.join(ckey), "$options": "i"}}]
        }).limit(12)
        return relate


def get_sitemap(data):
    fname = "static/"+str(data)+"-sitemap.xml"
    uri = 'https://cdn.123movies.fun/'+str(data)+'-sitemap.xml'
    req = requests.get(uri, allow_redirects=True)
    if 'application/xml' in req.headers['Content-Type']:
        os.makedirs(os.path.dirname(fname), exist_ok=True)
        open(fname, 'wb').write(req.content)
        return data
    else:
        return
