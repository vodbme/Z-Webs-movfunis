import json
import re
from datetime import datetime, timezone

import flask_login
from flask import Flask, render_template, abort, request, Response, redirect, url_for, flash, jsonify, session
from flask_assets import Environment
from flask_caching import Cache
from htmlmin.minify import html_minify

import modul as md

SESSION_COOKIE_SECURE = True
app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = md.enkey
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
assets = Environment(app)
cache = Cache(app, config={'CACHE_TYPE': 'filesystem', 'CACHE_DIR': 'fcache'})
cache1 = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_HOST': 'rds.vodb.ch',
    'CACHE_REDIS_PORT': 6379,
    'CACHE_REDIS_PASSWORD': md.enkey,
    'CACHE_REDIS_DB': 0
})


def user_sess():
    data = str(request.headers.get('User-Agent') + '-' + str(md.utcnow('%Y%m%d%H%M')) + '-' + str(md.user_ip()))
    ekey = str(md.hmacenc((data + md.enkey).encode()))
    return ekey


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(uname):
    # users = md.dblog.members.find_one({"uname": uname})
    users = None
    if users is None:
        return
    user = User()
    user.id = uname
    user.fname = ''
    user.email = ''
    user.lslog = ''
    user.active = ''
    return user


@login_manager.request_loader
def request_loader(request):
    uname = request.form.get('username')
    users = md.dblog.members.find_one({"uname": uname})
    if users is None:
        return
    user = User()
    user.id = uname
    if user.is_authenticated is request.form['password'] == users['password']:
        return user
    else:
        return


@login_manager.unauthorized_handler
def unauthorized_handler():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not flask_login.current_user.is_authenticated:
        if request.method == 'GET':
            return render_template('users/login.html', gsite=md.gsite)
        elif request.method == 'POST':
            uname = request.form['username']
            passw = request.form['password']
            if not uname or not passw:
                flash('Are you robot?', 'alert-danger')
                return '{"status":"false","url":"' + url_for('login') + '"}'
            users = md.dblog.members.find_one({"uname": uname})
            if users and uname == users['uname'] and passw == users['passw']:
                if users['active'] != 1:
                    flash('Account not active, please activate first.', 'alert-danger')
                    return '{"status":"false","url":"' + url_for('login') + '"}'
                user = User()
                user.id = uname
                flask_login.login_user(user)
                uag = request.user_agent.string
                md.dblog.logins.insert_one({"uname": uname, "uip": md.user_ip(), "time": md.ts_now(), "uag": uag})
                return '{"status":"true","url":"' + url_for('page_home') + '"}'
            err = json.dumps({"status": False, "message": "Username or Password is invalid."})
            return Response(response=err, status=404, mimetype="application/json")
        else:
            err = json.dumps({"status": False, "message": "Username or Password is invalid."})
            return Response(response=err, status=404, mimetype="application/json")
    else:
        return redirect(url_for('page_home'))


@app.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return redirect(url_for('page_home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if not flask_login.current_user.is_authenticated:
        if request.method == 'GET':
            return render_template('users/register.html', gsite=md.gsite)
        elif request.method == 'POST':
            fname = request.form['full_name']
            uname = request.form['username']
            email = request.form['email']
            passw = request.form['password']
            cpassw = request.form['confirm_password']
            usern = re.match(r'^[a-z0-9]*$', uname)
            if not fname or not email or not uname or not passw:
                err = json.dumps({"status": False, "message": "Are you robot?"})
                return Response(response=err, status=404, mimetype="application/json")
            if not usern or len(uname) <= 4 or len(uname) >= 15:
                err = json.dumps({"status": False, "message": "Username must be alphanumeric with 5-15 char."})
                return Response(response=err, status=404, mimetype="application/json")
            if passw != cpassw or len(passw) <= 6 or len(passw) >= 20:
                err = json.dumps({"status": False, "message": "Makesure both password match with 6-20 char."})
                return Response(response=err, status=404, mimetype="application/json")
            if 'bad' in md.is_valid_email(email):
                err = json.dumps({"status": False, "message": "Double check your email address."})
                return Response(response=err, status=404, mimetype="application/json")
            users = md.dblog.members.find_one({"uname": uname})
            if users:
                err = json.dumps({"status": False, "message": "Username already exists"})
                return Response(response=err, status=404, mimetype="application/json")
            if not users and usern:
                cmail = md.dblog.members.find_one({"email": email})
                if cmail:
                    err = json.dumps({"status": False, "message": "Email already registered"})
                    return Response(response=err, status=404, mimetype="application/json")
                else:
                    codes = md.hmacenc((uname + str(md.ts_now())).encode('utf-8'))
                    md.dblog.members.insert_one({"active": 1, "uname": uname, "fname": fname, "email": email,
                                                 "passw": passw, "last_log": md.ts_now(), "codes": codes})
                    user = User()
                    user.id = uname
                    flask_login.login_user(user)
                    valid = json.dumps({"status": True, "message": "Account created successfully."})
                    return Response(response=valid, status=200, mimetype="application/json")
            else:
                err = json.dumps({"status": False, "message": "Something wrong, please try again"})
                return Response(response=err, status=404, mimetype="application/json")
        else:
            abort(404)
    else:
        return redirect(url_for('page_home'))


@app.route('/verify/<codes>/', methods=['GET'])
def validate_email(codes):
    if not flask_login.current_user.is_authenticated:
        pcodes = re.match(r'^[A-Za-z0-9]+$', codes)
        if codes and len(codes) > 10 and pcodes:
            vcode = md.dblog.members.find_one({"codes": codes})
            if vcode:
                coder = md.hmacenc((vcode['fname'] + str(md.ts_now())).encode('utf-8'))
                md.dblog.members.update_one({"codes": codes}, {"$set": {"active": "1", "codes": coder}}, upsert=True)
                flash('Hi ' + vcode['fname'] + ', your account now active. Click button bellow to login', 'show')
                return render_template('users/verify.html')
            else:
                flash('Confirmation url invalid or already activated', 'hidden')
                return render_template('users/verify.html')
        else:
            abort(404)
    else:
        return redirect(url_for('page_home'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if not flask_login.current_user.is_authenticated:
        if request.method == 'GET':
            return render_template('users/forgot.html', gsite=md.gsite)
        elif request.method == 'POST':
            email = request.form['email']
            gcaptcha = request.form['g-recaptcha-response']
            if not email or not gcaptcha or not md.check_recaptcha(gcaptcha):
                flash('Are you robot?', 'alert-danger')
                return '{"status":"false","url":"' + url_for('forgot') + '"}'
            users = md.dblog.members.find_one({"email": email})
            if users and email == users['email']:
                md.forgot_password_email(email)
                flash('We send confirmation link to ' + email, 'alert-success')
                return '{"status":"true","url":"' + url_for('forgot') + '"}'
            flash('Email ' + email + ' not found', 'alert-danger')
            return '{"status":"false","url":"' + url_for('forgot') + '"}'
        else:
            abort(404)
    else:
        return redirect(url_for('page_home'))


@app.route('/change-pass/<codes>/', methods=['GET', 'POST'])
def change_pass(codes):
    if not flask_login.current_user.is_authenticated:
        pcodes = re.match(r'^[A-Za-z0-9]+$', codes)
        if request.method == 'GET' and pcodes:
            vcode = md.dblog.members.find_one({"codes": codes})
            if vcode:
                return render_template('users/change-pass.html', gsite=md.gsite, codes=codes)
            else:
                abort(404)
        elif request.method == 'POST' and pcodes:
            passw = request.form['password']
            cpassw = request.form['confirm_password']
            gcaptcha = request.form['g-recaptcha-response']
            if not passw or not cpassw or not gcaptcha or not md.check_recaptcha(gcaptcha):
                flash('Are you robot?', 'alert-danger')
                return '{"status":"false","url":"' + url_for('change_pass', codes=codes) + '"}'
            if passw != cpassw or len(passw) <= 6 or len(passw) >= 20:
                flash('Makesure both password match with 6-20 char.', 'alert-danger')
                return '{"status":"false","url":"' + url_for('change_pass', codes=codes) + '"}'
            vcode = md.dblog.members.find_one({"codes": codes})
            if vcode:
                coder = md.hmacenc((vcode['fname'] + str(md.ts_now())).encode('utf-8'))
                md.dblog.members.update_one({"codes": codes}, {"$set": {"password": passw, "codes": coder}},
                                            upsert=True)
                flash('Hi ' + vcode['fname'] + ', your password changed. You can now login with your new password.',
                      'alert-success')
                return '{"status":"false","url":"' + url_for('login') + '"}'
            else:
                flash('You try change password? but your code invalid!', 'alert-danger')
                return '{"status":"false","url":"' + url_for('login') + '"}'
        else:
            abort(404)
    else:
        return redirect(url_for('page_home'))


def user_type():
    if not session:
        session['utype'] = 'bot'
        return 'bot'
    elif session['utype'] and flask_login.current_user.is_authenticated:
        if session['utype'] != 'member':
            session['utype'] = 'member'
        return 'member'
    else:
        if session['utype'] and session['utype'] != ('member' or 'visitor'):
            session['utype'] = 'visitor'
        return 'visitor'


def cache_key(*args, **kwargs):
    path = request.path
    args = str(hash(frozenset(request.args.items())))
    utype = user_type()
    return (path + args + utype).encode('utf-8')


@cache.cached(timeout=86400, key_prefix='web_conf')
def web_conf():
    conf = md.dbweb.config.find_one({"name": 'global'}, {'_id': False})
    return conf


@cache.cached(timeout=86400, key_prefix='all_genre')
def all_genre():
    genre = md.dbweb.config.find_one({"name": 'genres'}, {'_id': False})
    return genre


@cache.cached(timeout=86400, key_prefix='all_country')
def all_country():
    country = md.dbweb.config.find_one({"name": 'country'}, {'_id': False})
    return country


@app.route('/')
@cache.cached(timeout=3600)
def index_page():
    return render_template('index.html')


@app.route('/home')
@cache.cached(timeout=3600, key_prefix=cache_key)
def page_home():
    l_m = md.dbweb.items.find({"$and": [{"type": "movies"}, {"ban": {"$nin": [1]}}]}, {'_id': False}).sort('data_id', -1).limit(16)
    l_s = md.dbweb.items.find({"$and": [{"type": "series"}, {"ban": {"$nin": [1]}}]}, {'_id': False}).sort('data_id', -1).limit(16)
    ftrd_item = md.dbweb.config.find_one({'type': 'featured'}, {'_id': False})
    ftrd = md.dbweb.items.find({'data_id': {'$in': ftrd_item['mid']}}).sort('data_id', -1).limit(16)
    sld_item = md.dbweb.config.find_one({'type': 'slider'}, {'_id': False})
    sld = md.dbweb.items.find({'data_id': {'$in': sld_item['mid']}}).limit(10)
    news = md.dbweb.articles.find().sort('post_date', -1).limit(10)
    if l_m and l_s:
        html = render_template('pages/home.html', l_m=l_m, l_s=l_s, ftrd=ftrd, sld=sld, news=news)
        return html_minify(html)
    else:
        abort(404)


@app.route('/site/<page>/', methods=['GET'])
@cache.cached(timeout=86400)
def site_page(page):
    if page not in ['dmca', 'faq', 'promote']:
        abort(404)
    items = md.dbweb.pages.find_one({'slug': page}, {'_id': False})
    if not items:
        abort(404)
    if items['type'] == 'site':
        return render_template('site/%s.html' % page, items=items, page=page)
    else:
        abort(404)


@app.route('/search', defaults={'skey': None, 'page': 1}, methods=['POST'])
@app.route('/search/<skey>/', defaults={'page': 1}, methods=['GET'])
@app.route('/search/<skey>/<int:page>/', methods=['GET'])
def searching(skey, page):
    if request.method == 'GET':
        @cache.cached(timeout=86400, key_prefix=str(skey)+str(page))
        def search_get():
            offset_page = (page - 1) * int(md.per_page)
            gitem = md.dbweb.items.find({"title": {"$regex": '.*' + skey.replace('+', ' ') + '.*', "$options": "-i"}}).skip(offset_page).limit(md.per_page)
            tp = gitem.count() // md.per_page + 1
            next_page = page + 1
            prev_page = page - 1
            return render_template('pages/search.html', items=gitem, tp=tp, cp=page, np=next_page, pp=prev_page, ic=gitem.count(), skey=skey)

        return search_get()
    elif request.method == 'POST':
        query = request.form['keyword']

        @cache.cached(timeout=86400, key_prefix=str(query))
        def search_post():
            items = md.dbweb.items.find({"title": {"$regex": query.replace('+', ' '), "$options": "-i"}}).limit(5)
            if items and query:
                resp = render_template('includes/aj-search.html', items=items, query=query)
                dat = json.dumps({"status": True, "html": resp})
                return Response(response=dat, status=200, mimetype="application/json")
            else:
                dat = json.dumps({"status": False, "html": ""})
                return Response(response=dat, status=404, mimetype="application/json")

        return search_post()
    else:
        abort(404)


@app.route('/filter', defaults={'page': 1}, methods=['GET'])
@app.route('/filter/<int:page>', methods=['GET'])
@cache.cached(timeout=86400, key_prefix=cache_key)
def filter_list(page):
    offset_page = (page - 1) * int(md.per_page)
    n_pg = page + 1
    p_pg = page - 1
    genre = request.args.get("genre")
    country = request.args.get("country")
    types = request.args.get("types")
    year = request.args.get("year")
    if genre == "all" or genre is None:
        f_genre = {'$ne': ["all"]}
    else:
        f_genre = {'$in': genre.split(",")}
    if country == "all" or country is None:
        f_country = {'$ne': ["all"]}
    else:
        f_country = {'$in': country.split(",")}
    if types == "all" or types is None:
        f_types = {'$ne': ["all"]}
    else:
        f_types = {'$in': types.split(",")}
    if year and year.isdigit():
        f_year = int(year)
    else:
        f_year = {'$ne': year}
    data = {"type": f_types, "year": f_year, "country.slug": f_country, "genre.slug": f_genre}
    items = md.dbweb.items.find(data).sort('data_id', -1).skip(offset_page).limit(md.per_page)
    if items:
        tp = items.count() // md.per_page + 1
        if 0 <= page <= tp:
            return render_template('pages/filter.html', items=items, tp=tp, cp=page, np=n_pg, pp=p_pg, genre=genre, country=country, types=types, year=year)
        else:
            abort(404)
    else:
        abort(404)


@app.route('/movie/filter/<slug>/', defaults={'page': 1}, methods=['GET'])
@app.route('/movie/filter/<slug>/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def film_list(slug, page):
    np = page + 1
    pp = page - 1
    if slug not in ['all', 'series', 'movies'] or not page:
        abort(404)
    items = md.chk_type(slug, page)
    if items:
        tp = items.count() // md.per_page + 1
        if 0 <= page <= tp:
            html = render_template('pages/film-list.html', items=items, tp=tp, cp=page, np=np, pp=pp, slug=slug)
            return html_minify(html)
        else:
            abort(404)
    else:
        abort(404)


@app.route('/film/<slug>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def film_page(slug):
    items = md.dbweb.items.find_one({"$and": [{"slug": slug}, {"ban": {"$nin": [1]}}]}, {'_id': False})
    if items:
        rate = md.dblog.ratings.find_one({"data_id": items['data_id']}, {'_id': False})
        html = render_template('pages/film-single.html', items=items, related=md.related(slug), slug=slug, rate=rate)
        return html_minify(html)
    else:
        abort(404)


@app.route('/film/<slug>/watching.html', methods=['GET'])
def film_watch(slug):
    items = md.dbweb.items.find_one({"$and": [{"slug": slug}, {"ban": {"$nin": [1]}}]}, {'_id': False})
    if items:
        vids = md.dbweb.videos.find_one({'data_id': items['data_id']}, {'_id': False})
        if not vids:
            abort(404)
        html = render_template('pages/film-watch.html', items=items, related=md.related(slug), vids=vids)
        return html_minify(html)
    else:
        abort(404)


@app.route('/genre/<slug>/', defaults={'page': 1}, methods=['GET'])
@app.route('/genre/<slug>/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def genre_list(slug, page):
    offset_page = (page - 1) * int(md.per_page)
    items = md.dbweb.items.find({"$and": [{"genre.slug": str(slug)}, {"ban": {"$nin": [1]}}]}, {'_id': False}
                                ).sort('data_id', -1).skip(offset_page).limit(md.per_page)
    ic = items.count()
    tp = ic // md.per_page + 1
    np = page + 1
    pp = page - 1
    if ic >= 1 and (0 <= page <= tp):
        html = render_template('pages/genre.html', items=items, tp=tp, cp=page, np=np, pp=pp, slug=slug)
        return html_minify(html)
    else:
        abort(404)


@app.route('/country/<slug>/', defaults={'page': 1}, methods=['GET'])
@app.route('/country/<slug>/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def country_list(slug, page):
    offset_page = (page - 1) * int(md.per_page)
    items = md.dbweb.items.find({"$and": [{"country.slug": str(slug)}, {"ban": {"$nin": [1]}}]}, {'_id': False}
                                ).sort('data_id', -1).skip(offset_page).limit(md.per_page)
    ic = items.count()
    tp = ic // md.per_page + 1
    np = page + 1
    pp = page - 1
    if ic >= 1 and (0 <= page <= tp):
        html = render_template('pages/country.html', items=items, tp=tp, cp=page, np=np, pp=pp, slug=slug)
        return html_minify(html)
    else:
        abort(404)


@app.route('/movie/top-imdb/', defaults={'page': 1}, methods=['GET'])
@app.route('/movie/top-imdb/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def top_imdb(page):
    offset_page = (page - 1) * int(md.per_page)
    next_page = page + 1
    prev_page = page - 1
    items = md.dbweb.items.find({"ban": {"$nin": [1]}}).sort('imdb_star', -1).skip(offset_page).limit(md.per_page)
    if items:
        tp = items.count() // md.per_page + 1
        html = render_template('pages/top-imdb.html', items=items, tp=tp, cp=page, np=next_page, pp=prev_page)
        return html_minify(html)
    else:
        abort(404)


@app.route('/movies/library/', defaults={'libs': '0-9', 'page': 1})
@app.route('/movies/library/<libs>/', defaults={'page': 1})
@app.route('/movies/library/<libs>/<int:page>/')
@cache.cached(timeout=3600, key_prefix=cache_key)
def az_list(libs, page):
    offset_page = (page - 1) * int(md.per_page)
    if libs == '0-9':
        items = md.dbweb.items.find({"title": {"$regex": '^\d', "$options": "i"}}, {'_id': False}).sort(
            'title', 1).skip(offset_page).limit(md.per_page)
    else:
        items = md.dbweb.items.find({"title": {"$regex": '^' + libs + '.*', "$options": "i"}}, {'_id': False}).sort(
            'title', 1).skip(offset_page).limit(md.per_page)
    ti = items.count()
    tp = ti // md.per_page + 1
    np = page + 1
    pp = page - 1
    if ti < 1:
        abort(404)
    html = render_template('pages/az-list.html', items=items, tp=tp, cp=page, np=np, pp=pp, libs=libs, ti=ti,
                           per_p=md.per_page)
    return html_minify(html)


@app.route('/actor/<slug>/', defaults={'page': 1}, methods=['GET'])
@app.route('/actor/<slug>/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def actor_list(slug, page):
    offset_page = (page - 1) * int(md.per_page)
    items = md.dbweb.items.find({"$and": [{"actors.slug": str(slug)}, {"ban": {"$nin": [1]}}]}, {'_id': False}
                                ).sort('data_id', -1).skip(offset_page).limit(md.per_page)
    ic = items.count()
    tp = ic // md.per_page + 1
    np = page + 1
    pp = page - 1
    if ic >= 1 and (0 <= page <= tp):
        html = render_template('pages/actor.html', items=items, tp=tp, cp=page, np=np, pp=pp, slug=slug)
        return html_minify(html)
    else:
        abort(404)


@app.route('/director/<slug>/', defaults={'page': 1}, methods=['GET'])
@app.route('/director/<slug>/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def director_list(slug, page):
    offset_page = (page - 1) * int(md.per_page)
    items = md.dbweb.items.find({"$and": [{"director.slug": str(slug)}, {"ban": {"$nin": [1]}}]}, {'_id': False}
                                ).sort('data_id', -1).skip(offset_page).limit(md.per_page)
    ic = items.count()
    tp = ic // md.per_page + 1
    np = page + 1
    pp = page - 1
    if ic >= 1 and (0 <= page <= tp):
        html = render_template('pages/director.html', items=items, tp=tp, cp=page, np=np, pp=pp, slug=slug)
        return html_minify(html)
    else:
        abort(404)


@app.route('/tags/<slug>/', defaults={'page': 1}, methods=['GET'])
@app.route('/tags/<slug>/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def tags_list(slug, page):
    offset_page = (page - 1) * int(md.per_page)
    items = md.dbweb.items.find({"$and": [{"keyword.slug": str(slug)}, {"ban": {"$nin": [1]}}]}, {'_id': False}
                                ).sort('data_id', -1).skip(offset_page).limit(md.per_page)
    ic = items.count()
    tp = ic // md.per_page + 1
    np = page + 1
    pp = page - 1
    if ic >= 1 and (0 <= page <= tp):
        html = render_template('pages/tags.html', items=items, tp=tp, cp=page, np=np, pp=pp, slug=slug)
        return html_minify(html)
    else:
        abort(404)


@app.route('/release/<int:slug>/', defaults={'page': 1}, methods=['GET'])
@app.route('/release/<int:slug>/<int:page>/', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=cache_key)
def release_list(slug, page):
    offset_page = (page - 1) * int(md.per_page)
    items = md.dbweb.items.find({"$and": [{"year": int(slug)}, {"ban": {"$nin": [1]}}]}, {'_id': False}
                                ).sort('data_id', -1).skip(offset_page).limit(md.per_page)
    ic = items.count()
    tp = ic // md.per_page + 1
    np = page + 1
    pp = page - 1
    if ic >= 1 and (0 <= page <= tp):
        html = render_template('pages/release.html', items=items, tp=tp, cp=page, np=np, pp=pp, slug=slug)
        return html_minify(html)
    else:
        abort(404)


@app.route('/articles/news/', defaults={'page': 1})
@app.route('/articles/news/<int:page>/')
@cache.cached(timeout=86400, key_prefix=cache_key)
def articles(page):
    i_page = 20
    offset_page = (page - 1) * int(i_page)
    items = md.dbweb.articles.find().sort('post_date', -1).skip(offset_page).limit(i_page)
    hot_ar = md.dbweb.articles.find().sort('view', -1).limit(5)
    tp = items.count() // i_page + 1
    np = page + 1
    pp = page - 1
    if not items:
        abort(404)
    html = render_template('pages/news.html', items=items, hot_ar=hot_ar, tp=tp, cp=page, np=np, pp=pp)
    return html_minify(html)


@app.route('/articles/view/<slug>/')
@cache.cached(timeout=86400, key_prefix=cache_key)
def articles_view(slug):
    items = md.dbweb.articles.find_one({"slug": slug}, {'_id': False})
    hot_ar = md.dbweb.articles.find().sort('view', -1).limit(5)
    if not items:
        abort(404)
    return render_template('pages/articles.html', items=items, hot_ar=hot_ar)


@app.route('/user/profile/', methods=['GET'])
@flask_login.login_required
def user_profile():
    html = render_template('users/profile.html')
    return html_minify(html)


@app.route('/user/favorite/', defaults={'page': 1}, methods=['GET'])
@app.route('/user/favorite/<int:page>/', methods=['GET'])
@flask_login.login_required
def user_favorite(page):
    offset_page = (page - 1) * int(md.per_page)
    next_page = page + 1
    prev_page = page - 1
    uname = flask_login.current_user.id
    lst_fav = md.dblog.favorites.find_one({'uname': uname}, {'_id': False})
    if not lst_fav:
        html = render_template('users/favorite.html')
        return html_minify(html)
    items = md.dbweb.items.find({'data_id': {'$in': lst_fav['data_id']}}).skip(offset_page).limit(md.per_page)
    if lst_fav and items:
        tp = items.count() // md.per_page + 1
        if 0 <= page <= tp:
            html = render_template('users/favorite.html', items=items, tp=tp, cp=page, np=next_page, pp=prev_page)
            return html_minify(html)
        else:
            abort(404)
    else:
        abort(404)


@app.route('/ajax/home-suggest/<slug>', methods=['GET'])
@cache.cached(timeout=86400, key_prefix=cache_key)
def home_suggest(slug):
    if slug == 'top-view':
        tv = md.dbweb.items.find().sort('views', -1).limit(16)
        list_item = []
        for item in tv:
            html = render_template('includes/home-suggest.html', item=item)
            list_item.append(html)
        return jsonify({"status": True, "message": "Success", "content": list_item, "type": slug})
    elif slug == 'top-favorite':
        mf = md.dbweb.items.find().sort('likes', -1).limit(16)
        list_item = []
        for item in mf:
            html = render_template('includes/home-suggest.html', item=item)
            list_item.append(html)
        return jsonify({"status": True, "message": "Success", "content": list_item, "type": slug})
    elif slug == 'top-rating':
        tr = md.dbweb.items.find().sort('ratings', -1).limit(16)
        list_item = []
        for item in tr:
            html = render_template('includes/home-suggest.html', item=item)
            list_item.append(html)
        return jsonify({"status": True, "message": "Success", "content": list_item, "type": slug})
    else:
        doc = json.dumps({'status': False, 'content': ''})
        return Response(response=doc, status=404, mimetype="application/json")


@app.route('/ajax/info/<mid>', methods=['GET'])
@cache.cached(timeout=86400)
def film_info(mid):
    items = md.dbweb.items.find_one({'data_id': int(mid)}, {'_id': False})
    if items:
        html = render_template('includes/aj-info.html', items=items)
        return html_minify(html)
    else:
        return "none"


@app.route('/ajax/data/<mid>', methods=['GET'])
@cache.cached(timeout=86400)
def list_ep(mid):
    if not mid or not mid.isdigit():
        doc = json.dumps({'status': 'false', 'html': ''})
        return Response(response=doc, status=404, mimetype="application/json")
    items = md.dbweb.videos.find_one({'data_id': int(mid)}, {'_id': False})
    if items:
        html = render_template('includes/srv-list.html', items=items)
        data = json.dumps({"status": True, "html": html})
        return Response(response=data, status=200, mimetype="application/json")
    else:
        doc = json.dumps({'status': False, 'html': ''})
        return Response(response=doc, status=404, mimetype="application/json")


@app.route('/ajax/source', methods=['POST'])
def mov_sources():
    mid = request.form["mid"]
    eid = request.form["eid"]
    srv = request.form["srv"]
    if not mid or not mid.isdigit() or not eid or not eid.isdigit() or srv not in ["1", "2", "3"]:
        doc = json.dumps({'status': False, 'sources': ''})
        return Response(response=doc, status=404, mimetype="application/json")
    items = md.dbweb.items.find_one({'data_id': int(mid)}, {'_id': False})
    if items:
        usr_ses = user_sess()
        if not cache1.get(usr_ses) or cache1.get(usr_ses) != '1':
            cache1.set(usr_ses, '1', 360)
        session['ses'] = usr_ses
        session.modified = True
        tmz = md.utcnow('%Y%m%d%H%M%S')
        data = json.dumps({"m": str(mid), "e": str(eid), "s": str(srv), "t": str(tmz)})
        ikey = md.encrypt((str(data)).encode())
        vido = str(md.strm_uri) + "/watch?v=" + str(ikey.decode())
        doc = json.dumps({'status': True, 'src': vido})
        return Response(response=doc, status=200, mimetype="application/json")
    else:
        doc = json.dumps({'status': False, 'sources': ''})
        return Response(response=doc, status=404, mimetype="application/json")


@app.route('/ajax/rating', methods=['POST'])
def ajax_user_rating():
    if not flask_login.current_user.is_authenticated:
        staterr = json.dumps({"status": False, "message": "You must login to rate this movie"})
        return Response(response=staterr, status=404, mimetype="application/json")
    else:
        mid = request.form['mid']
        act = request.form['act']
        if not mid or not mid.isdigit() or not act or not act.isdigit():
            staterr = json.dumps({"status": False, "message": "error"})
            return Response(response=staterr, status=404, mimetype="application/json")
        items = md.dbweb.items.find_one({"data_id": int(mid)}, {'_id': False})
        if not items:
            staterr = json.dumps({"status": False, "message": "error"})
            return Response(response=staterr, status=404, mimetype="application/json")
        stat = json.dumps({"status": True, "message": "Thanks for your rating."})
        uname = flask_login.current_user.id
        star_log = md.dblog.ratings.find_one({'uname': uname}, {'_id': False})
        if star_log and int(mid) in star_log['data_id']:
            staterr = json.dumps({"status": False, "message": "You already rate this movie"})
            return Response(response=staterr, status=404, mimetype="application/json")
        md.dblog.ratings.update_one({"uname": uname}, {"$addToSet": {"data_id": {"$each": [int(mid)]}}}, upsert=True)
        md.dbweb.items.find_one_and_update({"data_id": int(mid)}, {"$inc": {"ratings": int(act), "votes": 1}},
                                           upsert=True)
        return Response(response=stat, status=200, mimetype="application/json")


@app.route('/ajax/favorite', methods=['POST'])
def ajax_user_favorite():
    if not flask_login.current_user.is_authenticated:
        staterr = json.dumps({"status": False, "message": "You must login first."})
        return Response(response=staterr, status=404, mimetype="application/json")
    else:
        mid = request.form['mid']
        act = request.form['act']
        if not mid and not mid.isdigit() or not act:
            staterr = json.dumps({"status": False, "message": "error"})
            return Response(response=staterr, status=404, mimetype="application/json")
        items = md.dbweb.items.find_one({"data_id": int(mid)}, {'_id': False})
        if not items:
            abort(404)
        data = '<b>' + items['title'] + '</b> has been ' + act + ' to your favorite list.'
        stat = json.dumps({"status": True, "message": data})
        uname = flask_login.current_user.id
        if act == "added":
            md.dblog.favorites.update_one({"uname": uname}, {"$addToSet": {"data_id": {"$each": [int(mid)]}}},
                                          upsert=True)
        elif act == "removed":
            md.dblog.favorites.update_one({"uname": uname}, {"$pull": {"data_id": int(mid)}}, upsert=True)
        else:
            pass
        return Response(response=stat, status=200, mimetype="application/json")


@app.route('/ajax/report', methods=['POST'])
def ajax_report():
    if not flask_login.current_user.is_authenticated:
        staterr = json.dumps({"status": False, "message": "You must login to report this movie"})
        return Response(response=staterr, status=404, mimetype="application/json")
    else:
        issu = request.form.getlist('issue[]')
        msg = request.form['message']
        mid = request.form['movie_id']
        if not mid or not mid.isdigit() or not issu:
            staterr = json.dumps({"status": False, "message": "Please select any issues."})
            return Response(response=staterr, status=404, mimetype="application/json")
        stat = json.dumps({"status": True, "message": "Thanks for reporting. We will check and fix it soon."})
        uname = flask_login.current_user.id
        md.dblog.issues.insert_one({"uname": uname, "mid": mid, "issu": issu, "msg": msg})
        return Response(response=stat, status=200, mimetype="application/json")


@app.errorhandler(400)
def bad_request(err):
    if request.method == 'POST':
        err = json.dumps({"status": False, "message": "Something wrong, please try again"})
        return Response(response=err, status=400, mimetype="application/json")
    else:
        html = html_minify(render_template('errors/400.html', err=err))
        return Response(response=html, status=400, mimetype="text/html")


@app.errorhandler(404)
def page_not_found(err):
    if request.method == 'POST':
        err = json.dumps({"status": False, "message": "Something wrong, please try again"})
        return Response(response=err, status=404, mimetype="application/json")
    else:
        html = html_minify(render_template('errors/404.html', err=err))
        return Response(response=html, status=404, mimetype="text/html")


@app.errorhandler(403)
def page_forbidden(err):
    if request.method == 'POST':
        err = json.dumps({"status": False, "message": err})
        return Response(response=err, status=403, mimetype="application/json")
    else:
        return render_template('errors/403.html', err=err), 403


@app.errorhandler(429)
def ratelimit_handler(err):
    if request.method == 'POST':
        err = json.dumps({"status": False, "message": "Please slow down or we will ban you!"})
        return Response(response=err, status=429, mimetype="application/json")
    else:
        html = html_minify(render_template('errors/429.html', err=err))
        return Response(response=html, status=429, mimetype="text/html")


@app.errorhandler(500)
def internal_server_error(err):
    if request.method == 'POST':
        err = json.dumps({"status": False, "message": "Internal Server Error"})
        return Response(response=err, status=500, mimetype="application/json")
    else:
        html = html_minify(render_template('errors/500.html', err=err))
        return Response(response=html, status=500, mimetype="text/html")


@app.errorhandler(503)
def app_error(err):
    return render_template('errors/503.html', err=err), 503


@app.route('/sitemap.xml')
@cache.cached(timeout=86400, key_prefix=cache_key)
def sitemap():
    timer = datetime.utcnow().replace(microsecond=0, tzinfo=timezone.utc).isoformat()
    xml = render_template('sitemap/sitemap.xml', time=timer)
    return Response(response=xml, status=200, mimetype="application/xml")


@app.route('/<data>-sitemap.xml')
@cache.cached(timeout=86400)
def sitemap_data(data):
    timer = datetime.utcnow().replace(microsecond=0, tzinfo=timezone.utc).isoformat()
    if data == 'post':
        items = md.dbweb.items.find()
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'news':
        items = md.dbweb.articles.find().sort('post_date', -1)
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'page':
        items = md.dbweb.pages.find()
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'genre':
        items = all_genre()
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'country':
        items = all_country()
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'actor':
        items = md.dbweb.items.distinct("actors")
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'director':
        items = md.dbweb.items.distinct("director")
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'tag':
        items = md.dbweb.items.distinct("keyword")
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'release':
        items = md.dbweb.items.distinct("year")
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=sorted(items))
        return Response(response=xml, status=200, mimetype="application/xml")
    elif data == 'video':
        items = md.dbweb.items.find()
        xml = render_template('sitemap/%s-sitemap.xml' % data, time=timer, items=items)
        return Response(response=xml, status=200, mimetype="application/xml")
    else:
        abort(404)


@app.route('/watch-5s/', methods=['GET'])
@cache.cached(timeout=86400, key_prefix=cache_key)
def watch_5s():
    data = md.dbweb.pages.find_one({'slug': 'watch-5s'}, {'_id': False})
    if not data:
        abort(404)
    items = md.dbweb.items.find({'data_id': {'$in': data['mid']}}).limit(32)
    html = render_template('pages/special.html', items=items, data=data)
    return html_minify(html)


@app.route('/watch-free/', methods=['GET'])
@cache.cached(timeout=86400, key_prefix=cache_key)
def watch_free():
    data = md.dbweb.pages.find_one({'slug': 'watch-free'}, {'_id': False})
    if not data:
        abort(404)
    items = md.dbweb.items.find({'data_id': {'$in': data['mid']}}).limit(32)
    html = render_template('pages/special.html', items=items, data=data)
    return html_minify(html)


@app.route('/fmovies-se/', methods=['GET'])
@cache.cached(timeout=86400, key_prefix=cache_key)
def fmovies_se():
    data = md.dbweb.pages.find_one({'slug': 'fmovies-se'}, {'_id': False})
    if not data:
        abort(404)
    items = md.dbweb.items.find({'data_id': {'$in': data['mid']}}).limit(32)
    html = render_template('pages/special.html', items=items, data=data)
    return html_minify(html)


@app.route('/go-movies/', methods=['GET'])
@cache.cached(timeout=86400, key_prefix=cache_key)
def go_movies():
    data = md.dbweb.pages.find_one({'slug': 'go-movies'}, {'_id': False})
    if not data:
        abort(404)
    items = md.dbweb.items.find({'data_id': {'$in': data['mid']}}).limit(32)
    html = render_template('pages/special.html', items=items, data=data)
    return html_minify(html)


@app.route('/stream-hd/<slug>', methods=['GET'])
@cache.cached(timeout=86400)
def stream_ads(slug):
    data = 'https://bj1110.online/zFS4gPV20Hk2lJ0BGtOpHiJ-E665hl9FG5MndDsflre_WayOb_3D9Whx0MLJBfkiyy-kImw?cp.title='+str(slug)
    return redirect(data)


@app.route('/download/<slug>', methods=['GET'])
@cache.cached(timeout=86400)
def download_ads(slug):
    data = 'https://bj1110.online/zo8FUmqPcq1uSzhv8TuVDX5gTEWeZkoG-PMdFGTAvuu93gsgmG6pUDg6Rhlan_CbqvZJSFw?cp.title='+str(slug)
    return redirect(data)


@app.route('/home/', methods=['GET'])
@cache.cached(timeout=86400)
def home_old():
    return redirect(url_for('page_home'))



@app.context_processor
def set_config():
    wc = web_conf()
    ag = all_genre()
    ac = all_country()
    now = datetime.utcnow()
    return dict(web_conf=wc, all_genre=ag, all_country=ac, gsite=md.gsite, host_uri=md.host_url, now=now)


if __name__ == '__main__':
    app.run(threaded=True)
