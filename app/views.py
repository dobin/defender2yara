from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from typing import List, Tuple
from defender2yara.defender.dbthreat import db, DbThreat
import urllib.parse
import pickle

views = Blueprint('views', __name__)
logger = logging.getLogger("Views")


@views.route("/")
def index():
    return render_template('index.html')
    

@views.route("/threat")
def get_threat():
    threat_name = request.args.get('name', '').strip()
    if not threat_name:
        return redirect(url_for('views.index'))
    
    print("Searching for threat:", threat_name)
    dbThreat = DbThreat.get(DbThreat.name == threat_name)
    threat = pickle.loads(dbThreat.threatObject)
    
    return render_template('threat.html', threat=threat)


@views.route("/search/<threat_name>")
def search_threat(threat_name: str):

    if not threat_name:
        return redirect(url_for('views.index'))
    
    print("Searching for threat:", threat_name)
    dbThreats = DbThreat.select().where(DbThreat.name.contains(threat_name))
    print("Found", len(dbThreats), "threats in the database.")
    
    return render_template('threats.html', threats=dbThreats, threat_name=threat_name)


@views.app_template_filter('urlencode')
def urlencode_filter(s):
    if isinstance(s, str):
        return urllib.parse.quote_plus(s)
    return s
