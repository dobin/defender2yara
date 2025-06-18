from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from typing import List, Tuple
from defender2yara.defender.dbthreat import db, DbThreat
import urllib.parse
import pickle
from defender2yara.util.utils import hexdump_s

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
    
    print("Showing threat:", threat_name, flush=True)
    dbThreat = DbThreat.get(DbThreat.name == threat_name)
    threat = pickle.loads(dbThreat.threatObject)

    skip_signatures = [
        "HSTR_EXT_SIGS",
        "SIGNATURE_TYPE_PEHSTR",
        "SIGNATURE_TYPE_THREAT_BEGIN",
        "SIGNATURE_TYPE_THREAT_END",
        "SIGNATURE_TYPE_LUASTANDALONE",
        "SIGNATURE_TYPE_REVOKED_CERTIFICATE"
    ]

    sigs = []
    threat.revoked_certs = []
    for sig in threat.signatures:
        # more parsing
        if sig.sig_type == "SIGNATURE_TYPE_REVOKED_CERTIFICATE":
            threat.revoked_certs.append(sig.sig_data[3:23].hex())
            continue

        if sig.sig_type in skip_signatures or "HSTR_EXT" in sig.sig_type: 
            continue

        s = ""
        s += "{} {} {}\n".format(sig.sig_type_id, sig.sig_type, sig.size)
        s += hexdump_s(sig.sig_data)
        sigs.append(s)
    
    return render_template('threat.html', threat=threat, signatures=sigs)


@views.route("/search")
def search_threat():
    threat_name = request.args.get('threat_name', '').strip()
    if not threat_name:
        return redirect(url_for('views.index'))
    
    print("Searching for threat:", threat_name)
    dbThreats = DbThreat.select().where(DbThreat.name.contains(threat_name))
    print("Found", len(dbThreats), "threats in the database.", flush=True)
    
    return render_template('threats.html', threats=dbThreats, threat_name=threat_name)


@views.app_template_filter('urlencode')
def urlencode_filter(s):
    if isinstance(s, str):
        return urllib.parse.quote_plus(s)
    return s

@views.app_template_filter('hexencode')
def hexencode_filter(s):
    if isinstance(s, str):
        return hexdump_s(s)
    return s

@views.app_template_filter('bytes_to_str')
def bytes_to_str(s: bytes) -> str:
    if isinstance(s, bytes):
        return s.decode('utf-8', errors='replace')
    return str(s)

