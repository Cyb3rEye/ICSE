import os
import threading
import subprocess
import time
from flask import Flask, request, render_template

# START DB SETUP #
import sqlite3

dbfile = 'lVulns.db'

db = sqlite3.connect(dbfile, check_same_thread=False)
db.row_factory = sqlite3.Row
cur = db.cursor()
def query(query): # Use for SELECT operators
    result = db.cursor().execute(query).fetchone()[0]
    return result

def mquery(query, args=(), one=False): #Mass Query, collect all rows
    cur = db.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# END DB SETUP #

# START READING VULNS #
global rows
rows = mquery('SELECT * FROM vulns')
# END READING VULNS #

# START SCORING ENGINE SETUP #
def scoringEngine():
    ttr = 10 # Time to Repeat (Seconds)
    vulnr =  mquery('SELECT * FROM vulns WHERE eval = 0')
    evalr = mquery('SELECT * FROM vulns WHERE eval = 1')
    while True:
        for row in vulnr:
            cmdout = subprocess.check_output(row['command'], shell=True)
            if str(cmdout.strip('\n')) == str(row['expectedvalue']):
                cur.execute('UPDATE vulns SET point = 1 WHERE id=?', (str(row['id'])))
                db.commit()
            else:
                cur.execute('UPDATE vulns SET point = 0 WHERE id=?', (str(row['id'])))
                db.commit()
        for row in evalr:
            if str(eval(row['command'])).strip('\n') == str(row['expectedvalue']):
                cur.execute('UPDATE vulns SET point = 1 WHERE id=?', (str(row['id'])))
                db.commit()
            else:
                cur.execute('UPDATE vulns SET point = 0 WHERE id=?',(str(row['id'])))
                db.commit()
        time.sleep(ttr)
scoreService = threading.Thread(target=scoringEngine)
scoreService.daemon = True
# END SCORING ENGINE SETUP #

# START FLASK SETUP #
webapp = Flask(__name__,template_folder='web')
@webapp.route('/')
def index():
    amtvulns = query('SELECT count(*) FROM vulns')
    maxscore = query('SELECT sum(pointvalue) FROM vulns')
    currentscore = query('SELECT sum(pointvalue) FROM vulns WHERE point = 1')
    amtfoundvulns = query('SELECT sum(point) FROM vulns')
    foundvulns = mquery('SELECT * FROM vulns WHERE point = 1')
    content = {'numvuln':amtvulns,
            'mxscore':maxscore,
            'cscore':currentscore,
            'amtfound':amtfoundvulns,
            'fvulns':foundvulns}
    return render_template('index.html', **content)
scoreService.start()
webapp.run()
time.sleep(5)
print 'STOPPING'
db.close()
