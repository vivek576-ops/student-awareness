import pymysql
import os

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'sql12.freesqldatabase.com'),
    'user': os.environ.get('DB_USER', 'sql12829118'),
    'password': os.environ.get('DB_PASSWORD', '3BRxxtucEu'),
    'database': os.environ.get('DB_NAME', 'sql12829118'),
    'cursorclass': pymysql.cursors.DictCursor
}

def get_connection():
    return pymysql.connect(**DB_CONFIG)