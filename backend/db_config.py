import os
import pymysql

def get_connection():
    return pymysql.connect(
        host=os.environ.get('DB_HOST'),
        port=int(os.environ.get('DB_PORT', 13629)),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASSWORD'),
        database=os.environ.get('DB_NAME'),
        ssl_disabled=False,
        connect_timeout=10,
        cursorclass=pymysql.cursors.DictCursor
    )