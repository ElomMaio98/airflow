from __future__ import annotations
import pendulum
from airflow.models.dag import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.postgres.hooks.postgres import PostgresHook
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus
from pymongo import MongoClient
import psycopg2
from bson import ObjectId


load_dotenv()

def connect_to_mongo():
    env = os.getenv('ENVIRONMENT', 'PRD')
    database_name = os.getenv('MONGO_DB_NAME')

    if env == 'PRD':
        username = quote_plus(os.getenv('MONGO_USER_NAME'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        host = os.getenv('MONGO_URL')
        port = os.getenv('MONGO_PORT')
        if not all([username, password, host, port, database_name]):
            raise ValueError("Credenciais de produção do MongoDB não estão completamente definidas.")
        return f"mongodb://{username}:{password}@{host}:{port}/{database_name}"
    else: # DEV (Atlas)
        username = quote_plus(os.getenv('MONGO_USER_NAME'))
        password = quote_plus(os.getenv('MONGO_PASSWORD'))
        cluster_name = os.getenv('MONGO_CLUSTER_NAME')
        prefix = os.getenv('MONGO_PREFIX')
        if not all([username, password, cluster_name, prefix, database_name]):
            raise ValueError("Credenciais de desenvolvimento do MongoDB não estão completamente definidas.")
        return f"mongodb+srv://{username}:{password}@{cluster_name}.{prefix}.mongodb.net/{database_name}?retryWrites=true&w=majority"
    

def last_alert_psg():
    pg_hook = PostgresHook(postgres_conn_id='postgres_default')
    sql = "SELECT id FROM security_findings ORDER BY id DESC LIMIT 1"
    result = pg_hook.get_first(sql)
    return result[0] if result else "000000000000000000000000"

def mongo_new_alerts(**kwargs):
    ti = kwargs['ti']
    last_id = ti.xcom_pull(task_ids='get_last_alert_id')
    
    
