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
import logging


load_dotenv()

def connect_to_mongo():
    try:
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
    except Exception as e:
        logging.error(f"Erro ao conectar ao MongoDB: {e}")
        raise

def last_alert_psg():
    try:
        pg_hook = PostgresHook(postgres_conn_id='postgres_default')
        sql = "SELECT mongo_id FROM security_findings ORDER BY mongo_id DESC LIMIT 1"
        result = pg_hook.get_first(sql)
        return result[0] if result else "000000000000000000000000"
    except Exception as e:
        logging.error(f"Erro ao obter o último ID de alerta do PostgreSQL: {e}")
        raise

def load_alerts_to_postgres(**kwargs):
    try:
        ti = kwargs['ti']
        alerts_to_load = ti.xcom_pull(task_ids='extract_new_alerts')

        if not alerts_to_load:
            print("Nenhum alerta novo para carregar. Tarefa concluída.")
            return

        pg_hook = PostgresHook(postgres_conn_id='postgres_default')

        target_fields = [
            'mongo_id', 'project_name', 'tool_type', 'tool_name', 'title',
            'severity', 'description', 'local_path', 'status', 'creation_date',
            'resolved_date', 'cve', 'how_to_fix', 'tags'
        ]

        rows_to_insert = []
        for alert in alerts_to_load:
            row = (
                alert['_id'],  # O ID que já convertemos para string
                alert.get('projectName'),      # <--- CONFIRME o nome do campo no Mongo
                alert.get('toolType'),         # <--- CONFIRME
                alert.get('toolName'),         # <--- CONFIRME
                alert.get('title'),            # <--- CONFIRME
                alert.get('severity'),         # <--- CONFIRME
                alert.get('description'),      # <--- CONFIRME
                alert.get('path'),             # <--- CONFIRME (ex: 'path' para 'local_path')
                alert.get('status'),           # <--- CONFIRME
                alert.get('creationDate'),     # <--- CONFIRME (precisa ser um objeto datetime ou string formatada)
                alert.get('resolvedDate'),     # <--- CONFIRME
                alert.get('cve'),              # <--- CONFIRME
                alert.get('howToFix'),         # <--- CONFIRME
                str(alert.get('tags', []))     # <--- CONFIRME (convertendo lista para string, se necessário)
            )
            rows_to_insert.append(row)

        print(f"Inserindo {len(rows_to_insert)} novos alertas no PostgreSQL...")
        pg_hook.insert_rows(
            table="security_findings",
            rows=rows_to_insert,
            target_fields=target_fields,
            commit_every=1000
        )
        logging.info("Inserção concluída com sucesso.")
    except Exception as e:
        logging.error(f"Falha ao inserir dados no PostgreSQL. Erro: {e}")
        raise

def mongo_new_alerts(**kwargs):
    try:
        ti = kwargs['ti']
        last_id = ti.xcom_pull(task_ids='get_last_alert_id')
        mongo_uri = connect_to_mongo()
        client = MongoClient(mongo_uri)
        db = client[os.getenv('MONGO_DB_NAME')]
        collection = db['alerts']
        new_alerts = list(collection.find({"_id": {"$gt": ObjectId(last_id)}}))
        if not new_alerts:
            return None
        for alert in new_alerts:
            alert['_id'] = str(alert['_id'])
        return new_alerts
    except Exception as e:
        logging.error(f"Erro ao obter alertas do MongoDB: {e}")
        raise
    finally:
        if client:
            client.close()

with DAG(
    dag_id = "mongo_to_postgres_sync",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    schedule_interval="*/10 * * * *",
    catchup=False,
    tags=["data-sync", "mongo", "postgres"],
) as dag:
    get_last_alert_id = PythonOperator(
        task_id="get_last_alert_id",
        python_callable=last_alert_psg, 
    )

    extract_new_alerts = PythonOperator(
        task_id="extract_new_alerts",
        python_callable=mongo_new_alerts,
    )

    load_alerts = PythonOperator(
        task_id="load_alerts_to_postgres",
        python_callable=load_alerts_to_postgres,
    )
    get_last_alert_id >> extract_new_alerts >> load_alerts
