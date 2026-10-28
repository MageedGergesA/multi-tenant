"""Alembic runs plain SQL migrations (DOC-03 §0); the URL comes from CTL_DATABASE_URL."""
import os

from alembic import context
from sqlalchemy import create_engine

url = context.config.attributes.get('url') or os.environ['CTL_DATABASE_URL']
with create_engine(url.replace('postgresql://', 'postgresql+psycopg://', 1)).connect() as conn:
    context.configure(connection=conn, transactional_ddl=True)
    with context.begin_transaction():
        context.run_migrations()
    conn.commit()
