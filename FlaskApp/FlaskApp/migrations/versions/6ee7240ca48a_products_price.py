"""products price

Revision ID: 6ee7240ca48a
Revises: f59ddf307014
Create Date: 2019-04-07 16:41:59.853143

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6ee7240ca48a'
down_revision = 'f59ddf307014'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('products', sa.Column('price', sa.Float(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('products', 'price')
    # ### end Alembic commands ###