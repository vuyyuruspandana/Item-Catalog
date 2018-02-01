from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy import create_engine
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature, SignatureExpired)

Base = declarative_base()

# User table for storing all the details of the user
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(30), nullable=False)
    email = Column(String(50), nullable=False, index=True)
    password_hash = Column(String)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    @property
    def serialize(self):
        return{
            'id': self.id,
            'username': self.username,
            'email': self.email
        }

# this table is for storage of all the categories
class Decor(Base):
    __tablename__ = 'decor'
    id = Column(Integer, primary_key=True)
    name = Column(String)


    @property
    def serialize(self):
        return{
            'id': self.id,
            'name': self.name
        }

# stores the items in the categories
class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    d_id = Column(Integer, ForeignKey('decor.id'))
    decor = relationship(Decor)
    u_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'id':self.id,
            'title': self.title,
            'description': self.description
        }

engine = create_engine('sqlite:///catalog3.db')

Base.metadata.create_all(engine)
