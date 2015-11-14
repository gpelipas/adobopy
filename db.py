# -*- coding: utf-8 -*-



class ConnectionHandler(object):
      def __init__(self, **settings):
          self.__settings = settings

      def getConnection(self):
          pass

      def release(self, conn):
          pass

class SQLAlchemyConnectionHandler(ConnectionHandler):
      def __init__(self, **settings):
          super(SQLAlchemyConnectionHandler, self).__init__(settings)

          from sqlalchemy.engine.url import URL
          from sqlalchemy.engine import create_engine
          url = URL(drivername=__settings.ENGINE, username=__settings.USER, password=__settings.PASSWORD, host=__settings.HOST, port=__settings.PORT, database=__settings.DBNAME)
          self.__engine = create_engine(url)

      def getConnection(self):
          return self.__engine.connect()

      def release(self, conn):
          conn.close();


class SQLAlchemyORMHandler(SQLAlchemyConnectionHandler):
      from sqlalchemy.orm import scoped_session, sessionmaker
      __SessionFactory = sessionmaker()
      __SessionFactorySessionCtx = None

      def __init__(self, **settings):
          super(SQLAlchemyORMHandler, self).__init__(settings)
          if SQLAlchemyORMHandler.__SessionFactorySessionCtx is None:
            SQLAlchemyORMHandler.__SessionFactorySessionCtx = scoped_session(SQLAlchemyORMHandler.__SessionFactory)      
          
          if self.__settings.SESSION:
             addSessionConfig(self.__settings.SESSION)

      def addSessionConfig(self, **extraConfig):
          SQLAlchemyORMHandler.__SessionFactory.configure(extraConfig)

      def getSession(self):
          return SQLAlchemyORMHandler.__SessionFactory()

