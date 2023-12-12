import mysql.connector

from .sucm_settings import cfg, sys_logger

dbHost = cfg.get("mysql_connector", "host")
dbDatabase = cfg.get("mysql_connector", "database")
dbUser = cfg.get("mysql_connector", "user")
dbPassword = cfg.get("mysql_connector", "password")


class SucmMysql:
    def __init__(
        self,
        db_host=dbHost,
        db_user=dbUser,
        db_password=dbPassword,
        db_database=dbDatabase,
    ):
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        self.db_database = db_database
        self.ssl_ca = "/etc/ssl/certs/ca-certificates.crt"
        self.port = 3306
        self.ssl_verify_cert = True
        sys_logger.debug("SucmMysql instance created.")

    # Open DB connection
    def get_connection(self):
        try:
            connection = mysql.connector.connect(
                host=self.db_host,
                database=self.db_database,
                user=self.db_user,
                password=self.db_password,
                ssl_ca=self.ssl_ca,
                port=self.port,
                ssl_verify_cert=self.ssl_verify_cert,
            )
            sys_logger.debug("Database connection established.")
            return connection
        except mysql.connector.Error as error:
            sys_logger.error("Error establishing database connection: %s", error)
            return None

    # Close DB connection
    @staticmethod
    def close_connection(connection):
        if connection:
            try:
                connection.close()
                sys_logger.debug("Database connection closed.")
            except mysql.connector.Error as error:
                sys_logger.error("Error closing database connection: %s", error)

    # Executes a SELECT query and returns the records.
    def execute_select_query(self, sql_command, values=None):
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            if values:
                cursor.execute(sql_command, values)
            else:
                cursor.execute(sql_command)
            records = cursor.fetchall()
            self.close_connection(connection)
            sys_logger.debug("Executed SELECT query: %s", sql_command)
            return records
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error("Error while executing SELECT query: %s", error)
            return None

    # Executes a INSERT, REPLACE, DELETE query and returns success or failure.
    def execute_modify_query(self, sql_command, values):
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            cursor.execute(sql_command, values)
            connection.commit()
            self.close_connection(connection)
            sys_logger.debug("Executed MODIFY query: %s", sql_command)
            return "Success"
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error("Error while executing MODIFY query: %s", error)
            return "Failure"

    def get_next_available_id(self, table_name):
        try:
            sql_command = f"SELECT * FROM {table_name}"
            all_records = self.execute_select_query(sql_command)
            next_id = all_records[-1][0] + 1
            sys_logger.debug(
                "Executed SELECT query: %s, to find the next available id: %s",
                sql_command,
                next_id,
            )
            return next_id
        except IndexError:  # if db is empty
            sys_logger.error(
                "Error while executing SELECT query to find next ID for %s, the db is empty and will return starting id.",
                table_name,
            )
            return (
                100
                if table_name == "Certificate"
                else (1000 if table_name == "NotifyGroup" else 10000)
            )

    def get_records(self, table_name, condition=None):
        try:
            sql_command = f"SELECT * FROM {table_name}"
            if condition and "None" not in condition:
                sql_command += f" WHERE {condition}"
            records = self.execute_select_query(sql_command)
            sys_logger.debug("Executed SELECT query: %s", sql_command)
            return records
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error("Error while executing SELECT query: %s", error)
            return None

    def remove_record(self, table_name, condition):
        sql_command = f"DELETE FROM {table_name} WHERE {condition}"
        result = self.execute_modify_query(sql_command, ())
        if result == "Success":
            sys_logger.debug("Executed MODIFY query: %s", sql_command)
        return result

    def add_update_record(self, table_name, data):
        try:
            fields = data.keys()
            values = list(data.values())
            placeholders = ", ".join(["%s"] * len(values))

            # Add the ON DUPLICATE KEY UPDATE clause
            update_clause = ", ".join(f"{field} = VALUES({field})" for field in fields)

            sql_command = (
                f"INSERT INTO {table_name} "
                f"({', '.join(fields)}) "
                f"VALUES ({placeholders}) "
                f"ON DUPLICATE KEY UPDATE {update_clause}"
            )

            result = self.execute_modify_query(sql_command, tuple(values))
            if result == "Success":
                sys_logger.debug("Executed INSERT/UPDATE query: %s", sql_command)
            return result
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error("Error while modifying data: %s", error)
            return "Failure"
