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

    # Executes an INSERT/UPDATE/DELETE and returns the number of affected rows,
    # so callers can make conditional writes atomic (e.g. check-and-set guards
    # like "UPDATE ... WHERE jwk IS NULL" and detect whether they won a race).
    def execute_modify_rows(self, sql_command, values):
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            cursor.execute(sql_command, values)
            connection.commit()
            rowcount = cursor.rowcount
            self.close_connection(connection)
            sys_logger.debug(
                "Executed MODIFY query: %s (affected rows: %s)", sql_command, rowcount
            )
            return rowcount
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error("Error while executing MODIFY query: %s", error)
            return -1

    # Tables whose primary key is an app-assigned integer (not AUTO_INCREMENT),
    # mapped to (pk column, first id to hand out when the table is empty).
    # Used by get_next_available_id()/claim_next_id() to compute MAX(pk)+1.
    # Keeping this as an explicit allow-list means `table_name` can never be
    # attacker-influenced SQL - only these known tables/columns are reachable.
    _ID_TABLES = {
        "Certificate": ("Cert_Id", 100),
        "ActiveCertificate": ("ActiveCertificate_Id", 10000),
        "NotifyGroup": ("Group_Id", 1000),
        "AcmeAccount": ("Account_Id", 10000),
        "AcmeAccountDomain": ("Domain_Id", 10000),
        "AcmeOrder": ("Order_Id", 10000),
        "AcmeAuthorization": ("Authz_Id", 10000),
    }

    def get_next_available_id(self, table_name):
        """
        Next free primary-key value for `table_name` (MAX(pk) + 1).

        NOTE: this read is inherently racy - see claim_next_id() for the
        race-free variant. This is kept for the common single-threaded callers
        (the web UI and the ACME order/finalize path are low-concurrency), but
        `table_name` is at least confined to the known _ID_TABLES allow-list so
        it can't be used as an injection vector.
        """
        if table_name not in self._ID_TABLES:
            sys_logger.error(
                "get_next_available_id called for unknown table: %r", table_name
            )
            return None
        pk_column, start_id = self._ID_TABLES[table_name]
        try:
            rows = self.execute_select_query(
                f"SELECT MAX({pk_column}) FROM {table_name}"
            )
            current_max = rows[0][0] if rows else None
            next_id = (current_max + 1) if current_max is not None else start_id
            sys_logger.debug("Next available id for %s: %s", table_name, next_id)
            return next_id
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error(
                "Error finding next available id for %s: %s", table_name, error
            )
            return None

    def claim_next_id(self, table_name):
        """
        Race-free next-id allocation backed by the `IdCounter` table
        (`name` PK, `value` INT). The increment is a single atomic
        INSERT ... ON DUPLICATE KEY UPDATE, so two concurrent claimers always
        get distinct values - unlike get_next_available_id(), whose
        read-then-compute is racy across the app's separate DB connections
        (web UI, ACME finalize, and the scheduler each open their own).

        The counter is seeded from the table's current MAX(pk) on first use so
        existing rows are never collided with. Returns the allocated id, or
        None on error / unknown table.

        Requires (one-time, idempotent):
            CREATE TABLE IF NOT EXISTS IdCounter (
                name VARCHAR(64) NOT NULL PRIMARY KEY,
                value INT UNSIGNED NOT NULL
            );
        """
        if table_name not in self._ID_TABLES:
            sys_logger.error("claim_next_id called for unknown table: %r", table_name)
            return None
        pk_column, start_id = self._ID_TABLES[table_name]

        # Seed the counter from the live table once, then bump it atomically.
        # LAST_INSERT_ID(value) lets us read back the post-increment counter
        # on the same connection without a second round-trip.
        seed_rows = self.execute_select_query(
            f"SELECT COALESCE(MAX({pk_column}), %s) FROM {table_name}", (start_id - 1,)
        )
        seed = seed_rows[0][0] if seed_rows else start_id - 1

        connection = self.get_connection()
        if connection is None:
            return None
        try:
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO IdCounter (name, value) VALUES (%s, LAST_INSERT_ID(%s + 1)) "
                "ON DUPLICATE KEY UPDATE value = LAST_INSERT_ID(value + 1)",
                (table_name, seed),
            )
            connection.commit()
            cursor.execute("SELECT LAST_INSERT_ID()")
            allocated = cursor.fetchone()[0]
            return allocated
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error("Error claiming next id for %s: %s", table_name, error)
            return None
        finally:
            self.close_connection(connection)

    def get_records(self, table_name, column=None, value=None):
        """
        SELECT * FROM `table_name` [WHERE `column` = %s].

        The WHERE clause is built internally from a bare column name; callers
        never supply raw SQL fragments. `column` is validated to contain only
        word characters (letters/digits/underscore) so it cannot be used to
        inject SQL. `value` (attacker-reachable or not) is always passed via
        a parameterized placeholder.
        """
        if column is not None and not column.isidentifier():
            sys_logger.error("Rejected invalid column name in get_records: %r", column)
            return None
        try:
            sql_command = f"SELECT * FROM {table_name}"
            params = None
            if column is not None:
                sql_command += f" WHERE {column} = %s"
                params = (value,)
            records = self.execute_select_query(sql_command, params)
            sys_logger.debug("Executed SELECT query: %s", sql_command)
            return records
        except (Exception, mysql.connector.Error) as error:
            sys_logger.error("Error while executing SELECT query: %s", error)
            return None

    def remove_record(self, table_name, column, value):
        """
        DELETE FROM `table_name` WHERE `column` = %s.

        Same rule as get_records(): the WHERE clause is built internally from
        a validated bare column name, and `value` is always parameterized.
        """
        if not column.isidentifier():
            sys_logger.error(
                "Rejected invalid column name in remove_record: %r", column
            )
            return "Failure"
        sql_command = f"DELETE FROM {table_name} WHERE {column} = %s"
        result = self.execute_modify_query(sql_command, (value,))
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
