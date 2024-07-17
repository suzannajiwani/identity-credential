package com.android.identity.wallet.server

import com.android.identity.flow.server.Storage
import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.io.bytestring.ByteString
import java.sql.Connection
import java.sql.DriverManager
import javax.sql.DataSource
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random

class ServerStorage(
    private val jdbc: String,
    private var user: String = "",
    private val password: String = "",
): Storage {
    private val createdTables = mutableSetOf<String>()
    private val blobType: String
    private lateinit var pool: DataSource

    init {
        // initialize appropriate drives (this also ensures that dependencies don't get
        // stripped when building WAR file).
        if (jdbc.startsWith("jdbc:hsqldb:")) {
            blobType = "BLOB"
            org.hsqldb.jdbc.JDBCDriver()
        } else if (jdbc.startsWith("cloud")) {
            blobType = "BLOB"
            this.pool = createConnectionPool()
        } else if (jdbc.startsWith("jdbc:mysql:")) {
            blobType = "LONGBLOB"  // MySQL BLOB is limited to 64k
            com.mysql.cj.jdbc.Driver()
        } else {
            blobType = "BLOB"
        }
    }

    override suspend fun get(table: String, peerId: String, key: String): ByteString? {
        val safeTable = sanitizeTable(table)
        val connection = acquireConnection()
        ensureTable(connection, safeTable)
        val statement = connection.prepareStatement(
            "SELECT data FROM $safeTable WHERE (peerId = ? AND id = ?)")
        statement.setString(1, peerId)
        statement.setString(2, key)
        val resultSet = statement.executeQuery()
        if (!resultSet.next()) {
            return null
        }
        val bytes = resultSet.getBytes(1)
        releaseConnection(connection)
        return ByteString(bytes)
    }

    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun insert(table: String, peerId: String, data: ByteString, key: String): String {
        val safeTable = sanitizeTable(table)
        val recordKey = key.ifEmpty { Base64.encode(Random.Default.nextBytes(18)) }
        val connection = acquireConnection()
        ensureTable(connection, safeTable)
        val statement = connection.prepareStatement("INSERT INTO $safeTable VALUES(?, ?, ?)")
        statement.setString(1, recordKey)
        statement.setString(2, peerId)
        statement.setBytes(3, data.toByteArray())
        val count = statement.executeUpdate()
        releaseConnection(connection)
        if (count != 1) {
            throw IllegalStateException("Value was not inserted")
        }
        return recordKey
    }

    override suspend fun update(table: String, peerId: String, key: String, data: ByteString) {
        val safeTable = sanitizeTable(table)
        val connection = acquireConnection()
        ensureTable(connection, safeTable)
        val statement = connection.prepareStatement(
            "UPDATE $safeTable SET data = ? WHERE (peerId = ? AND id = ?)")
        statement.setBytes(1, data.toByteArray())
        statement.setString(2, peerId)
        statement.setString(3, key)
        val count = statement.executeUpdate()
        releaseConnection(connection)
        if (count != 1) {
            throw IllegalStateException("Value was not updated")
        }
    }

    override suspend fun delete(table: String, peerId: String, key: String): Boolean {
        val safeTable = sanitizeTable(table)
        val connection = acquireConnection()
        ensureTable(connection, safeTable)
        val statement = connection.prepareStatement(
            "DELETE FROM $safeTable WHERE (peerId = ? AND id = ?)")
        statement.setString(1, peerId)
        statement.setString(2, key)
        val count = statement.executeUpdate()
        releaseConnection(connection)
        return count > 0
    }

    override suspend fun enumerate(table: String, peerId: String,
                                   notBeforeKey: String, limit: Int): List<String> {
        val safeTable = sanitizeTable(table)
        val connection = acquireConnection()
        ensureTable(connection, safeTable)
        val opt = if (limit < Int.MAX_VALUE) " LIMIT 0, $limit" else ""
        val statement = connection.prepareStatement(
            "SELECT id FROM $safeTable WHERE (peerId = ? AND id > ?) ORDER BY id$opt")
        statement.setString(1, peerId)
        statement.setString(2, notBeforeKey)
        val resultSet = statement.executeQuery()
        val list = mutableListOf<String>()
        while (resultSet.next()) {
            list.add(resultSet.getString(1))
        }
        releaseConnection(connection)
        return list
    }

    private fun ensureTable(connection: Connection, safeTable: String) {
        if (!createdTables.contains(safeTable)) {
            connection.createStatement().execute("""
                CREATE TABLE IF NOT EXISTS $safeTable (
                    id VARCHAR(64) PRIMARY KEY,
                    peerId VARCHAR(64),
                    data $blobType
                )
            """.trimIndent())
            createdTables.add(safeTable)
        }
    }

    private fun acquireConnection(): Connection {
        if (jdbc.startsWith("cloud")) {
            return this.pool.connection
        }
        return DriverManager.getConnection(jdbc, user, password)
    }

    private fun releaseConnection(connection: Connection) {
        connection.close()
    }

    private fun sanitizeTable(table: String): String {
        return "Wt$table"
    }

    fun createConnectionPool(): DataSource {
        val config = HikariConfig()

        val DB_NAME = "server"
        val DB_PASS: String
        val DB_USER = "root"
        val INSTANCE_CONNECTION_NAME = "mdoc-reader-external:us-east1:wallet-server"

        SecretManagerServiceClient.create().use { client ->
            val request = AccessSecretVersionRequest.newBuilder().setName("projects/1048349407273/secrets/sql-user-pass/versions/latest").build()
            val response: AccessSecretVersionResponse =
                client.accessSecretVersion(request)

            DB_PASS = response.payload.data.toStringUtf8()
        }

        config.jdbcUrl = java.lang.String.format("jdbc:mysql:///%s", DB_NAME)
        config.username = DB_USER
        config.password = DB_PASS

        config.setDriverClassName(com.mysql.cj.jdbc.Driver::class.java.name)
        config.addDataSourceProperty("socketFactory", "com.google.cloud.sql.mysql.SocketFactory")
        config.addDataSourceProperty("cloudSqlInstance", INSTANCE_CONNECTION_NAME)
        config.addDataSourceProperty("ipTypes", "PUBLIC,PRIVATE")

        return HikariDataSource(config)
    }
}