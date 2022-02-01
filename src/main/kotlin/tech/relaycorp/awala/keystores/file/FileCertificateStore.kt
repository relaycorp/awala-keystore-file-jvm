package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import tech.relaycorp.relaynet.keystores.CertificateStore

public abstract class FileCertificateStore(keystoreRoot: FileKeystoreRoot) : CertificateStore() {

    @Suppress("MemberVisibilityCanBePrivate")
    public val rootDirectory: File = keystoreRoot.directory.resolve("certificate")

    override suspend fun saveData(
        subjectPrivateAddress: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray
    ) {
        val expirationTimestamp = leafCertificateExpiryDate.toTimestamp()
        val dataDigest = certificationPathData.toDigest()
        val certFile = getNodeSubdirectory(subjectPrivateAddress).resolve(
            "$FILE_PREFIX-$expirationTimestamp-$dataDigest"
        )
        saveCertificationFile(certFile, certificationPathData)
    }

    override suspend fun retrieveData(subjectPrivateAddress: String): List<ByteArray> {
        val certificateFiles =
            getNodeSubdirectory(subjectPrivateAddress).listFiles()
                ?: return emptyList()

        return certificateFiles
            .filter { it.getExpiryDateFromName().isAfter(ZonedDateTime.now()) }
            .map { retrieveData(it) }
    }

    override suspend fun deleteExpired() {
        rootDirectory
            .listFiles() // addresses
            ?.filter(File::isDirectory)
            ?.map { addressFile ->
                addressFile
                    .listFiles() // address certificates
                    ?.filter { it.getExpiryDateFromName().isBefore(ZonedDateTime.now()) }
                    ?.forEach { it.delete() }
            }
    }

    @Throws(FileKeystoreException::class)
    override fun delete(subjectPrivateAddress: String) {
        val deletionSucceeded = getNodeSubdirectory(subjectPrivateAddress).deleteRecursively()
        if (!deletionSucceeded) {
            throw FileKeystoreException(
                "Failed to delete node directory for $subjectPrivateAddress"
            )
        }
    }

    private fun saveCertificationFile(certFile: File, serialization: ByteArray) {
        val parentDirectory = certFile.parentFile
        val wereDirectoriesCreated = parentDirectory.mkdirs()
        if (!wereDirectoriesCreated && !parentDirectory.exists()) {
            throw FileKeystoreException(
                "Failed to create address directory for certification files"
            )
        }
        try {
            makeEncryptedOutputStream(certFile).use {
                it.write(serialization)
                it.flush()
            }
        } catch (exc: IOException) {
            throw FileKeystoreException("Failed to save certification file", exc)
        }
    }

    private fun retrieveData(file: File): ByteArray {
        return try {
            makeEncryptedInputStream(file).use { it.readBytes() }
        } catch (exc: IOException) {
            throw FileKeystoreException("Failed to read certification file", exc)
        }
    }

    private fun ZonedDateTime.toTimestamp() =
        toInstant().toEpochMilli()

    private fun Long.toZonedDateTime() =
        ZonedDateTime.ofInstant(Instant.ofEpochMilli(this), ZoneId.of("UTC"))

    private fun File.getExpiryDateFromName(): ZonedDateTime =
        name.split("-")
            .getOrNull(1)
            ?.toLongOrNull()
            ?.toZonedDateTime()
            ?: throw FileKeystoreException("Invalid certificate file name: $name")

    private fun getNodeSubdirectory(privateAddress: String) =
        rootDirectory.resolve(privateAddress)

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream

    private companion object {
        private const val FILE_PREFIX = "CERT"
    }
}

internal fun ByteArray.toDigest() =
    MessageDigest.getInstance("SHA-256")
        .digest(this)
        .joinToString("") { "%02x".format(it) }
