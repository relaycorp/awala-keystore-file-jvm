package tech.relaycorp.awala.keystores.file

import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class FileSessionPublicKeyStoreTest {
    @Nested
    inner class Constructor {
        @Test
        @Disabled
        fun `Root directory should be rejected if it isn't really a directory`() {
        }
    }

    @Nested
    inner class Save {
        @Test
        @Disabled
        fun `Parent directories should be created if they don't already exist`() {
        }

        @Test
        @Disabled
        fun `Errors creating parent directories should be wrapped`() {
        }

        @Test
        @Disabled
        fun `Key data should be stored in new file if there is no prior key for peer`() {
        }

        @Test
        @Disabled
        fun `Key data should be updated if there is a prior key for peer`() {
        }

        @Test
        @Disabled
        fun `Data should be flushed with fdatasync`() {
        }
    }
}
