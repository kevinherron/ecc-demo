package com.digitalpetri.opcua.ecc.server

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.UsageError
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.check
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.int
import java.util.concurrent.CountDownLatch

/** Runs the demo server CLI. */
fun main(args: Array<String>) {
  System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn")
  ServerCommand().main(args)
}

/**
 * Command-line configuration for one demo server process.
 *
 * The security-related fields use Milo enum names because they map directly to OPC UA endpoint
 * descriptors: a security policy names the cryptographic algorithm suite, a message mode says how
 * messages are protected, and a user token says how the client identifies itself when it activates
 * a session.
 *
 * @property bindAddresses network interfaces the TCP listener binds to.
 * @property endpointAddresses host names or addresses advertised in endpoint URLs.
 * @property port the TCP port used by every advertised endpoint.
 * @property dataDir directory that stores the server's own application identity.
 * @property applicationUri the OPC UA application URI embedded in generated certificates.
 * @property applicationName human-readable application name shown to clients.
 * @property dnsNames the DNS subject alternative names embedded in generated certificates.
 * @property ipAddresses the IP subject alternative names embedded in generated certificates.
 * @property username demo username accepted by username-token sessions.
 * @property password demo password accepted by username-token sessions.
 * @property policies selected security policy names.
 * @property modes selected message security mode names.
 * @property tokens selected user token names.
 */
internal data class ServerOptions(
    val bindAddresses: List<String>,
    val endpointAddresses: List<String>,
    val port: Int,
    val dataDir: String,
    val applicationUri: String,
    val applicationName: String,
    val dnsNames: List<String>,
    val ipAddresses: List<String>,
    val username: String,
    val password: String,
    val policies: List<String>,
    val modes: List<String>,
    val tokens: List<String>,
)

/** Default interoperability profile advertised by the server. */
internal val DEFAULT_SECURITY_POLICIES =
    listOf(
        "None",
        "Basic256Sha256",
        "Aes128_Sha256_RsaOaep",
        "Aes256_Sha256_RsaPss",
        "ECC_nistP256_AesGcm",
        "ECC_nistP256_ChaChaPoly",
        "ECC_nistP384_AesGcm",
        "ECC_nistP384_ChaChaPoly",
        "ECC_brainpoolP256r1_AesGcm",
        "ECC_brainpoolP256r1_ChaChaPoly",
        "ECC_brainpoolP384r1_AesGcm",
        "ECC_brainpoolP384r1_ChaChaPoly",
        "ECC_curve25519_AesGcm",
        "ECC_curve25519_ChaChaPoly",
        "ECC_curve448_AesGcm",
        "ECC_curve448_ChaChaPoly",
        "RSA_DH_AesGcm",
        "RSA_DH_ChaChaPoly",
    )

/**
 * Message protection modes used by the default profile.
 *
 * OPC UA only pairs `None` with the `None` security policy; non-`None` policies are offered with
 * signed and signed-and-encrypted messages.
 */
internal val DEFAULT_MESSAGE_MODES = listOf("None", "Sign", "SignAndEncrypt")

/** User identity mechanisms advertised by the demo server. */
internal val DEFAULT_USER_TOKENS = listOf("Anonymous", "UserName")

private class ServerCommand :
    CliktCommand(
        name = "ecc-demo-server",
    ) {
  private val bindAddresses by
      option(
              "--bind-address",
              help = "Address to bind. Repeat to bind more than one address.",
          )
          .multiple(default = listOf("0.0.0.0"))

  private val endpointAddresses by
      option(
              "--endpoint-address",
              help =
                  "Host name or address advertised in endpoint URLs. Repeat to advertise more than one.",
          )
          .multiple(default = listOf("localhost"))

  private val port by
      option(
              "--port",
              help = "TCP port for OPC UA endpoints.",
          )
          .int()
          .default(4840)
          .check("port must be between 1 and 65535") { it in 1..65535 }

  private val dataDir by
      option(
              "--data-dir",
              help = "Directory for local server identity data.",
          )
          .default("/data/server")

  private val applicationUri by
      option(
              "--application-uri",
              help = "Server application URI placed in generated certificates.",
          )
          .default("urn:eclipse:milo:ecc-demo:server")

  private val applicationName by
      option(
              "--application-name",
              help = "Server application name.",
          )
          .default("ECC Demo Server")

  private val dnsNames by
      option(
              "--dns-name",
              help = "DNS subject alternative name for generated certificates. Repeat to add more.",
          )
          .multiple(default = listOf("localhost"))

  private val ipAddresses by
      option(
              "--ip-address",
              help = "IP subject alternative name for generated certificates. Repeat to add more.",
          )
          .multiple(default = listOf("127.0.0.1"))

  private val username by
      option(
              "--username",
              help = "Username accepted by the demo username identity validator.",
          )
          .default("user")

  private val password by
      option(
              "--password",
              help = "Password accepted by the demo username identity validator.",
          )
          .default("password")

  private val policyFilters by
      option(
              "--policy",
              help = "Security policy filter. Repeat or pass comma-separated values.",
          )
          .multiple()

  private val modeFilters by
      option(
              "--mode",
              help = "Message security mode filter. Repeat or pass comma-separated values.",
          )
          .multiple()

  private val tokenFilters by
      option(
              "--token",
              help = "User token filter. Repeat or pass comma-separated values.",
          )
          .multiple()

  override fun run() {
    val options =
        ServerOptions(
            bindAddresses = bindAddresses,
            endpointAddresses = endpointAddresses,
            port = port,
            dataDir = dataDir,
            applicationUri = applicationUri,
            applicationName = applicationName,
            dnsNames = dnsNames,
            ipAddresses = ipAddresses,
            username = username,
            password = password,
            policies = parseAllowedFilterValues("policy", policyFilters, DEFAULT_SECURITY_POLICIES),
            modes = parseAllowedFilterValues("mode", modeFilters, DEFAULT_MESSAGE_MODES),
            tokens = parseAllowedFilterValues("token", tokenFilters, DEFAULT_USER_TOKENS),
        )

    val shutdown = CountDownLatch(1)
    Runtime.getRuntime()
        .addShutdownHook(
            Thread({ shutdown.countDown() }, "ecc-demo-server-shutdown"),
        )

    ServerRuntime.create(options).use { runtime ->
      ServerTerminal().renderStartup(runtime.start())
      shutdown.await()
    }
  }
}

/**
 * Parses repeatable or comma-separated CLI filter values into canonical allowed values.
 *
 * Omitted filters select the full allowed list. Supplied values are trimmed, matched
 * case-insensitively, and deduplicated while preserving their first-seen order.
 *
 * @param optionName name used in CLI errors without the leading `--`.
 * @param rawValues values collected by Clikt for the repeatable option.
 * @param allowedValues canonical values accepted by this filter.
 * @return canonical selected values, or all allowed values when the filter is omitted.
 * @throws UsageError if the option contains no non-empty values or an unknown value.
 */
private fun parseAllowedFilterValues(
    optionName: String,
    rawValues: List<String>,
    allowedValues: List<String>,
): List<String> {
  if (rawValues.isEmpty()) return allowedValues

  val selected = rawValues.flatMap { it.split(",") }.map { it.trim() }.filter { it.isNotEmpty() }

  if (selected.isEmpty()) {
    throw UsageError("--$optionName must include at least one non-empty value")
  }

  val allowedByLowerName = allowedValues.associateBy { it.lowercase() }
  return selected
      .map { value ->
        allowedByLowerName[value.lowercase()]
            ?: throw UsageError(
                "invalid $optionName '$value'. Expected one of: ${allowedValues.joinToString(", ")}"
            )
      }
      .distinct()
}
