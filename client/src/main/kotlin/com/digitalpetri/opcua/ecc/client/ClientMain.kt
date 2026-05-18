package com.digitalpetri.opcua.ecc.client

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.UsageError
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option

/** Runs the client probe CLI. */
fun main(args: Array<String>) {
  System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn")
  ClientCommand().main(args)
}

/**
 * Command-line configuration for one client probe run.
 *
 * The probe compares the target server's advertised endpoint matrix against these filters. Policy,
 * mode, and token names intentionally stay close to Milo and OPC UA terminology, so terminal output
 * can be compared directly with endpoint descriptions from other tools.
 *
 * @property targetUrl the OPC UA discovery URL used to fetch endpoint descriptions.
 * @property dataDir directory that stores the client's own application identity.
 * @property username optional username used for username-token attempts.
 * @property password optional password used for username-token attempts.
 * @property policies selected security policy names.
 * @property modes selected message security mode names.
 * @property tokens selected user token names.
 */
internal data class ClientOptions(
    val targetUrl: String,
    val dataDir: String,
    val username: String?,
    val password: String?,
    val policies: List<String>,
    val modes: List<String>,
    val tokens: List<String>,
)

/** Default interoperability profile attempted by the client. */
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
 * OPC UA only pairs `None` with the `None` security policy; non-`None` policies are probed with
 * signed and signed-and-encrypted messages.
 */
internal val DEFAULT_MESSAGE_MODES = listOf("None", "Sign", "SignAndEncrypt")

/** User identity mechanisms understood by the client probe. */
internal val DEFAULT_USER_TOKENS = listOf("Anonymous", "UserName")

private class ClientCommand :
    CliktCommand(
        name = "ecc-demo-client",
    ) {
  private val targetUrl by
      argument(
          "TARGET_URL",
          help = "OPC UA discovery URL to probe.",
      )

  private val dataDir by
      option(
              "--data-dir",
              help = "Directory for local client identity data.",
          )
          .default("/data/client")

  private val username by
      option(
          "--username",
          help = "Username to use for username-token attempts.",
      )

  private val password by
      option(
          "--password",
          help = "Password to use for username-token attempts.",
      )

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
    if (username != null && password == null) {
      throw UsageError("--password is required when --username is supplied")
    }

    val options =
        ClientOptions(
            targetUrl = targetUrl,
            dataDir = dataDir,
            username = username,
            password = password,
            policies = parseAllowedFilterValues("policy", policyFilters, DEFAULT_SECURITY_POLICIES),
            modes = parseAllowedFilterValues("mode", modeFilters, DEFAULT_MESSAGE_MODES),
            tokens = parseAllowedFilterValues("token", tokenFilters, DEFAULT_USER_TOKENS),
        )

    val terminal = ClientTerminal()
    terminal.renderProbeResult(
        runProbe(
            options = options,
            onPlanReady = terminal::renderProbeStart,
            onProbeAttemptsStarted = terminal::startProbeProgress,
        )
    )
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
