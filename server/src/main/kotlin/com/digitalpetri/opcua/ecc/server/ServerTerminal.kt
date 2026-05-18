package com.digitalpetri.opcua.ecc.server

import com.github.ajalt.mordant.rendering.TextColors.brightBlue
import com.github.ajalt.mordant.terminal.Terminal
import kotlin.collections.iterator

private const val CERTIFICATE_TYPE_WIDTH = 42
private const val MODE_WIDTH = 17
private const val POLICY_WIDTH = 34
private const val RULE_WIDTH = 64
private const val TOKEN_WIDTH = 23

/**
 * Renders startup state as the server's primary evidence surface.
 *
 * The summary names the local certificates and advertised endpoint combinations so a client-side
 * probe can be compared against exactly what this server intended to expose.
 */
internal class ServerTerminal(
    private val terminal: Terminal = Terminal(),
) {
  fun renderStartup(summary: ServerStartupSummary) {
    terminal.println(title("ECC Demo Server"))
    terminal.println(rule())
    terminal.println(row("Endpoints", "${summary.endpointCount} advertised"))
    terminal.println(row("URLs", endpointUrls(summary.endpoints)))
    terminal.println(
        row(
            "Trust",
            if (summary.remoteCertificatesAutoTrusted) {
              "remote certificates auto-trusted"
            } else {
              "remote certificates validated"
            },
        )
    )
    terminal.println(
        row(
            "Rate limit",
            if (summary.connectionRateLimitDisabled) {
              "disabled for interop probe runs"
            } else {
              "enabled"
            },
        )
    )
    terminal.println(row("Server PKI", summary.keyStorePath.toString()))
    terminal.println(row("Milo SDK", summary.miloSdkVersion))
    terminal.println(row("Milo stack", summary.miloStackVersion))
    terminal.println(rule())
    terminal.println()

    renderCertificates(summary.certificates)
    renderEndpoints(summary.endpoints)
  }

  private fun renderCertificates(certificates: List<ServerCertificateSummary>) {
    terminal.println(section("Certificates"))

    if (certificates.isEmpty()) {
      terminal.println("  none")
      terminal.println()
      return
    }

    terminal.println("  " + fixed("CERTIFICATE TYPE", CERTIFICATE_TYPE_WIDTH) + " THUMBPRINT")
    for (certificate in certificates.sortedBy { it.certificateType }) {
      terminal.println(
          "  " +
              fixed(certificate.certificateType, CERTIFICATE_TYPE_WIDTH) +
              " " +
              certificate.thumbprint
      )
    }
    terminal.println()
  }

  private fun renderEndpoints(endpoints: List<ServerEndpointSummary>) {
    terminal.println(section("Advertised Endpoints"))

    if (endpoints.isEmpty()) {
      terminal.println("  none")
      terminal.println()
      return
    }

    for ((family, familyEndpoints) in endpointGroups(endpoints)) {
      terminal.println("  $family (${familyEndpoints.size} advertised)")
      terminal.println(
          "    " +
              fixed("POLICY", POLICY_WIDTH) +
              " " +
              fixed("MODE", MODE_WIDTH) +
              " " +
              fixed("TOKENS", TOKEN_WIDTH) +
              " CERTIFICATE"
      )

      for (endpoint in familyEndpoints) {
        terminal.println(endpointLine(endpoint))
      }
      terminal.println()
    }
  }

  private fun endpointGroups(
      endpoints: List<ServerEndpointSummary>
  ): Map<String, List<ServerEndpointSummary>> =
      sortedEndpoints(endpoints).groupBy { policyFamily(it.securityPolicy) }

  private fun sortedEndpoints(endpoints: List<ServerEndpointSummary>): List<ServerEndpointSummary> =
      endpoints.sortedWith(
          compareBy<ServerEndpointSummary> { policyRank(it.securityPolicy) }
              .thenBy { it.securityPolicy }
              .thenBy { modeRank(it.messageSecurityMode) }
              .thenBy { it.messageSecurityMode }
              .thenBy { it.userTokens.joinToString() }
      )

  private fun endpointLine(endpoint: ServerEndpointSummary): String =
      "    " +
          fixed(endpoint.securityPolicy, POLICY_WIDTH) +
          " " +
          fixed(endpoint.messageSecurityMode, MODE_WIDTH) +
          " " +
          fixed(endpoint.userTokens.joinToString(), TOKEN_WIDTH) +
          " " +
          (endpoint.certificateType ?: "none")
}

/** Returns the broad security family used to group policy names in terminal output. */
internal fun policyFamily(policy: String): String =
    when {
      policy == "None" -> "None"
      policy.startsWith("ECC_nist") -> "ECC NIST"
      policy.startsWith("ECC_brainpool") -> "ECC Brainpool"
      policy.startsWith("ECC_curve") -> "ECC Curve"
      policy.startsWith("RSA_DH") -> "RSA-DH"
      policy.startsWith("Aes") || policy.startsWith("Basic") -> "RSA"
      else -> "Other"
    }

private fun endpointUrls(endpoints: List<ServerEndpointSummary>): String {
  val urls = endpoints.map { it.endpointUrl }.filter { it.isNotBlank() }.distinct().sorted()
  return when (urls.size) {
    0 -> "unknown"
    1 -> urls.single()
    else -> "${urls.size} advertised: ${urls.joinToString()}"
  }
}

private fun policyRank(policy: String): Int {
  val rank = DEFAULT_SECURITY_POLICIES.indexOf(policy)
  return if (rank >= 0) rank else Int.MAX_VALUE
}

private fun modeRank(mode: String): Int =
    when (mode) {
      "None" -> 0
      "Sign" -> 1
      "SignAndEncrypt" -> 2
      else -> Int.MAX_VALUE
    }

private fun row(label: String, value: String): String = rowLabel(label) + value

private fun rowLabel(label: String): String = label.padEnd(13) + " "

private fun fixed(value: String, width: Int): String =
    if (value.length > width) value else value.padEnd(width)

private fun rule(): String = "-".repeat(RULE_WIDTH)

private fun section(text: String): String = title(text)

private fun title(text: String): String = brightBlue(text)
