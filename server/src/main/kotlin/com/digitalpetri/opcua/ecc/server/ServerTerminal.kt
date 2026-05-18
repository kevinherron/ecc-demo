package com.digitalpetri.opcua.ecc.server

import com.github.ajalt.mordant.rendering.TextColors.brightBlue
import com.github.ajalt.mordant.terminal.Terminal
import kotlin.collections.iterator
import org.eclipse.milo.opcua.stack.core.NodeIds
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy

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

    val groups = endpointGroups(endpoints)
    for (category in EndpointCategory.entries) {
      val categoryEndpoints = groups[category].orEmpty()
      if (categoryEndpoints.isEmpty()) continue

      terminal.println("  ${category.displayName} (${categoryEndpoints.size} advertised)")
      terminal.println(
          "    " +
              fixed("POLICY", POLICY_WIDTH) +
              " " +
              fixed("MODE", MODE_WIDTH) +
              " " +
              fixed("TOKENS", TOKEN_WIDTH) +
              " CERTIFICATE"
      )

      for (endpoint in categoryEndpoints) {
        terminal.println(endpointLine(endpoint))
      }
      terminal.println()
    }
  }

  private fun endpointGroups(
      endpoints: List<ServerEndpointSummary>
  ): Map<EndpointCategory, List<ServerEndpointSummary>> =
      sortedEndpoints(endpoints).groupBy { EndpointCategory.from(it.securityPolicy) }

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

private enum class EndpointCategory(val displayName: String) {
  NONE("None"),
  RSA("RSA"),
  RSA_SHA256_CERTIFICATE("RsaSha256"),
  ECC_NIST_P256_CERTIFICATE("EccNistP256"),
  ECC_NIST_P384_CERTIFICATE("EccNistP384"),
  ECC_BRAINPOOL_P256R1_CERTIFICATE("EccBrainpoolP256r1"),
  ECC_BRAINPOOL_P384R1_CERTIFICATE("EccBrainpoolP384r1"),
  ECC_CURVE25519_CERTIFICATE("EccCurve25519"),
  ECC_CURVE448_CERTIFICATE("EccCurve448"),
  OTHER("Other");

  companion object {
    private val OLD_RSA_POLICIES =
        setOf(
            "Basic256Sha256",
            "Aes128_Sha256_RsaOaep",
            "Aes256_Sha256_RsaPss",
        )

    private val CERTIFICATE_TYPE_CATEGORIES =
        mapOf(
            NodeIds.RsaSha256ApplicationCertificateType to RSA_SHA256_CERTIFICATE,
            NodeIds.EccNistP256ApplicationCertificateType to ECC_NIST_P256_CERTIFICATE,
            NodeIds.EccNistP384ApplicationCertificateType to ECC_NIST_P384_CERTIFICATE,
            NodeIds.EccBrainpoolP256r1ApplicationCertificateType to
                ECC_BRAINPOOL_P256R1_CERTIFICATE,
            NodeIds.EccBrainpoolP384r1ApplicationCertificateType to
                ECC_BRAINPOOL_P384R1_CERTIFICATE,
            NodeIds.EccCurve25519ApplicationCertificateType to ECC_CURVE25519_CERTIFICATE,
            NodeIds.EccCurve448ApplicationCertificateType to ECC_CURVE448_CERTIFICATE,
        )

    fun from(policy: String): EndpointCategory {
      if (policy == "None") return NONE
      if (policy in OLD_RSA_POLICIES) return RSA

      val certificateType =
          runCatching {
                SecurityPolicy.valueOf(policy).profile.preferredCertificateTypeId().orElse(null)
              }
              .getOrNull()

      return CERTIFICATE_TYPE_CATEGORIES[certificateType] ?: OTHER
    }
  }
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
