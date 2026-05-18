package com.digitalpetri.opcua.ecc.server

import org.eclipse.milo.opcua.sdk.core.AccessLevel
import org.eclipse.milo.opcua.sdk.core.Reference
import org.eclipse.milo.opcua.sdk.server.ManagedNamespaceWithLifecycle
import org.eclipse.milo.opcua.sdk.server.OpcUaServer
import org.eclipse.milo.opcua.sdk.server.items.DataItem
import org.eclipse.milo.opcua.sdk.server.items.MonitoredItem
import org.eclipse.milo.opcua.sdk.server.nodes.UaFolderNode
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode
import org.eclipse.milo.opcua.sdk.server.util.SubscriptionModel
import org.eclipse.milo.opcua.stack.core.NodeIds
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant

private const val DEMO_NAMESPACE_URI = "urn:eclipse:milo:ecc-demo:server:demo"

/**
 * Small address space published by the demo server after startup.
 *
 * OPC UA security negotiation proves that a client can connect; reading and writing nodes proves
 * the negotiated session can use the server. This namespace gives probes stable, obvious nodes
 * under the standard `Objects` folder without turning the demo into a full application model.
 */
internal class DemoNamespace(server: OpcUaServer) :
    ManagedNamespaceWithLifecycle(server, DEMO_NAMESPACE_URI) {
  private val subscriptionModel = SubscriptionModel(server, this)

  init {
    lifecycleManager.addLifecycle(subscriptionModel)
    lifecycleManager.addStartupTask(::createNodes)
  }

  private fun createNodes() {
    val rootNodeId = newNodeId("Demo")
    if (nodeManager.containsNode(rootNodeId)) return

    val rootNode =
        UaFolderNode(
            nodeContext,
            rootNodeId,
            newQualifiedName("Demo"),
            LocalizedText.english("Demo"),
        )

    nodeManager.addNode(rootNode)
    rootNode.addReference(
        Reference(
            rootNode.nodeId,
            NodeIds.Organizes,
            NodeIds.ObjectsFolder.expanded(),
            false,
        ),
    )

    addVariable(
        rootNode,
        DemoVariable("Demo/WritableString", "WritableString", NodeIds.String, "hello"),
    )
    addVariable(rootNode, DemoVariable("Demo/WritableInt32", "WritableInt32", NodeIds.Int32, 42))
    addVariable(
        rootNode,
        DemoVariable("Demo/WritableBoolean", "WritableBoolean", NodeIds.Boolean, true),
    )
  }

  private fun addVariable(rootNode: UaFolderNode, variable: DemoVariable) {
    val node =
        UaVariableNode.build(nodeContext) { builder ->
          builder
              .setNodeId(newNodeId(variable.identifier))
              .setBrowseName(newQualifiedName(variable.browseName))
              .setDisplayName(LocalizedText.english(variable.browseName))
              .setDataType(variable.dataTypeId)
              .setTypeDefinition(NodeIds.BaseDataVariableType)
              .setAccessLevel(AccessLevel.READ_WRITE)
              .setUserAccessLevel(AccessLevel.READ_WRITE)
              .setValue(DataValue(Variant(variable.initialValue)))
              .buildAndAdd()
        }

    rootNode.addOrganizes(node)
  }

  override fun onDataItemsCreated(dataItems: List<DataItem>) {
    subscriptionModel.onDataItemsCreated(dataItems)
  }

  override fun onDataItemsModified(dataItems: List<DataItem>) {
    subscriptionModel.onDataItemsModified(dataItems)
  }

  override fun onDataItemsDeleted(dataItems: List<DataItem>) {
    subscriptionModel.onDataItemsDeleted(dataItems)
  }

  override fun onMonitoringModeChanged(monitoredItems: List<MonitoredItem>) {
    subscriptionModel.onMonitoringModeChanged(monitoredItems)
  }
}

/** Description of one writable demo variable created under the `Demo` folder. */
private data class DemoVariable(
    val identifier: String,
    val browseName: String,
    val dataTypeId: NodeId,
    val initialValue: Any,
)
