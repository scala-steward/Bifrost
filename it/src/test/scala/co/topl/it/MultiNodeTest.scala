package co.topl.it

import cats.implicits._
import co.topl.akkahttprpc.implicits.client._
import co.topl.attestation.Address
import co.topl.rpc.implicits.client._
import co.topl.it.util._
import co.topl.rpc.ToplRpc
import com.typesafe.config.ConfigFactory
import io.circe.syntax._
import org.scalatest.concurrent.PatienceConfiguration.Timeout
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.{EitherValues, Inspectors}

import scala.concurrent.Future
import scala.concurrent.duration._

class MultiNodeTest
    extends AnyFreeSpec
    with Matchers
    with IntegrationSuite
    with ScalaFutures
    with EitherValues
    with Inspectors {

  val nodeCount: Int = 3
  // Values close to 0.0 indicate a strict/tight fairness threshold
  val blockDistributionTolerance: Double = 0.99d
  val forgeDuration: FiniteDuration = 5.minutes
  val seed: String = "MultiNodeTest" + System.currentTimeMillis()

  "Multiple nodes can forge blocks with roughly equal distribution" in {

    val nodes = createAndStartNodes()

    assignForgingAddress(nodes)

    // Fetch the initial count of blocks generated by address.  Because forging has not started, only a single
    // genesis block should be assigned to a single address
    val initialGeneratorCounts: Map[String, Map[Address, Int]] =
      Future
        .traverse(nodes) { implicit node =>
          ToplRpc.Debug.Generators.rpc.call
            .run(ToplRpc.Debug.Generators.Params())
            .value
            .map(node.containerId -> _.value)
        }
        .futureValue
        .toMap

    initialGeneratorCounts.foreach { case (containerId, generatorCounts) =>
      logger.info(
        s"Initial block generator counts for containerId=$containerId:\n${generatorCounts.asJson.spaces2SortKeys}"
      )
    }

    forAll(initialGeneratorCounts.values) { counts =>
      counts should have size 1
      counts.head._2 shouldBe 1L
      forAll(initialGeneratorCounts.values)(counts should contain theSameElementsAs _)
    }

    val genesisAddress = initialGeneratorCounts.head._2.head._1

    // Now instruct the nodes to start forging
    nodes.foreach(_.Admin.startForging().futureValue.value)

    logger.info(s"Waiting $forgeDuration for forging")
    Thread.sleep(forgeDuration.toMillis)

    // Verify that each node has forged a roughly equal number of blocks according to their own "myBlocks" information
    val forgeCounts =
      Future
        .traverse(nodes) { implicit node =>
          ToplRpc.Debug.MyBlocks.rpc.call
            .run(ToplRpc.Debug.MyBlocks.Params())
            .map(_.count)
            .value
            .map(node.containerId -> _.value)
        }
        .futureValue
        .toMap

    forgeCounts.foreach { case (containerId, count) =>
      logger.info(s"myBlocks forging count=$count containerId=$containerId")
    }

    forAll(forgeCounts.values)(_ should be > 0)

    val mean = forgeCounts.values.sum / forgeCounts.size

    forAll(forgeCounts.values)(_ should be(mean +- (mean * blockDistributionTolerance).toInt))

    // And now verify that the nodes have shared understanding of how many blocks their peers have forged
    val finalGeneratorCounts: Map[String, Map[Address, Int]] =
      Future
        .traverse(nodes) { implicit node =>
          ToplRpc.Debug.Generators.rpc.call
            .run(ToplRpc.Debug.Generators.Params())
            .value
            .map(node.containerId -> _.value)
        }
        .futureValue
        .toMap

    finalGeneratorCounts.foreach { case (containerId, generatorCounts) =>
      logger.info(
        s"Final block generator counts for containerId=$containerId:\n${generatorCounts.asJson.spaces2SortKeys}"
      )
    }

    forAll(finalGeneratorCounts.values) { counts =>
      counts should have size (nodeCount + 1)
      counts(genesisAddress) shouldBe 1L
      forAll(finalGeneratorCounts.values)(counts should contain theSameElementsAs _)
    }

    val headGeneratorCounts =
      finalGeneratorCounts.head._2 - genesisAddress

    headGeneratorCounts should have size nodes.size

    // And verify again that the block distribution was fair
    val generatorCountMean = headGeneratorCounts.values.sum / headGeneratorCounts.size

    forAll(headGeneratorCounts.values)(_ should be(mean +- (generatorCountMean * blockDistributionTolerance).toInt))
  }

  /** Launches a group of nodes, all on the same Docker network and sharing the same seed.  Forging
    * is disabled on startup.
    */
  def createAndStartNodes(): List[BifrostDockerNode] = {
    val nodeNames = List.tabulate(nodeCount)("bifrostMultiNode" + _)

    val config =
      ConfigFactory.parseString(
        raw"""bifrost.network.knownPeers = ${nodeNames.map(n => s"$n:${BifrostDockerNode.NetworkPort}").asJson}
             |bifrost.rpcApi.namespaceSelector.debug = true
             |bifrost.forging.privateTestnet.numTestnetAccts = $nodeCount
             |bifrost.forging.privateTestnet.genesisSeed = "$seed"
             |bifrost.forging.forgeOnStartup = false
             |""".stripMargin
      )

    val nodes = nodeNames.map(dockerSupport.createNode(_, "MultiNodeTest"))

    nodes.foreach(_.reconfigure(config))
    nodes.foreach(_.start())

    Thread.sleep(20.seconds.toMillis)

    // Startup may take a bit longer in multi-node tests because they need to synchronize first
    Future
      .traverse(nodes)(_.waitForStartup().map(_.value))
      .futureValue(Timeout(60.seconds))

    nodes
  }

}
