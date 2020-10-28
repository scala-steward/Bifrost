package co.topl.wallet

import akka.actor.{Actor, ActorRef}
import akka.pattern.{ask, pipe}
import akka.util.Timeout
import co.topl.modifier.block.Block
import co.topl.network.NodeViewSynchronizer.ReceivableMessages.{ModificationOutcome, SemanticallySuccessfulModifier}
import co.topl.utils.Logging
import co.topl.wallet.AssetRequests.AssetRequest
import co.topl.wallet.WalletRequests.WalletRequest
import io.circe.parser.parse

import scala.concurrent.ExecutionContext
import scala.util.Success
import scala.concurrent.duration._


class WalletConnectionHandler ( implicit ec: ExecutionContext ) extends Actor with Logging {
  import WalletConnectionHandler._

  var remoteWalletActor: Option[ActorRef] = None

  var remoteWalletKeys: Set[String] = Set.empty

  implicit val timeout: Timeout = 10.seconds

  override def preStart(): Unit = {
    context.system.eventStream.subscribe(self, classOf[ModificationOutcome])
  }

  /*
   case NewBlockAdded(block: Block) => {
      remoteWalletActor match {
        case Some(actor) => {
          actor ! s"new block added: ${block.json}"
        }
        case None => System.out.println("no wallet running")
      }
      context.system.eventStream.publish(s"publishing new block: $block")
     /* val lookupBus = new LookupBusImpl
      lookupBus.publish(MsgEnvelope("New block added", block))*/
    }
   */

  def sendRequest(params: String, walletRef: ActorRef, requestType: String): Unit = {
    parse(params) match {
      case Right(tx) => {
        requestType match {
          case "asset" =>
            context.actorSelection("../" + AssetRequests.actorName).resolveOne().onComplete {
              case Success(request: ActorRef) =>
                    val futureResponse = request ? AssetRequest(tx)
                    futureResponse.pipeTo(walletRef)
              case _ =>
                log.warn("No ledger actor found. Can not update view.")
            }
          case "wallet" =>
            context.actorSelection("../" + WalletRequests.actorName).resolveOne().onComplete {
              case Success(request: ActorRef) =>
                val futureResponse = request ? WalletRequest(tx)
                futureResponse.pipeTo(walletRef)
              case _ =>
                log.warn("No ledger actor found. Can not update view.")
            }
        }
      }
      case Left(error)  => throw new Exception (s"error: $error")
    }
  }

  def parseKeys (keys: String): Unit = {
    val keysArr: Array[String] = keys.split(",")
    remoteWalletKeys = keysArr.map( key =>
      if (keysArr.indexOf(key) == 0)
        key.substring("Set(".length)
      else if (keysArr.indexOf(key) == keysArr.length-1)
        key.substring(1, key.length-1)
      else key.substring(1)
    ).toSet
  }

  def msgHandler(msg: String): Unit = {
    if (msg.contains("Remote wallet actor initialized")) {
      parseKeys(msg.substring("Remote wallet actor initialized. My public keys are: ".length))
      remoteWalletActor = Some(sender())
      remoteWalletActor match {
        case Some(actor) => {
          actor ! s"received new wallet from: ${sender()}"
        }
        case None => println ("no wallets!")
      }
    }
    if (msg == "Remote wallet actor stopped") {
      remoteWalletActor = None
      sender ! s"The remote wallet ${sender()} has been removed from the WalletConnectionHandler in Bifrost"
    }

    if (msg.contains("asset transaction:")) {
      val txString: String = msg.substring("asset transaction: ".length)
      println("Wallet Connection handler received asset transaction: " + txString)
      val walletActorRef: ActorRef = sender()
      sendRequest(txString, walletActorRef, "asset")
    }

    if (msg.contains("wallet request:")) {
      val params: String = msg.substring("wallet request: ".length)
      println("Wallet connection handler received wallet request: " + params)
      val walletActorRef: ActorRef = sender()
      sendRequest(params, walletActorRef, "wallet")
    }
  }

  override def receive: Receive = {

    case msg: String => {
      msgHandler(msg)
    }

    case GetRemoteWalletRef => sender ! remoteWalletActor

    case SemanticallySuccessfulModifier(block: Block) => {
      remoteWalletActor match {
        case Some(actor) => {
          actor ! s"new block added: ${block.json}"
        }
        case None => System.out.println("no wallet running")
      }
    }


  }
}

object WalletConnectionHandler {
  case object GetRemoteWalletRef
  //case class NewBlockAdded(block: PersistentNodeViewModifier)
}
