package bifrost.network.peer

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.pattern.ask
import akka.util.Timeout
import bifrost.network.NetworkController.ReceivableMessages.{RegisterMessageSpecs, SendToNetwork}
import bifrost.network.SharedNetworkMessages.ReceivableMessages.DataFromPeer
import bifrost.network.message.{GetPeersSpec, Message, PeersSpec}
import bifrost.network.peer.PeerManager.ReceivableMessages.{AddPeerIfEmpty, RecentlySeenPeers}
import bifrost.network.{SendToPeers, SendToRandom}
import bifrost.settings.NetworkSettings
import bifrost.utils.Logging
import shapeless.syntax.typeable._

import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.language.postfixOps

/**
  * Responsible for discovering and sharing new peers.
  */
class PeerSynchronizer(val networkControllerRef: ActorRef,
                       peerManager: ActorRef,
                       settings: NetworkSettings,
                       featureSerializers: PeerFeature.Serializers)
                      (implicit ec: ExecutionContext) extends Actor with Logging {

  private implicit val timeout: Timeout = Timeout(settings.syncTimeout.getOrElse(5 seconds))
  private val peersSpec = new PeersSpec(featureSerializers, settings.maxPeerSpecObjects)

  override def preStart: Unit = {
    super.preStart()

    networkControllerRef ! RegisterMessageSpecs(Seq(GetPeersSpec, peersSpec), self)

    val msg = Message[Unit](GetPeersSpec, Right(Unit), None)
    val stn = SendToNetwork(msg, SendToRandom)
    context.system.scheduler.schedule(2.seconds, settings.getPeersInterval)(networkControllerRef ! stn)
  }

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////// ACTOR MESSAGE HANDLING //////////////////////////////

  // ----------- CONTEXT && MESSAGE PROCESSING FUNCTIONS
  override def receive: Receive = {
    case DataFromPeer(spec, peers: Seq[PeerSpec]@unchecked, _)
      if spec.messageCode == PeersSpec.messageCode && peers.cast[Seq[PeerSpec]].isDefined =>

      peers.foreach(peerSpec => peerManager ! AddPeerIfEmpty(peerSpec))

    case DataFromPeer(spec, _, peer) if spec.messageCode == GetPeersSpec.messageCode =>

      (peerManager ? RecentlySeenPeers(settings.maxPeerSpecObjects))
        .mapTo[Seq[PeerInfo]]
        .foreach { peers =>
          val msg = Message(peersSpec, Right(peers.map(_.peerSpec)), None)
          networkControllerRef ! SendToNetwork(msg, SendToPeers(Seq(peer)))
        }

    case nonsense: Any => log.warn(s"PeerSynchronizer: got unexpected input $nonsense from ${sender()}")
  }
}

////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// ACTOR REF HELPER //////////////////////////////////

object PeerSynchronizerRef {
  def props(networkControllerRef: ActorRef, peerManager: ActorRef, settings: NetworkSettings,
            featureSerializers: PeerFeature.Serializers)(implicit ec: ExecutionContext): Props =
    Props(new PeerSynchronizer(networkControllerRef, peerManager, settings, featureSerializers))

  def apply(networkControllerRef: ActorRef, peerManager: ActorRef, settings: NetworkSettings,
            featureSerializers: PeerFeature.Serializers)(implicit system: ActorSystem, ec: ExecutionContext): ActorRef =
    system.actorOf(props(networkControllerRef, peerManager, settings, featureSerializers))

  def apply(name: String, networkControllerRef: ActorRef, peerManager: ActorRef, settings: NetworkSettings,
            featureSerializers: PeerFeature.Serializers)(implicit system: ActorSystem, ec: ExecutionContext): ActorRef =
    system.actorOf(props(networkControllerRef, peerManager, settings, featureSerializers), name)
}