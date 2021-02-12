package co.topl.consensus.genesis

import co.topl.attestation.AddressEncoder.NetworkPrefix
import co.topl.consensus.Forger.ChainParams
import co.topl.crypto.PrivateKeyCurve25519
import co.topl.modifier.ModifierId
import co.topl.modifier.block.Block
import co.topl.settings.Version
import co.topl.utils.{Int128, Logging}
import scorex.crypto.signatures.{PrivateKey, PublicKey}

import scala.util.Try

trait GenesisProvider extends Logging {

  implicit val networkPrefix: NetworkPrefix

  protected lazy val genesisAcct: PrivateKeyCurve25519 =
    PrivateKeyCurve25519(PrivateKey @@ Array.fill(32)(2: Byte), PublicKey @@ Array.fill(32)(2: Byte))

  protected lazy val totalStake: Int128 = members.values.foldLeft[Int128](0)(_ + _)

  protected val blockChecksum: ModifierId

  protected val blockVersion: Version

  protected val initialDifficulty: Long

  protected val members: Map[String, Int128]

  def getGenesisBlock: Try[(Block, ChainParams)]

}
