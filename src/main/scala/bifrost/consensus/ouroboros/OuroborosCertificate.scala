package bifrost.consensus.ouroboros

import bifrost.consensus.ouroboros.OuroborosPrimitives._
import bifrost.serialization.Serializer
import scala.util.Try
import com.google.common.primitives.{Bytes, Longs}
import java.lang.Double

class OuroborosCertificate(slot:Long,
                           rho_nonce:Rho,
                           pi_nonce:Pi,
                           y_test:Rho,
                           pi_test:Pi,
                           pk_sig:PublicKey,
                           pk_vrf:PublicKey,
                           pk_kes:PublicKey,
                           threshold:Double) {

  def getFields:(Long, Rho, Pi, Rho, Pi, PublicKey, PublicKey, PublicKey, Double) = {
    (slot, rho_nonce, pi_nonce, y_test, pi_test, pk_sig, pk_vrf, pk_kes, threshold)
  }

}

object OuroborosCertificate {

  def apply(slot:Long,
            rho_nonce:Rho,
            pi_nonce:Pi,
            y_test:Rho,
            pi_test:Pi,
            pk_sig:PublicKey,
            pk_vrf:PublicKey,
            pk_kes:PublicKey,
            threshold:Double): OuroborosCertificate = {
    new OuroborosCertificate(
      slot:Long,
      rho_nonce:Rho,
      pi_nonce:Pi,
      y_test:Rho,
      pi_test:Pi,
      pk_sig:PublicKey,
      pk_vrf:PublicKey,
      pk_kes:PublicKey,
      threshold:Double
    )
  }

  def empty: OuroborosCertificate = {
    new OuroborosCertificate(slot = -1,
      rho_nonce = Array(),
      pi_nonce = Array(),
      y_test = Array(),
      pi_test = Array(),
      pk_sig = Array(),
      pk_vrf = Array(),
      pk_kes = Array(),
      threshold = 0.0)
  }
}

object OuroborosCertificateCompanion extends Serializer[OuroborosCertificate] {

  private def doubleToByteArray(x: Double) = {
    val l = Double.doubleToLongBits(x)
    val a = Array.fill(8)(0.toByte)
    for (i <- 0 to 7) a(i) = ((l >> ((7 - i) * 8)) & 0xff).toByte
    a
  }

  private def byteArrayToDouble(x: Array[scala.Byte]) = {
    var i = 0
    var res = 0.toLong
    for (i <- 0 to 7) {
      res +=  ((x(i) & 0xff).toLong << ((7 - i) * 8))
    }
    Double.longBitsToDouble(res)
  }

  override def toBytes(cert: OuroborosCertificate): Array[Byte] = {
    val (slot, rho_nonce, pi_nonce, y_test, pi_test, pk_sig, pk_vrf, pk_kes, threshold) = cert.getFields
    Bytes.concat(
      Longs.toByteArray(slot),
      rho_nonce,
      pi_nonce,
      y_test,
      pi_test,
      pk_sig,
      pk_vrf,
      pk_kes,
      doubleToByteArray(threshold)
    )
  }

  override def parseBytes(bytes: Array[Byte]): Try[OuroborosCertificate] = Try {
    bytes.length match {
      case CERT_LEN => {
        var remainingBytes = bytes

        val slot = Longs.fromByteArray(remainingBytes.take(8))
        remainingBytes = remainingBytes.drop(8)

        val rho_nonce = remainingBytes.take(RHO_LENGTH)
        remainingBytes = remainingBytes.drop(RHO_LENGTH)

        val pi_nonce = remainingBytes.take(PI_LENGTH)
        remainingBytes = remainingBytes.drop(PI_LENGTH)

        val y_test = remainingBytes.take(RHO_LENGTH)
        remainingBytes = remainingBytes.drop(RHO_LENGTH)

        val pi_test = remainingBytes.take(PI_LENGTH)
        remainingBytes = remainingBytes.drop(PI_LENGTH)

        val pk_sig = remainingBytes.take(PK_LEN)
        remainingBytes = remainingBytes.drop(PK_LEN)

        val pk_vrf = remainingBytes.take(PK_LEN)
        remainingBytes = remainingBytes.drop(PK_LEN)

        val pk_kes = remainingBytes.take(PK_LEN)
        remainingBytes = remainingBytes.drop(PK_LEN)

        val threshold = byteArrayToDouble(remainingBytes.take(8))
        remainingBytes = remainingBytes.drop(8)

        OuroborosCertificate(slot,rho_nonce,pi_nonce,y_test,pi_test,pk_sig,pk_vrf,pk_kes,threshold)
      }
      case _ => OuroborosCertificate.empty
    }
  }
}