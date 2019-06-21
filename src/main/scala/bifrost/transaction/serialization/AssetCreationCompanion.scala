package bifrost.transaction.serialization

import bifrost.serialization.Serializer
import bifrost.transaction.bifrostTransaction.AssetCreation
import bifrost.transaction.box.proposition.{Constants25519, PublicKey25519Proposition}
import bifrost.transaction.proof.Signature25519
import com.google.common.primitives.{Bytes, Ints, Longs}
import scorex.crypto.signatures.Curve25519

import scala.util.Try

object AssetCreationCompanion extends Serializer[AssetCreation] {
  override def toBytes(ac: AssetCreation): Array[Byte] = {
    val typeBytes = "AssetCreation".getBytes

    Bytes.concat(
      Ints.toByteArray(typeBytes.length),
      typeBytes,
      Longs.toByteArray(ac.fee),
      Longs.toByteArray(ac.timestamp),
      Ints.toByteArray(ac.signatures.length),
      Ints.toByteArray(ac.to.size),
      Ints.toByteArray(ac.assetCode.getBytes.length),
      ac.assetCode.getBytes,
      ac.issuer.pubKeyBytes,
      ac.signatures.foldLeft(Array[Byte]())((a, b) => a ++ b.bytes),
      ac.to.foldLeft(Array[Byte]())((a, b) => a ++ b._1.pubKeyBytes ++ Longs.toByteArray(b._2)),
      ac.data.getBytes,
      Ints.toByteArray(ac.data.getBytes.length)
    )
  }

  //noinspection ScalaStyle
  override def parseBytes(bytes: Array[Byte]): Try[AssetCreation] = Try {
    val dataLen: Int = Ints.fromByteArray(bytes.slice(bytes.length - Ints.BYTES, bytes.length))
    val data: String = new String(
      bytes.slice(bytes.length - Ints.BYTES - dataLen, bytes.length - Ints.BYTES)
    )
    val typeLength = Ints.fromByteArray(bytes.take(Ints.BYTES))
    val typeStr = new String(bytes.slice(Ints.BYTES, Ints.BYTES + typeLength))
    var numReadBytes = Ints.BYTES + typeLength
    val bytesWithoutType = bytes.slice(numReadBytes, bytes.length)

    val Array(fee: Long, timestamp: Long) = (0 until 2).map { i =>
      Longs.fromByteArray(bytesWithoutType.slice(i * Longs.BYTES, (i + 1) * Longs.BYTES))
    }.toArray

    numReadBytes = 2 * Longs.BYTES

    val sigLength = Ints.fromByteArray(bytesWithoutType.slice(numReadBytes, numReadBytes + Ints.BYTES))

    numReadBytes += Ints.BYTES

    val toLength = Ints.fromByteArray(bytesWithoutType.slice(numReadBytes, numReadBytes + Ints.BYTES))

    numReadBytes += Ints.BYTES

    val assetCodeLen: Int = Ints.fromByteArray(bytesWithoutType.slice(numReadBytes, numReadBytes + Ints.BYTES))

    numReadBytes += Ints.BYTES

    val assetCode: String = new String(
      bytesWithoutType.slice(numReadBytes, numReadBytes + assetCodeLen)
    )

    numReadBytes += assetCodeLen

    val issuer = PublicKey25519Proposition(bytesWithoutType.slice(numReadBytes,
      numReadBytes + Constants25519.PubKeyLength))

    numReadBytes += Constants25519.PubKeyLength

    val signatures = (0 until sigLength) map { i =>
      Signature25519(bytesWithoutType.slice(numReadBytes + i * Curve25519.SignatureLength,
        numReadBytes + (i + 1) * Curve25519.SignatureLength))
    }

    numReadBytes += sigLength * Curve25519.SignatureLength

    val elementLength = Longs.BYTES + Curve25519.KeyLength

    val to = (0 until toLength) map { i =>
      val pk = bytesWithoutType.slice(numReadBytes + i * elementLength, numReadBytes + (i + 1) * elementLength - Longs.BYTES)
      val v = Longs.fromByteArray(
        bytesWithoutType.slice(numReadBytes + (i + 1) * elementLength - Longs.BYTES, numReadBytes + (i + 1) * elementLength)
      )
      (PublicKey25519Proposition(pk), v)
    }

//    val dataLen: Int = Ints.fromByteArray(bytesWithoutType.slice(bytesWithoutType.length - Ints.BYTES, bytesWithoutType.length))
//    val data: String = new String(
//      bytes.slice(bytesWithoutType.length - Ints.BYTES - dataLen, bytesWithoutType.length - Ints.BYTES)
//    )


    AssetCreation(to, signatures, assetCode, issuer, fee, timestamp, data)
  }
}