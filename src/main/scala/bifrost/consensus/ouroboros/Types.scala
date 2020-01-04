package bifrost.consensus.ouroboros

import bifrost.block.Block.Version
import io.iohk.iodb.ByteArrayWrapper

import scala.math.BigInt

trait Types {
  type KesKey = (Tree[Array[Byte]],Tree[Array[Byte]],Array[Byte],Array[Byte],Array[Byte])
  type KesSignature = (Array[Byte],Array[Byte],Array[Byte])
  type Eta = Array[Byte]
  type Signature = Array[Byte]
  type Slot = Int
  type Rho = Array[Byte]
  type PublicKey = Array[Byte]
  type Sid = ByteArrayWrapper
  type PublicKeyW = ByteArrayWrapper
  type PublicKeys = (PublicKey,PublicKey,PublicKey)
  type PrivateKey = Array[Byte]
  type Hash = ByteArrayWrapper
  type Pi = Array[Byte]
  type Box = (Any,Sid,Signature,PublicKey)
  type Transaction = (PublicKeyW,PublicKeyW,BigInt,Sid,Int,Signature)
  type ChainRequest = (BlockSlotId,Int,Int)
  type BlockRequest = (BlockSlotId,Int)
  type Ledger = List[Any]
  type State = Map[PublicKeyW,(BigInt,Boolean,Int)]
  type MemPool = Map[Sid,(Transaction,Int)]
  type Cert = (PublicKey,Rho,Pi,PublicKey,Double,String)
  type Block = (Hash,Ledger,Slot,Cert,Rho,Pi,KesSignature,PublicKey,Int,Slot)
  type BlockSlotId = (Slot,ByteArrayWrapper)
  type Chain = Array[BlockSlotId]
  type ChainData = Array[Map[ByteArrayWrapper,Block]]
  type ChainHistory = Array[List[BlockSlotId]]
}

object OuroborosPrimitives {

  val obversion:Version = 0x4.toByte
  val RHO_LENGTH = 64
  val PI_LENGTH = 80
  val PK_LEN = 32
  val CERT_LEN = 400
  type KesSignature = (Array[Byte],Array[Byte],Array[Byte])
  type Eta = Array[Byte]
  type Pi = Array[Byte]
  type Rho = Array[Byte]
  type PublicKey = Array[Byte]
}