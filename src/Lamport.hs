module Lamport ( 
  KeyPair(..), HashPair(..),
  generateKey, sign,
  verify ) where

import LamUtils ( encode, hash, format, hashB )

import qualified Control.Monad             as M
import qualified Crypto.Hash.SHA256        as SHA256
import qualified Data.Binary               as B
import qualified Data.Bit                  as BI (cloneFromByteString, Bit (unBit))
import qualified Data.ByteArray.Encoding   as E
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Lazy      as BL
import qualified Data.ByteString.Random    as R
import qualified Data.ByteString.UTF8      as BSU
import qualified Data.Vector               as V
import qualified Data.Vector.Generic       as VG
import qualified Data.Vector.Unboxed       as VU

data HashPair = HashPair { _0 :: BS.ByteString
                         , _1 :: BS.ByteString }
instance Show HashPair where
  show pair = "_0: " ++ format _0s ++ ", _1: " ++ format _1s ++ "\n"
              where _0s = _0 pair
                    _1s  = _1 pair

data KeyPair = KeyPair { _private :: [HashPair]
                       , _public  :: [HashPair] }
instance Show KeyPair where
  show keyPair = "_private:\n" ++ privS ++ "\n_public:\n" ++ pubS
                 where privS = show $ _private keyPair
                       pubS  = show $ _public keyPair

select :: BI.Bit -> HashPair -> BS.ByteString
select b = if BI.unBit b then _0 else _1

{-| Generate pairs containing one random 256-bit ByteString,
and the SHA256 output of that ByteString. -}
generateKey :: IO KeyPair
generateKey = do
  privs <- genPrivs
  let pubs = [HashPair (hash $ _0 p) (hash $ _1 p) | p <- privs]
  return $ KeyPair privs pubs
  where
    genPrivs = M.replicateM 256 priv
    priv = do
      r0 <- R.random 32
      r1 <- R.random 32
      return $ HashPair (encode r0) (encode r1)

{-| Hash the message, and map the individual bits to
a selection of one of the ByteString's from the provided
[HashPair] (which is conventionally the private key).

The resulting [BS.ByteString] is a subset of the provided
[HashPair], where each element has been mapped to one of
the elements of the HashPair, depending on the individual
bit at each element index. -}
sign :: [HashPair]
     -> String
     -> [BS.ByteString]
sign privs message =
  V.toList $ V.zipWith select bits keys
  where bits = hashB message
        keys = V.fromList privs

{-| Hash the message, select single public key elements
from the pairs provided, hash each private key element 
in the signature, and ensure that the hash of each selected 
public key element matches the correct public key element 
available. -}
verify :: [HashPair]
       -> String
       -> [BS.ByteString]
       -> Bool
verify pubs message sig =
  V.all id $ V.zipWith3 sigMatch bits sigChunks publicKeys
  where bits = hashB message
        sigMatch = \b s p ->
          hash s == select b p
        publicKeys = V.fromList pubs
        sigChunks = V.fromList sig
