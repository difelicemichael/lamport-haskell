module LamUtils ( encode, hash, format, bits, hashB ) where

import qualified Crypto.Hash.SHA256        as SHA256
import qualified Data.Binary               as B
import qualified Data.Bit                  as BI (cloneFromByteString, Bit (unBit))
import qualified Data.ByteArray.Encoding   as E
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Lazy      as BL
import qualified Data.ByteString.UTF8      as BSU
import qualified Data.Vector               as V
import qualified Data.Vector.Generic       as VG

encode :: BS.ByteString -> BS.ByteString
encode   = BS.drop 8 . BS.concat . BL.toChunks . B.encode

hash :: BSU.ByteString -> BSU.ByteString
hash = SHA256.hash . encode

format :: BS.ByteString -> String
format b = show (E.convertToBase E.Base16 b :: BS.ByteString)

bits :: BSU.ByteString -> V.Vector BI.Bit
bits = VG.convert . BI.cloneFromByteString

hashB :: String -> V.Vector BI.Bit
hashB = bits . hash . BSU.fromString